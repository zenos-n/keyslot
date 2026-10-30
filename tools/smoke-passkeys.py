"""Real GTK passkey management and native transfer in a disposable database."""
import json
import base64
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
temporary = tempfile.TemporaryDirectory(prefix="ks-passkeys-", dir="/tmp")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from keyslot.app import Keyslot
from keyslot import passkey_views
from test_passkeys import creation
from gi.repository import Adw, Gdk, GLib, Gtk

Gtk.init_check()
assert Gdk.Display.get_default() is not None, "Run this check under Xvfb/private D-Bus"
app = Keyslot()
failures = []
state = {"phase": "starting", "answered": set()}
folder = directory / "exports"
folder.mkdir()
single = directory / "single.passkey"


def widgets(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def click(dialog, label):
    button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == label)
    assert button.get_sensitive(), label
    button.emit("clicked")
    return button


def guard(callback):
    def run(*args):
        try:
            return callback(*args)
        except Exception as exc:
            failures.append(exc)
            app.quit()
            return False
    return run


@guard
def start():
    session = app.active_session
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.path, "public management master")
    key = base64.b64encode(bytes(range(32))).decode()
    session.vault.browser_associate("fixture", key)
    review = session.vault.browser_prepare_passkey("fixture", key, "register", creation(), "https://login.example.org")
    session.vault.browser_finish_passkey(review["token"], approved=True)
    original = session.vault.snapshot.entries[0]
    session.vault.save_entry(original.group, original.title, original.username, original.url, original.notes,
                            entry=original, expires=True, expiry="2000-01-01T00:00:00Z")
    state["original"] = session.vault.snapshot.entries[0].uuid
    session.window.show_vault(session.vault.snapshot)
    assert session.host_window.lookup_action("passkeys") is not None
    def selected(callback, save=False, name=None, kdbx=False, folder=False):
        if folder:
            callback(str(directory / "exports"))
        elif save:
            callback(str(single))
        else:
            callback(str(state["source"]))
    session.choose_file = selected  # Fixture paths only; real helper IO/GTK decisions remain exercised.
    state["phase"] = "export-cancel"
    passkey_views.manage(session)
    GLib.timeout_add(25, drive)
    return False


def entry(uuid):
    return next(e for e in app.active_session.vault.snapshot.entries if e.uuid == uuid)


@guard
def drive():
    session = app.active_session
    if session.busy:
        return True
    dialogs = list(session.dialogs)
    phase = state["phase"]
    if phase == "import-done" and len(session.vault.snapshot.entries) == 2:
        imported = next(e for e in session.vault.snapshot.entries if e.uuid != state["original"])
        assert imported.passkey and imported.group_path.endswith("/Imported Passkeys")
        state["imported"] = imported.uuid
        state["phase"] = "single-cancel"
        single.write_text("public existing output")
        passkey_views.show_info(session, imported)
        return True
    if phase == "single-done" and single.read_text() != "public existing output":
        assert set(json.loads(single.read_text())) == {"relyingParty", "url", "username", "credentialId", "userHandle", "privateKey"}
        assert stat.S_IMODE(single.stat().st_mode) == 0o600
        state["phase"] = "remove-cancel"
        passkey_views.show_info(session, entry(state["imported"]))
        return True
    if phase == "remove-done" and not entry(state["imported"]).passkey:
        assert entry(state["imported"]).history_count == 1
        state["phase"] = "replace-cancel"
        passkey_views.choose_import(session, entry(state["original"]))
        return True
    if phase == "replace-done" and not dialogs:
        assert entry(state["original"]).passkey
        state["phase"] = "source-changed"
        passkey_views.choose_import(session)
        return True
    if phase == "late-open" and not dialogs:
        passkey_views.choose_import(session)
        state["phase"] = "late-review"
        return True
    for dialog in reversed(dialogs):
        if not dialog.get_mapped():
            return True
        if isinstance(dialog, Adw.AlertDialog):
            if dialog in state["answered"]:
                continue
            state["answered"].add(dialog)
            heading = dialog.get_heading()
            assert dialog.get_default_response() == "cancel" or heading == "Could Not Complete Operation"
            if heading == "Export Unencrypted Passkeys?":
                if phase == "export-cancel":
                    click(dialog, "Cancel")
                    assert not list(folder.iterdir())
                    state["phase"] = "export-approve"
                    passkey_views.manage(session)
                elif phase == "export-approve":
                    state["phase"] = "export-done"
                    click(dialog, "Export")
                elif phase == "single-cancel":
                    click(dialog, "Cancel")
                    assert single.read_text() == "public existing output"
                    state["phase"] = "single-approve"
                    passkey_views.show_info(session, entry(state["imported"]))
                elif phase == "single-approve":
                    state["phase"] = "single-done"
                    click(dialog, "Export and Replace")
                else:
                    raise AssertionError("Unexpected export phase: " + phase)
            elif heading == "Remove Passkey?":
                if phase == "remove-cancel":
                    before = session.path.read_bytes()
                    click(dialog, "Cancel")
                    assert session.path.read_bytes() == before and entry(state["imported"]).passkey
                    state["phase"] = "remove-approve"
                    passkey_views.show_info(session, entry(state["imported"]))
                else:
                    assert phase == "remove-approve"
                    state["phase"] = "remove-done"
                    click(dialog, "Remove Passkey")
            elif heading == "Replace Existing Passkey?":
                if phase == "replace-cancel":
                    state["phase"] = "replace-approve"
                    click(dialog, "Cancel")
                else:
                    assert phase == "replace-approve"
                    state["phase"] = "replace-done"
                    click(dialog, "Replace Passkey")
            elif heading == "Could Not Complete Operation":
                assert phase == "source-error" and "changed since review" in dialog.get_body()
                assert session.path.read_bytes() == state["before"]
                state["source"].write_bytes(state["source_bytes"])
                state["phase"] = "late-open"
                click(dialog, "Close")
            else:
                raise AssertionError("Unexpected alert: " + heading)
            return True
        title = dialog.get_title()
        assert not any("PRIVATE KEY" in w.get_label() for w in widgets(dialog) if isinstance(w, Gtk.Label))
        if title == "Passkeys":
            if dialog in state["answered"]:
                continue
            state["answered"].add(dialog)
            check = next(w for w in widgets(dialog) if isinstance(w, Gtk.CheckButton) and not w.get_label())
            expired = next(w for w in widgets(dialog) if isinstance(w, Gtk.CheckButton) and w.get_label() == "Show Expired Passkeys")
            row = next(w for w in widgets(dialog) if isinstance(w, Adw.ActionRow) and hasattr(w, "entry"))
            assert not row.get_child_visible()
            expired.set_active(True)
            assert row.get_child_visible()
            check.set_active(True)
            expired.set_active(False)
            assert not check.get_active() and not row.get_child_visible()
            expired.set_active(True)
            search = next(w for w in widgets(dialog) if isinstance(w, Gtk.SearchEntry))
            search.set_text("no matching passkey")
            search.emit("search-changed")
            assert not row.get_child_visible()
            search.set_text("example.org")
            search.emit("search-changed")
            assert row.get_child_visible()
            check.set_active(True)
            for widget in widgets(dialog):
                if isinstance(widget, Gtk.Button) and widget.get_tooltip_text() == "Passkey Details":
                    assert widget.get_valign() == Gtk.Align.CENTER
            click(dialog, "Export (1)…")
        elif title == "Passkey Details":
            if dialog in state["answered"]:
                continue
            state["answered"].add(dialog)
            click(dialog, "Remove Passkey…" if phase.startswith("remove-") else "Export…")
        elif title == "Import Passkey":
            if phase.startswith("replace-"):
                target = next(w for w in widgets(dialog) if isinstance(w, Adw.ComboRow) and w.get_title() == "Save To")
                expected = next(index for index, item in enumerate(session.vault.snapshot.entries, start=1) if item.uuid == state["original"])
                assert target.get_selected() == expected, "Replacement must preselect the originating entry"
            if phase == "late-review":
                target = next(w for w in widgets(dialog) if isinstance(w, Adw.ComboRow) and w.get_title() == "Save To")
                target.set_selected(next(index for index, item in enumerate(session.vault.snapshot.entries, start=1)
                    if item.uuid == state["original"]))
                button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Import")
                before = session.path.read_bytes()
                session.lock()
                assert not session.dialogs and not session.vault.unlocked
                button.emit("clicked")
                assert session.path.read_bytes() == before and not session.dialogs
                state["phase"] = "finished"
                app.quit()
                return False
            if dialog in state["answered"] and phase != "replace-approve":
                continue
            state["answered"].add(dialog)
            if phase == "source-changed":
                state["before"] = session.path.read_bytes()
                state["source_bytes"] = state["source"].read_bytes()
                state["source"].write_bytes(state["source_bytes"] + b"\n")
                state["phase"] = "source-error"
            elif phase == "import":
                state["phase"] = "import-done"
            click(dialog, "Import")
        else:
            raise AssertionError("Unexpected dialog: " + title)
        return True
    if phase == "export-done":
        files = list(folder.glob("*.passkey"))
        if files:
            assert len(files) == 1 and stat.S_IMODE(files[0].stat().st_mode) == 0o600
            state["source"] = files[0]
            state["phase"] = "import"
            passkey_views.choose_import(session)
    return True


GLib.timeout_add(200, start)
GLib.timeout_add_seconds(30, lambda: (failures.append(AssertionError("GTK passkey management timed out at " + state["phase"])), app.quit(), False)[-1])
result = app.run(["keyslot-passkeys-smoke"])
temporary.cleanup()
if failures:
    raise failures[0]
assert result == 0 and state["phase"] == "finished", "GTK passkey management did not complete"
print("GTK passkey manager, import/replacement review, private export, history-preserving removal, cancellation, changed-source rejection and late-lock guards passed")
