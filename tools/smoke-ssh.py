"""Mapped GTK SSH workflows with a disposable vault, key and OpenSSH agent."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
temporary = tempfile.TemporaryDirectory(prefix="ks-ssh-ui-", dir="/tmp")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
os.environ["SSH_AUTH_SOCK"] = str(directory / "agent")
os.environ["SSH_ASKPASS_REQUIRE"] = "force"
agent = subprocess.Popen([shutil.which("ssh-agent"), "-D", "-a", os.environ["SSH_AUTH_SOCK"]],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
for _ in range(100):
    if Path(os.environ["SSH_AUTH_SOCK"]).exists():
        break
    time.sleep(.01)
key = directory / "fixture-key"
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "public SSH passphrase", "-C", "Public GTK fixture", "-f", str(key)],
               check=True, capture_output=True)
external = [directory / "external-one", directory / "external-two"]
for path in external:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", path.name, "-f", str(path)],
                   check=True, capture_output=True)
external_bytes = [path.read_bytes() for path in external]
from keyslot.app import Keyslot
from keyslot import preferences, ssh_views
from gi.repository import Adw, Gdk, GLib, Gtk

Gtk.init_check()
assert Gdk.Display.get_default() is not None, "Run under Xvfb/private D-Bus"
app = Keyslot()
failures = []
state = {"phase": "starting", "answered": set()}


def widgets(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def row(dialog, title, kind):
    return next(w for w in widgets(dialog) if isinstance(w, kind) and w.get_title() == title)


def click(dialog, label):
    button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == label)
    assert button.get_sensitive(), label
    button.emit("clicked")
    return button


def count():
    result = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True, timeout=3)
    assert result.returncode in (0, 1), result.stderr
    return len(result.stdout.splitlines()) if result.returncode == 0 else 0


def entry():
    return app.active_session.vault.snapshot.entries[0]


def guard(function):
    def run(*args):
        try:
            return function(*args)
        except Exception as exc:
            failures.append(exc)
            app.quit()
            return False
    return run


@guard
def start():
    session = app.active_session
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.path, "public vault master")
    session.vault.save_entry(session.vault.snapshot.root, "SSH fixture", "alice", "", "Preserve notes", "public SSH passphrase")
    session.window.show_vault(session.vault.snapshot)
    state["phase"] = "preferences"
    preferences.show(session)
    GLib.timeout_add(30, drive)
    return False


@guard
def drive():
    session = app.active_session
    if session.busy:
        return True
    phase = state["phase"]
    dialogs = list(session.dialogs)
    if phase == "ready" and app.ssh.ready:
        state["phase"] = "settings"
        ssh_views.entry_settings(session, entry())
    elif phase == "saved" and not dialogs:
        state["phase"] = "preview"
        ssh_views.preview_key(session, entry())
    elif phase == "cancelled" and not dialogs:
        assert count() == 0
        state["phase"] = "add"
        ssh_views.add_key(session, entry())
    elif phase == "added" and count() == 1:
        result = subprocess.run(["ssh-keygen", "-Y", "sign", "-U", "-f", str(key) + ".pub", "-n", "keyslot-gtk"],
                                input=b"Public GTK signing fixture", capture_output=True, timeout=3)
        assert result.returncode == 0 and b"BEGIN SSH SIGNATURE" in result.stdout, result.stderr
        state["phase"] = "remove-cancel"
        ssh_views.manage(session)
    elif phase == "remove-cancelled" and not dialogs:
        assert count() == 1
        state["phase"] = "remove"
        ssh_views.manage(session)
    elif phase == "removed" and not dialogs:
        # The manager reopens after removal; handled below once mapped.
        pass
    elif phase == "external-cancelled" and not dialogs:
        assert count() == 2
        state["phase"] = "external-remove"
        ssh_views.manage(session)
    elif phase == "clear-cancelled" and not dialogs:
        assert count() == 1
        state["phase"] = "clear-approve"
        ssh_views.manage(session)
    elif phase == "clear-review-fresh" and not dialogs:
        state["phase"] = "clear-fresh"
        ssh_views.manage(session)
    elif phase == "locked" and count() == 0 and not session.jobs.busy:
        state["phase"] = "auto-loading"
        session.run_job(lambda: session.vault.unlock(session.path, "public vault master"), session.window.show_vault)
    elif phase == "auto-loading" and count() == 1:
        assert session.vault.ssh_settings(entry())["auto_add"]
        assert not session.jobs.interactive or not session.jobs.busy
        app.set_background(True)
        session.host_window.close()
        assert app.background and not session.host_window.get_visible()
        assert session.vault.unlocked and count() == 1
        app.select_session(session)
        state["phase"] = "stale"
        ssh_views.add_key(session, entry())
    elif phase == "stale-locked" and count() == 0:
        assert not session.vault.unlocked
        state["phase"] = "final-unlock"
        session.run_job(lambda: session.vault.unlock(session.path, "public vault master"), session.window.show_vault)
    elif phase == "final-unlock" and count() == 1:
        assert entry().notes == "Preserve notes"
        state["phase"] = "removal-stale"
        ssh_views.review_removal(session, clear=True)
    elif phase == "removal-stale-locked" and count() == 0 and not session.jobs.busy:
        state["phase"] = "removal-final-unlock"
        session.run_job(lambda: session.vault.unlock(session.path, "public vault master"), session.window.show_vault)
    elif phase == "removal-final-unlock" and count() == 1:
        app.set_ssh(False)
        state["phase"] = "disabled"
    elif phase == "disabled" and count() == 0 and session.vault.ssh_manager is None:
        assert session.vault.unlocked and not app.startup.ssh
        state["phase"] = "reenable"
        preferences.show(session)
    elif phase == "reenabled" and count() == 1:
        state["phase"] = "finished"
        app.quit()
        return False
    for dialog in reversed(session.dialogs):
        if not dialog.get_mapped():
            return True
        if dialog in state["answered"]:
            continue
        phase = state["phase"]
        if isinstance(dialog, Adw.AlertDialog):
            state["answered"].add(dialog)
            if dialog.get_heading() == "Add SSH Key?":
                assert dialog.get_default_response() == "cancel"
                assert "SHA256:" in dialog.get_body() and "120 seconds" in dialog.get_body()
                if phase == "cancel":
                    state["phase"] = "cancelled"
                    click(dialog, "Cancel")
                elif phase == "add":
                    state["phase"] = "added"
                    click(dialog, "Add Key")
                elif phase == "stale":
                    session.lock()
                    assert not session.dialogs and not session.vault.unlocked
                    dialog.emit("response", "add")
                    assert not session.dialogs
                    state["phase"] = "stale-locked"
                else:
                    raise AssertionError("Unexpected add phase: " + phase)
            elif dialog.get_heading() == "Could Not Complete Operation" and phase == "clear-changed":
                assert "changed" in dialog.get_body() and count() == 2
                state["phase"] = "clear-review-fresh"
                click(dialog, "Close")
            else:
                raise AssertionError("Unexpected SSH alert: " + dialog.get_heading() + ": " + dialog.get_body())
            return True
        title = dialog.get_title()
        state["answered"].add(dialog)
        if title == "Preferences":
            row(dialog, "Enable SSH Agent", Adw.SwitchRow).set_active(True)
            assert app.startup.ssh
            socket = row(dialog, "Agent Socket (blank = SSH_AUTH_SOCK)", Adw.EntryRow)
            socket.set_text(os.environ["SSH_AUTH_SOCK"])
            socket.emit("apply")
            provider = row(dialog, "Security Key Provider (blank = default)", Adw.EntryRow)
            provider.set_text("internal")
            provider.emit("apply")
            assert (app.startup.ssh_socket, app.startup.ssh_provider) == (os.environ["SSH_AUTH_SOCK"], "internal")
            dialog.close()
            state["phase"] = "reenabled" if phase == "reenable" else "ready"
        elif title == "SSH Key Settings":
            row(dialog, "Source", Adw.ComboRow).set_selected(1)
            row(dialog, "Key File", Adw.EntryRow).set_text(str(key))
            row(dialog, "Remove When Vault Locks", Adw.SwitchRow).set_active(True)
            row(dialog, "Limit Key Lifetime", Adw.SwitchRow).set_active(True)
            row(dialog, "Lifetime (Seconds)", Adw.SpinRow).set_value(120)
            if phase == "automatic":
                row(dialog, "Add When Vault Unlocks", Adw.SwitchRow).set_active(True)
                state["phase"] = "lock-after-save"
            else:
                state["phase"] = "saved"
            click(dialog, "Save")
        elif title == "SSH Public Key":
            assert row(dialog, "SHA256 Fingerprint", Adw.ActionRow).get_subtitle().startswith("SHA256:")
            assert any(isinstance(w, Gtk.Label) and w.get_label().startswith("ssh-ed25519 ") for w in widgets(dialog))
            dialog.close()
            state["phase"] = "cancel"
            ssh_views.add_key(session, entry())
        elif title == "Remove SSH Keys":
            who = "External Key" if phase.startswith("external") else "This Vault"
            assert any(isinstance(w, Adw.ActionRow) and who in w.get_subtitle() for w in widgets(dialog))
            cancelled = phase in ("remove-cancel", "external-cancel")
            state["phase"] = ("external-cancelled" if cancelled else "external-removed") if phase.startswith("external") else ("remove-cancelled" if cancelled else "removed")
            action = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Remove Key")
            click(dialog, "Cancel" if cancelled else "Remove Key")
            action.emit("clicked")  # Queued/duplicate activation cannot reverse Cancel or approve twice.
        elif title == "Clear SSH Agent":
            if phase == "removal-stale":
                action = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Clear Agent")
                session.lock()
                action.emit("clicked")
                assert not session.vault.unlocked and not session.dialogs
                state["phase"] = "removal-stale-locked"
            elif phase == "clear-cancel":
                state["phase"] = "clear-cancelled"
                action = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Clear Agent")
                click(dialog, "Cancel")
                action.emit("clicked")
            elif phase == "clear-approve":
                loaded = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True, check=True).stdout
                absent = next(path for path in external if Path(str(path) + ".pub").read_text().split()[1] not in loaded)
                subprocess.run(["ssh-add", str(absent)], check=True, capture_output=True)
                state["phase"] = "clear-changed"
                click(dialog, "Clear Agent")
            elif phase == "clear-fresh":
                assert sum(isinstance(w, Adw.ActionRow) and "External Key" in w.get_subtitle() for w in widgets(dialog)) == 2
                state["phase"] = "cleared"
                click(dialog, "Clear Agent")
            else:
                raise AssertionError("Unexpected clear phase: " + phase)
        elif title == "SSH Agent Keys":
            if phase == "removed":
                assert count() == 0
                dialog.close()
                for path in external:
                    subprocess.run(["ssh-add", str(path)], check=True, capture_output=True)
                state["database_before_agent_actions"] = session.path.read_bytes()
                state["phase"] = "external-list"
                ssh_views.manage(session)
            elif phase in ("external-list", "refresh-one"):
                listed = [w for w in widgets(dialog) if isinstance(w, Adw.ActionRow) and "External Key" in w.get_subtitle()]
                if phase == "external-list":
                    assert len(listed) == 2
                    subprocess.run(["ssh-add", "-d", str(external[0]) + ".pub"], check=True, capture_output=True)
                    search = next(w for w in widgets(dialog) if isinstance(w, Gtk.SearchEntry))
                    search.set_text("external-two")
                    state["phase"] = "refresh-one"
                else:
                    assert len(listed) == 1
                    search = next(w for w in widgets(dialog) if isinstance(w, Gtk.SearchEntry))
                    assert search.get_text() == "external-two"
                    search.set_text("")
                    subprocess.run(["ssh-add", str(external[0])], check=True, capture_output=True)
                    state["phase"] = "external-refreshed"
                next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_tooltip_text() == "Refresh Agent Keys").emit("clicked")
            elif phase in ("external-refreshed", "external-remove"):
                listed = [w for w in widgets(dialog) if isinstance(w, Adw.ActionRow) and "External Key" in w.get_subtitle()]
                assert len(listed) == 2
                check = next(w for w in widgets(listed[0]) if isinstance(w, Gtk.CheckButton))
                check.set_active(True)
                if phase == "external-refreshed":
                    only = next(w for w in widgets(dialog) if isinstance(w, Gtk.CheckButton) and w.get_label() == "Only This Vault")
                    only.set_active(True)
                    assert not check.get_active()
                    only.set_active(False)
                    search = next(w for w in widgets(dialog) if isinstance(w, Gtk.SearchEntry))
                    search.set_text("external-one")
                    search.emit("search-changed")
                    search.set_text("")
                    search.emit("search-changed")
                    state["phase"] = "external-cancel"
                    next(w for w in widgets(listed[0]) if isinstance(w, Gtk.Button) and w.get_tooltip_text() == "Remove SSH Key").emit("clicked")
                else:
                    click(dialog, "Remove Selected…")
            elif phase == "external-removed":
                assert count() == 1
                state["phase"] = "clear-cancel"
                click(dialog, "Clear Agent…")
            elif phase in ("clear-approve", "clear-fresh"):
                click(dialog, "Clear Agent…")
            elif phase == "cleared":
                assert count() == 0
                assert [path.read_bytes() for path in external] == external_bytes
                assert session.path.read_bytes() == state["database_before_agent_actions"]
                dialog.close()
                state["phase"] = "automatic"
                ssh_views.entry_settings(session, entry())
            elif phase == "remove-cancel" and not state.get("owned-refreshed"):
                next(w for w in widgets(dialog) if isinstance(w, Gtk.CheckButton) and w.get_label() == "Only This Vault").set_active(True)
                state["phase"] = "owned-refresh"
                next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_tooltip_text() == "Refresh Agent Keys").emit("clicked")
            else:
                if phase == "owned-refresh":
                    assert next(w for w in widgets(dialog) if isinstance(w, Gtk.CheckButton) and w.get_label() == "Only This Vault").get_active()
                    state["owned-refreshed"] = True
                    state["phase"] = "remove-cancel"
                remove = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_tooltip_text() == "Remove SSH Key")
                remove.emit("clicked")
        else:
            raise AssertionError("Unexpected SSH dialog: " + title)
        return True
    if state["phase"] == "lock-after-save" and not session.dialogs:
        state["phase"] = "locked"
        session.lock()
    return True


GLib.timeout_add(200, start)
GLib.timeout_add_seconds(45, lambda: (failures.append(AssertionError("SSH GTK timed out at " + state["phase"])), app.quit(), False)[-1])
try:
    result = app.run(["keyslot-ssh-smoke"])
    assert count() == 0, "Application shutdown left a managed fixture key loaded"
finally:
    if agent.poll() is None:
        agent.terminate()
        agent.wait(timeout=3)
    temporary.cleanup()
if failures:
    raise failures[0]
assert result == 0 and state["phase"] == "finished", "SSH GTK workflow did not complete"
print("SSH GTK preferences/settings/preview, cancel/add/sign, managed/external removal, filtering/selection, clear/cancel/changed-list review, auto-reload/background, stale-lock guards, live disable/re-enable and quit cleanup passed")
