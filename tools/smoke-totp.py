"""Mapped native OTP setup, passive live views, clipboard/QR export and cancellation."""
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-totp-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from keyslot.app import Keyslot
from keyslot import totp_views
from gi.repository import Adw, Gdk, GLib, Gtk

KEY = "JBSWY3DPEHPK3PXP"
app = Keyslot()
failures = []


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def row(root, title, kind=Adw.PasswordEntryRow):
    return next(widget for widget in widgets(root) if isinstance(widget, kind) and widget.get_title() == title)


def click(root, label=None, tooltip=None):
    button = next(widget for widget in widgets(root) if isinstance(widget, Gtk.Button)
                  and (widget.get_label() == label if label else widget.get_tooltip_text() == tooltip))
    button.emit("clicked")


def texts(root):
    return [widget.get_text() for widget in widgets(root) if isinstance(widget, Gtk.Label)]


def wait(predicate, seconds=15):
    until = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < until, "OTP UI fixture timed out"
        yield


def clipboard(session):
    result = []
    selection = session.window.get_clipboard()
    assert session.clipboard_provider is not None, "Copy must set an owned clipboard provider"
    assert selection.get_content() == session.clipboard_provider, "Repeated copies must retain their current clipboard ownership"
    selection.read_text_async(None, lambda source, value: result.append(source.read_text_finish(value)))
    yield from wait(lambda: bool(result))
    return result[0]


def scenario():
    yield from wait(lambda: app.active_session is not None)
    session = app.active_session
    app.set_background(False)
    session.requested_path = directory / "Fixture.kdbx"
    session.vault.create(session.path, "public fixture master")
    session.vault.save_entry(session.vault.snapshot.root, "Example <Account>", "public-user", "", "", "public password")
    session.window.show_vault(session.vault.snapshot)
    entry = session.vault.snapshot.entries[0]
    session.setup_totp(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Set Up One-Time Password")
    setup = session.dialogs[-1]
    key_field = row(setup, "Secret Key")
    key_field.set_text(KEY)
    click(setup, "Save")
    yield from wait(lambda: not session.busy and setup not in session.dialogs)
    assert not key_field.get_text(), "Normal setup closure must clear the secret and undo history"
    entry = session.vault.snapshot.entries[0]
    assert entry.totp

    # A visible live code polls passively, without postponing inactivity lock.
    calls = []
    original_sample = session.vault.totp_sample
    def sampled(*args):
        result = original_sample(*args)
        calls.append(result)
        return result
    with patch.object(session.vault, "totp_sample", sampled):
        click(session.window.detail, tooltip="Reveal One-Time Password")
        yield from wait(lambda: session.totp.views and calls and not session.jobs.busy)
        view = next(iter(session.totp.views))
        touched = app.last_activity
        yield from wait(lambda: len(calls) >= 3 and not session.jobs.busy)
        assert app.last_activity == touched, "Passive OTP refresh must not reset idle lock"
        assert re.fullmatch(r"\d{3} \d{3}", view.label.get_text())
        assert 0 < view.progress.get_fraction() <= 1
        assert "remaining" in view.remaining.get_text()
        click(session.window.detail, tooltip="Hide One-Time Password")
        assert not session.totp.views and not view.label.get_text() and not view.timer

    # The standalone code window supports fresh code/password+code clipboard actions.
    row(session.window.detail, "One-Time Password", Adw.ActionRow).emit("activated")
    code_dialog = session.dialogs[-1]
    yield from wait(lambda: session.totp.views and not session.jobs.busy and any(re.fullmatch(r"\d{3} \d{3}", text) for text in texts(code_dialog)))
    click(code_dialog, "Copy Code")
    yield from wait(lambda: not session.busy)
    copied = yield from clipboard(session)
    assert re.fullmatch(r"\d{6}", copied)
    click(code_dialog, "Copy Password and Code")
    yield from wait(lambda: not session.busy)
    copied = yield from clipboard(session)
    assert re.fullmatch(r"public password\d{6}", copied)
    retained = [widget for widget in widgets(code_dialog) if isinstance(widget, Gtk.Label)]
    code_dialog.close()
    yield from wait(lambda: code_dialog not in session.dialogs)
    assert not session.totp.views and all(not label.get_text() for label in retained)

    # Explicit Steam setup, QR display, setup-link copy and a real native SVG export.
    session.setup_totp(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Set Up One-Time Password")
    setup = session.dialogs[-1]
    row(setup, "Type", Adw.ComboRow).set_selected(1)
    click(setup, "Save")
    yield from wait(lambda: not session.busy and setup not in session.dialogs)
    entry = session.vault.snapshot.entries[0]
    assert session.vault.totp_config(entry)["mode"] == "steam"
    before = session.path.read_bytes()
    click(session.window.detail, "Show Authenticator QR Code…")
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Authenticator QR Code")
    qr = session.dialogs[-1]
    picture = next(widget for widget in widgets(qr) if isinstance(widget, Gtk.Picture))
    assert picture.get_paintable() is not None
    assert any("Steam settings" in text for text in texts(qr))
    click(qr, "Copy Setup Link")
    yield from wait(lambda: not session.busy)
    copied = yield from clipboard(session)
    assert "secret=" + KEY in copied and "encoder=steam" in copied
    target = directory / "Authenticator.svg"
    with patch.object(session, "choose_file", side_effect=lambda callback, **_kwargs: callback(str(target))):
        click(qr, "Save QR Code…")
    yield from wait(lambda: target.exists() and not session.busy)
    assert "<svg" in target.read_text() and target.stat().st_mode & 0o777 == 0o600
    assert session.path.read_bytes() == before
    qr.close()
    yield from wait(lambda: qr not in session.dialogs)
    assert picture.get_paintable() is None
    selection = session.window.get_clipboard()
    external = Gdk.ContentProvider.new_for_value("public external clipboard fixture")
    selection.set_content(external)
    session.clear_clipboard()
    assert selection.get_content() == external, "Clearing a previous copy must preserve a different clipboard owner"

    # QR views automatically close after their short disclosure window.
    session.totp.show_qr(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Authenticator QR Code")
    qr = session.dialogs[-1]
    picture = next(widget for widget in widgets(qr) if isinstance(widget, Gtk.Picture))
    real_time = time.monotonic
    with patch.object(totp_views, "time", SimpleNamespace(monotonic=lambda: real_time() + 46)):
        yield from wait(lambda: qr not in session.dialogs)
    assert picture.get_paintable() is None

    # Cancel clears edited key/link fields. Link setup parses real custom native settings.
    session.setup_totp(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Set Up One-Time Password")
    setup = session.dialogs[-1]
    secret = row(setup, "Secret Key")
    link = row(setup, "Setup Link")
    secret.set_text("public canceled fixture")
    setup.close()
    yield from wait(lambda: setup not in session.dialogs)
    assert not secret.get_text() and not link.get_text() and session.path.read_bytes() == before
    session.setup_totp(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Set Up One-Time Password")
    setup = session.dialogs[-1]
    row(setup, "Setup Method", Adw.ComboRow).set_selected(1)
    row(setup, "Setup Link").set_text(f"otpauth://totp/Fixture?secret={KEY}&period=45&digits=8&algorithm=SHA512")
    click(setup, "Save")
    yield from wait(lambda: not session.busy and setup not in session.dialogs)
    entry = session.vault.snapshot.entries[0]
    config = session.vault.totp_config(entry)
    assert (config["period"], config["digits"], config["algorithm"]) == (45, 8, "SHA-512")

    # Removal is reviewed, cancellation is nondestructive, and acceptance removes the current setup.
    session.setup_totp(entry)
    yield from wait(lambda: not session.busy and session.dialogs and session.dialogs[-1].get_title() == "Set Up One-Time Password")
    setup = session.dialogs[-1]
    before = session.path.read_bytes()
    click(setup, "Remove One-Time Password…")
    alert = session.dialogs[-1]
    click(alert, "Cancel")
    yield from wait(lambda: alert not in session.dialogs)
    assert setup in session.dialogs and session.path.read_bytes() == before
    click(setup, "Remove One-Time Password…")
    click(session.dialogs[-1], "Remove")
    yield from wait(lambda: not session.busy and setup not in session.dialogs)
    entry = session.vault.snapshot.entries[0]
    assert not entry.totp

    # A reply from the previous selected entry cannot fill the new entry's preview.
    session.vault.save_totp(entry, session.vault.totp_config(entry)["revision"], key=KEY)
    first = session.vault.snapshot.entries[0]
    session.vault.save_entry(first.group, "Other Account", "other-user", "", "", "public other password")
    other = next(item for item in session.vault.snapshot.entries if item.title == "Other Account")
    session.window.show_vault(session.vault.snapshot)
    session.window.selected_entry = first
    session.window.render_detail(first)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def paused(*args):
        entered.set()
        assert release.wait(8)
        try:
            return original_sample(*args)
        finally:
            finished.set()
    with patch.object(session.vault, "totp_sample", paused):
        click(session.window.detail, tooltip="Reveal One-Time Password")
        view = next(iter(session.totp.views))
        yield from wait(entered.is_set)
        session.window.selected_entry = other
        session.window.render_detail(other)
        release.set()
        yield from wait(lambda: finished.is_set() and not session.jobs.busy)
    assert not session.totp.views and not view.label.get_text()

    # Hide clears codes immediately. Idle lock cancels an outstanding passive request.
    first = next(item for item in session.vault.snapshot.entries if item.title == "Example <Account>")
    session.window.selected_entry = first
    session.window.render_detail(first)
    click(session.window.detail, tooltip="Reveal One-Time Password")
    yield from wait(lambda: session.totp.views and not session.jobs.busy)
    app.set_background(True)
    session.host_window.close()
    assert not session.totp.views and session.vault.unlocked
    app.select_session(session)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    with patch.object(session.vault, "totp_sample", paused):
        click(session.window.detail, tooltip="Reveal One-Time Password")
        view = next(iter(session.totp.views))
        yield from wait(entered.is_set)
        app.startup.lock_minutes = 1
        app.last_activity = time.monotonic() - 61
        app._idle_check()
        release.set()
        yield from wait(finished.is_set)
        yield
    assert not session.vault.unlocked and not session.totp.views and not session.dialogs
    assert not view.label.get_text() and not view.timer
    app.quit()


steps = scenario()
def tick():
    try:
        for session in app.sessions:
            for dialog in session.dialogs:
                if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() == "Could Not Complete Operation":
                    raise AssertionError(dialog.get_body())
        next(steps)
        return True
    except StopIteration:
        return False
    except Exception as exc:
        failures.append(exc)
        app.quit()
        return False

app.connect("activate", lambda *_: GLib.timeout_add(25, tick))
status = app.run(["keyslot-totp-fixture"])
temporary.cleanup()
if failures:
    raise failures[0]
assert status == 0
print("GTK OTP standard/Steam/link setup, passive code/countdown, fresh clipboard, secret clearing, QR export/expiry, reviewed removal, selection/hide/idle-lock cancellation: PASS")
