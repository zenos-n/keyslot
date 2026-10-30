"""GTK browser connection revocation uses disposable vaults and private desktop state."""
import base64
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-browser-ui-")
os.environ["XDG_CONFIG_HOME"] = str(Path(temporary.name) / "config")

from keyslot.app import Keyslot
from keyslot import database_views
from gi.repository import Adw, Gdk, GLib, Gtk

Gtk.init_check()
assert Gdk.Display.get_default() is not None, "A display is required"
app = Keyslot()
errors = []
key = base64.b64encode(bytes(range(32))).decode()


def guard(callback):
    def run(*args):
        try:
            return callback(*args)
        except Exception as exc:
            errors.append(exc)
            app.quit()
            return False
    return run


def widgets(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


@guard
def start():
    session = app.active_session
    session.requested_path = Path(temporary.name) / "fixture.kdbx"
    session.vault.create(session.path, "public GTK test master")
    session.vault.browser_associate("Firefox laptop", key)
    session.window.show_vault(session.vault.snapshot)
    database_views.browser_connections(session, session.vault.browser_associations())
    GLib.timeout_add(50, shown)
    return False


@guard
def shown():
    session = app.active_session
    dialog = session.dialogs[-1]
    row = next(w for w in widgets(dialog) if isinstance(w, Adw.ActionRow) and w.get_title() == "Firefox laptop")
    remove = next(w for w in widgets(row) if isinstance(w, Gtk.Button) and w.get_tooltip_text() == "Revoke Browser Connection")
    assert remove.get_valign() == Gtk.Align.CENTER
    assert not any(key in w.get_label() for w in widgets(dialog) if isinstance(w, Gtk.Label))
    remove.emit("clicked")
    alert = session.dialogs[-1]
    assert isinstance(alert, Adw.AlertDialog)
    assert alert.get_default_response() == "cancel"
    next(w for w in widgets(alert) if isinstance(w, Gtk.Button) and w.get_label() == "Cancel").emit("clicked")
    assert session.vault.browser_authenticate("Firefox laptop", key)["authenticated"]
    remove.emit("clicked")
    next(w for w in widgets(session.dialogs[-1]) if isinstance(w, Gtk.Button) and w.get_label() == "Revoke Connection").emit("clicked")
    GLib.timeout_add(25, revoked, dialog)
    return False


@guard
def revoked(dialog):
    session = app.active_session
    if session.busy:
        return True
    assert not session.vault.browser_authenticate("Firefox laptop", key)["authenticated"]
    assert any(isinstance(w, Adw.ActionRow) and w.get_title() == "No Connected Browsers" for w in widgets(dialog))
    session.vault.browser_associate("Lock cancellation", key)
    session.close_dialogs()
    database_views.browser_connections(session, session.vault.browser_associations())
    remove = next(w for w in widgets(session.dialogs[-1]) if isinstance(w, Gtk.Button) and w.get_tooltip_text() == "Revoke Browser Connection")
    remove.emit("clicked")
    before = session.path.read_bytes()
    session.lock()
    assert not session.dialogs and not session.vault.unlocked
    assert session.path.read_bytes() == before
    app._smoke_completed = True
    app.quit()
    return False


GLib.timeout_add(200, start)
GLib.timeout_add_seconds(20, lambda: (errors.append(AssertionError("Browser GTK smoke timed out")), app.quit(), False)[-1])
result = app.run(["keyslot-browser-smoke"])
temporary.cleanup()
if errors:
    raise errors[0]
assert getattr(app, "_smoke_completed", False), "Browser management workflow did not complete"
assert result == 0
print("Browser GTK revocation, cancellation, compact actions and lock cleanup passed")
