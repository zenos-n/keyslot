"""Mapped GTK icon/advanced editors and cancellation against a disposable real vault."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
temporary = tempfile.TemporaryDirectory(prefix="keyslot-appearance-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from test_appearance import png
from keyslot.app import Keyslot
from keyslot import appearance
from gi.repository import Adw, Gdk, GLib, Gtk

app = Keyslot()
failures = []


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def row(dialog, title, kind=Adw.EntryRow):
    return next(widget for widget in widgets(dialog) if isinstance(widget, kind) and widget.get_title() == title)


def click(root, label=None, tooltip=None):
    button = next(widget for widget in widgets(root) if isinstance(widget, Gtk.Button)
                  and (widget.get_label() == label if label else widget.get_tooltip_text() == tooltip))
    button.emit("clicked")


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "Appearance UI fixture timed out"
        yield


def scenario():
    yield from wait(lambda: app.active_session is not None)
    session = app.active_session
    app.set_background(False)
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.path, "public fixture master")
    session.vault.add_group(session.vault.snapshot.root, "Visual Group")
    group_id = next(group.uuid for group in session.vault.snapshot.groups if group.name == "Visual Group")
    session.vault.save_entry(group_id, "Visual Entry", "public user", "https://example.org", "Fixture notes", "public fixture password")
    session.window.show_vault(session.vault.snapshot)
    yield from wait(lambda: bool(session.icons.cache) and not session.icons.pending)
    assert all(isinstance(image.get_paintable(), Gdk.Texture) for image in widgets(session.window.entries)
               if isinstance(image, Gtk.Image) and image.get_pixel_size() == 32)
    entry = session.vault.snapshot.entries[0]
    session.edit_entry(entry)
    yield from wait(lambda: session.dialogs and session.dialogs[-1].get_title() == "Edit Entry" and not session.busy)
    editor = session.dialogs[-1]
    row(editor, "Text Color").set_text("#f0d0a0")
    color = next(widget for widget in widgets(row(editor, "Text Color")) if isinstance(widget, Gtk.ColorDialogButton)).get_rgba()
    assert abs(color.red - 240 / 255) < .01 and abs(color.blue - 160 / 255) < .01
    row(editor, "Background Color").set_text("#303040")
    row(editor, "URL Override").set_text("https://example.org/{USERNAME}")
    row(editor, "Exclude from Password Reports", Adw.SwitchRow).set_active(True)
    row(editor, "Icon", Adw.ActionRow).emit("activated")
    yield from wait(lambda: session.dialogs[-1].get_title() == "Choose Icon" and not session.busy)
    chooser = session.dialogs[-1]
    grid = next(widget for widget in widgets(chooser) if isinstance(widget, Gtk.FlowBox))
    grid.get_child_at_index(12).get_child().emit("clicked")
    yield from wait(lambda: chooser not in session.dialogs)
    click(editor, "Save")
    yield from wait(lambda: not session.busy and editor not in session.dialogs)
    entry = session.vault.snapshot.entries[0]
    assert entry.icon == 12 and entry.foreground == "#f0d0a0" and entry.exclude_reports
    assert entry.override_url == "https://example.org/{USERNAME}"
    assert session.vault.attribute(entry) == "public fixture password"

    session.window.selected_group = group_id
    session.edit_group()
    editor = session.dialogs[-1]
    row(editor, "Tags (separated by semicolons)").set_text("fixture;visual")
    row(editor, "Search Entries", Adw.ComboRow).set_selected(2)
    row(editor, "Expires", Adw.SwitchRow).set_active(True)
    row(editor, "Expiry (ISO 8601)").set_text("2028-01-01T00:00:00Z")
    row(editor, "Icon", Adw.ActionRow).emit("activated")
    yield from wait(lambda: session.dialogs[-1].get_title() == "Choose Icon" and not session.busy)
    chooser = session.dialogs[-1]
    source = directory / "Blue.png"
    source.write_bytes(png())
    with patch.object(session, "choose_file", side_effect=lambda callback, **_kwargs: callback(str(source))):
        click(chooser, "Import Icon…")
    yield from wait(lambda: not session.busy and chooser not in session.dialogs)
    click(editor, "Save")
    yield from wait(lambda: not session.busy and editor not in session.dialogs)
    group = next(group for group in session.vault.snapshot.groups if group.uuid == group_id)
    icon = group.custom_icon
    assert icon and group.tags == "fixture;visual" and group.searching == 2 and group.expires
    session.edit_entry()
    editor = session.dialogs[-1]
    row(editor, "Title").set_text("Inherited Icon Entry")
    click(editor, "Save")
    yield from wait(lambda: not session.busy and editor not in session.dialogs)
    inherited = next(entry for entry in session.vault.snapshot.entries if entry.title == "Inherited Icon Entry")
    assert inherited.custom_icon == icon

    # Deletion cancellation preserves the database, then explicit deletion repairs all uses.
    session.edit_entry(inherited)
    yield from wait(lambda: session.dialogs and session.dialogs[-1].get_title() == "Edit Entry" and not session.busy)
    editor = session.dialogs[-1]
    row(editor, "Icon", Adw.ActionRow).emit("activated")
    yield from wait(lambda: session.dialogs[-1].get_title() == "Choose Icon" and not session.busy)
    chooser = session.dialogs[-1]
    before = session.path.read_bytes()
    click(chooser, tooltip="Delete Icon")
    alert = session.dialogs[-1]
    click(alert, "Cancel")
    yield from wait(lambda: alert not in session.dialogs)
    assert session.path.read_bytes() == before
    click(chooser, tooltip="Delete Icon")
    click(session.dialogs[-1], "Delete")
    yield from wait(lambda: not session.busy and chooser not in session.dialogs)
    assert session.vault.icons()["total"] == 0
    assert not any(entry.custom_icon for entry in session.vault.snapshot.entries)
    assert not any(group.custom_icon for group in session.vault.snapshot.groups)
    yield from wait(lambda: session.dialogs[-1].get_title() == "Choose Icon")
    session.dialogs[-1].close()
    yield from wait(lambda: session.dialogs[-1] is editor)
    click(editor, "Save")
    yield from wait(lambda: not session.busy and editor not in session.dialogs)

    # An icon read completing after lock cannot populate a cache or repaint a closed vault.
    session.icons.clear()
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = session.vault.icon
    def paused(*args):
        entered.set()
        assert release.wait(8)
        try:
            return original(*args)
        finally:
            finished.set()
    session.vault.icon = paused
    session.icons.image(session.vault.snapshot.entries[0], 32)
    yield from wait(entered.is_set)
    session.lock()
    release.set()
    yield from wait(finished.is_set)
    yield
    assert not session.icons.cache and not session.vault.unlocked
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
status = app.run(["keyslot-appearance-fixture"])
temporary.cleanup()
if failures:
    raise failures[0]
assert status == 0
print("GTK icons, standard/custom selection, import/deletion review, advanced entry/group edits, inheritance and late-lock cleanup: PASS")
