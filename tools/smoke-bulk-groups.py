"""Mapped selection controls, bulk operations and recursive cross-vault groups."""
import os
from pathlib import Path
import sys
import tempfile
import time
import ctypes as ct

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-bulk-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
from keyslot.app import Keyslot
import gi
gi.require_version("GdkX11", "4.0")
from gi.repository import Adw, Gdk, GdkX11, GLib, Gtk

# The package gate runs serially in its private Xvfb so these real pointer events cannot affect another test.
x11 = ct.CDLL(os.environ["KEYSLOT_TEST_X11"])
xtst = ct.CDLL(os.environ["KEYSLOT_TEST_XTST"])
x11.XOpenDisplay.argtypes = [ct.c_char_p]
x11.XOpenDisplay.restype = ct.c_void_p
x11.XDefaultRootWindow.argtypes = [ct.c_void_p]
x11.XDefaultRootWindow.restype = ct.c_ulong
x11.XTranslateCoordinates.argtypes = [ct.c_void_p, ct.c_ulong, ct.c_ulong, ct.c_int, ct.c_int,
                                     ct.POINTER(ct.c_int), ct.POINTER(ct.c_int), ct.POINTER(ct.c_ulong)]
x11.XKeysymToKeycode.argtypes = [ct.c_void_p, ct.c_ulong]
x11.XKeysymToKeycode.restype = ct.c_uint
x11.XSetInputFocus.argtypes = [ct.c_void_p, ct.c_ulong, ct.c_int, ct.c_ulong]
x11.XRaiseWindow.argtypes = [ct.c_void_p, ct.c_ulong]
x11.XSync.argtypes = [ct.c_void_p, ct.c_int]
x11.XCloseDisplay.argtypes = [ct.c_void_p]
xtst.XTestFakeMotionEvent.argtypes = [ct.c_void_p, ct.c_int, ct.c_int, ct.c_int, ct.c_ulong]
xtst.XTestFakeButtonEvent.argtypes = [ct.c_void_p, ct.c_uint, ct.c_int, ct.c_ulong]
xtst.XTestFakeKeyEvent.argtypes = [ct.c_void_p, ct.c_uint, ct.c_int, ct.c_ulong]
display = x11.XOpenDisplay(None)
assert display


def pointer(widget, button=0, shift=False):
    window = widget.get_root()
    ok, bounds = widget.compute_bounds(window)
    assert ok and bounds.size.width > 0 and bounds.size.height > 0
    xid = GdkX11.X11Surface.get_xid(window.get_surface())
    root_x, root_y, child = ct.c_int(), ct.c_int(), ct.c_ulong()
    assert x11.XTranslateCoordinates(display, xid, x11.XDefaultRootWindow(display),
        int(bounds.origin.x + bounds.size.width * .8), int(bounds.origin.y + bounds.size.height / 2),
        ct.byref(root_x), ct.byref(root_y), ct.byref(child))
    x11.XRaiseWindow(display, xid)
    x11.XSetInputFocus(display, xid, 2, 0)
    xtst.XTestFakeMotionEvent(display, 0, root_x.value, root_y.value, 0)
    shift_code = x11.XKeysymToKeycode(display, Gdk.KEY_Shift_L)
    if shift:
        xtst.XTestFakeKeyEvent(display, shift_code, 1, 0)
    if button:
        xtst.XTestFakeButtonEvent(display, button, 1, 0)
        xtst.XTestFakeButtonEvent(display, button, 0, 0)
    if shift:
        xtst.XTestFakeKeyEvent(display, shift_code, 0, 0)
    x11.XSync(display, 0)

app = Keyslot()
failures = []


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def click(dialog, label):
    next(item for item in widgets(dialog) if isinstance(item, Gtk.Button) and item.get_label() == label).emit("clicked")


def combo(dialog, title):
    return next(item for item in widgets(dialog) if isinstance(item, Adw.ComboRow) and item.get_title() == title)


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "Bulk/group GTK fixture timed out"
        yield


def scenario():
    yield from wait(lambda: app.active_session is not None)
    source = app.active_session
    app.set_background(False)
    source.requested_path = directory / "Source.kdbx"
    source.vault.create(source.path, "public fixture master")
    source.vault.add_group(source.vault.snapshot.root, "Collection")
    group_id = next(item.uuid for item in source.vault.snapshot.groups if item.name == "Collection")
    source.vault.add_group(group_id, "Nested")
    child_id = next(item.uuid for item in source.vault.snapshot.groups if item.name == "Nested")
    source.vault.add_group(group_id, "Empty")
    for title, group in (("Alpha", source.vault.snapshot.root), ("Beta", source.vault.snapshot.root), ("Gamma", child_id)):
        source.vault.save_entry(group, title, "public user", "https://example.org", "public notes", "public " + title)
    original_ids = {item.uuid for item in source.vault.snapshot.entries}
    source.window.show_vault(source.vault.snapshot)
    destination = app.new_window(present=False)
    destination.requested_path = directory / "Destination.kdbx"
    destination.vault.create(destination.path, "different public master")
    destination.window.show_vault(destination.vault.snapshot)
    view = source.window

    yield from wait(lambda: view.entries.get_first_child().get_width() > 100)
    first = view.entries.get_first_child()
    pointer(first)
    yield from wait(lambda: first.selection_check.get_mapped())
    pointer(first.selection_check, button=1)
    yield from wait(lambda: view.selection_mode and len(view.selected_entries()) == 1)
    assert [item.title for item in view.selected_entries()] == ["Alpha"]
    assert view.selection_cancel.get_visible() and not view.new_entry_button.get_visible()
    pointer(view.entries.get_row_at_index(1), button=1)
    yield from wait(lambda: len(view.selected_entries()) == 2)
    assert {item.title for item in view.selected_entries()} == {"Alpha", "Beta"}
    pointer(view.entries.get_row_at_index(1), button=1)
    yield from wait(lambda: len(view.selected_entries()) == 1)
    assert view.selected_entries()[0].title == "Alpha"
    pointer(view.entries.get_row_at_index(0), button=1)
    yield from wait(lambda: not view.selected_entries())
    pointer(view.entries.get_row_at_index(0), button=1)
    yield from wait(lambda: len(view.selected_entries()) == 1)
    pointer(view.entries.get_row_at_index(2), button=1, shift=True)
    yield from wait(lambda: len(view.selected_entries()) == 3)
    view.selection_cancel.emit("clicked")
    assert not view.selection_mode and view.new_entry_button.get_visible()
    # Allow GTK to allocate the replacement normal-mode rows before targeting pointer coordinates.
    yield
    pointer(view.entries.get_row_at_index(2), button=3)
    yield from wait(lambda: view.selection_mode and len(view.selected_entries()) == 1)
    assert view.selected_entries()[0].title == "Gamma"
    view.selection_cancel.emit("clicked")

    # The real toggle/checkbox/selection actions, keyboard handling and filtered list agree.
    view.selection_toggle.emit("clicked")
    assert view.selection_mode and view.selection_bar.get_revealed()
    view.select_all.emit("clicked")
    assert len(view.selected_entries()) == 3
    assert all(item.get_active() for item in widgets(view.entries) if isinstance(item, Gtk.CheckButton))
    next(item for item in widgets(view.entries) if isinstance(item, Gtk.CheckButton)).set_active(False)
    assert len(view.selected_entries()) == 2
    view.select_all.emit("clicked")
    assert len(view.selected_entries()) == 3
    view.select_all.emit("clicked")
    assert not view.selected_entries() and not view.bulk_transfer.get_sensitive() and not view.bulk_recycle.get_sensitive()
    view._entry_keys(None, Gdk.KEY_a, 0, Gdk.ModifierType.CONTROL_MASK)
    assert len(view.selected_entries()) == 3
    view.search.set_text("Alpha")
    yield from wait(lambda: not source.busy and view.entry_count == 1 and view.search_matches is not None)
    assert [item.title for item in view.selected_entries()] == ["Alpha"]
    view.search.set_text("")
    yield from wait(lambda: not source.busy and view.entry_count == 3)
    view._entry_keys(None, Gdk.KEY_a, 0, Gdk.ModifierType.CONTROL_MASK)

    def start(copy, target_index, target_group=None):
        view.bulk_transfer.emit("clicked")
        dialog = source.dialogs[-1]
        assert dialog.get_title() == "Copy or Move Entries"
        combo(dialog, "Action").set_selected(0 if copy else 1)
        combo(dialog, "Destination Vault").set_selected(target_index)
        if target_group:
            row = combo(dialog, "Destination Group")
            row.set_selected(next(index for index in range(row.get_model().get_n_items())
                                  if target_group in row.get_model().get_string(index)))
        click(dialog, "Continue")

    before_source, before_destination = source.path.read_bytes(), destination.path.read_bytes()
    start(True, 1)
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog)
                    and source.dialogs[-1].get_heading() == "Copy 3 Entries?")
    alert = source.dialogs[-1]
    assert all(title in alert.get_body() for title in ("Alpha", "Beta", "Gamma"))
    click(alert, "Cancel")
    yield from wait(lambda: not source.dialogs)
    source.jobs.executor.submit(lambda: None).result(timeout=3)
    assert source.path.read_bytes() == before_source and destination.path.read_bytes() == before_destination
    assert view.selection_mode and len(view.selected_entries()) == 3

    start(True, 1)
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog)
                    and source.dialogs[-1].get_heading() == "Copy 3 Entries?")
    click(source.dialogs[-1], "Copy")
    yield from wait(lambda: not source.busy and not destination.busy and len(destination.vault.snapshot.entries) == 3)
    assert not view.selection_mode and not view.selection_bar.get_revealed()
    assert {item.uuid for item in source.vault.snapshot.entries} == original_ids
    assert original_ids.isdisjoint(item.uuid for item in destination.vault.snapshot.entries)

    view.selection_toggle.emit("clicked")
    view._entry_keys(None, Gdk.KEY_a, 0, Gdk.ModifierType.CONTROL_MASK)
    start(False, 0, "Collection")
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog)
                    and source.dialogs[-1].get_heading() == "Move 3 Entries?")
    click(source.dialogs[-1], "Move")
    yield from wait(lambda: not source.busy and not view.selection_mode and view.selected_group == group_id)
    assert {item.uuid for item in source.vault.snapshot.entries} == original_ids
    assert all(item.group == group_id for item in source.vault.snapshot.entries)

    view.selection_toggle.emit("clicked")
    view._entry_keys(None, Gdk.KEY_a, 0, Gdk.ModifierType.CONTROL_MASK)
    view.bulk_recycle.emit("clicked")
    alert = source.dialogs[-1]
    assert alert.get_heading() == "Move 3 Entries to Recycle Bin?"
    before = source.path.read_bytes()
    click(alert, "Cancel")
    yield from wait(lambda: not source.dialogs)
    assert source.path.read_bytes() == before and len(view.selected_entries()) == 3
    view.bulk_recycle.emit("clicked")
    click(source.dialogs[-1], "Move to Recycle Bin")
    yield from wait(lambda: not source.busy and not view.selection_mode)
    assert all(item.recycled for item in source.vault.snapshot.entries)

    # Transfer a group through its real editor action, including empty and nested groups.
    source.vault.save_entry(child_id, "Grouped Entry", "public user", "", "", "public grouped password")
    source.window.show_vault(source.vault.snapshot)
    source.edit_group()
    editor = source.dialogs[-1]
    click(editor, "Copy or Move Group…")
    yield from wait(lambda: source.dialogs and source.dialogs[-1].get_title() == "Copy or Move Group")
    chooser = source.dialogs[-1]
    groups = combo(chooser, "Destination Group").get_model()
    assert all("Collection" not in groups.get_string(index) for index in range(groups.get_n_items()))
    combo(chooser, "Destination Vault").set_selected(1)
    click(chooser, "Continue")
    yield from wait(lambda: source.dialogs and isinstance(source.dialogs[-1], Adw.AlertDialog)
                    and source.dialogs[-1].get_heading() == "Move Group?")
    assert "3 groups and 1 entry" in source.dialogs[-1].get_body()
    assert "KeeShare" in source.dialogs[-1].get_body()
    click(source.dialogs[-1], "Move")
    yield from wait(lambda: not source.busy and not destination.busy and not any(item.uuid == group_id for item in source.vault.snapshot.groups))
    imported = next(item for item in destination.vault.snapshot.groups if item.name == "Collection")
    assert imported.uuid != group_id and imported.uuid == destination.window.selected_group
    children = [item for item in destination.vault.snapshot.groups if item.parent == imported.uuid]
    assert {item.name for item in children} == {"Nested", "Empty"}
    entry = next(item for item in destination.vault.snapshot.entries if item.title == "Grouped Entry")
    assert entry.group == next(item.uuid for item in children if item.name == "Nested")
    assert destination.vault.attribute(entry) == "public grouped password"
    assert len(destination.vault.snapshot.entries) == 4
    assert all(item.recycled for item in source.vault.snapshot.entries)

    # Root cannot be transferred, and lock clears selection without affecting the other vault.
    view.selected_group = source.vault.snapshot.root
    source.edit_group()
    assert not any(isinstance(item, Gtk.Button) and item.get_label() == "Copy or Move Group…" for item in widgets(source.dialogs[-1]))
    source.dialogs[-1].close()
    yield from wait(lambda: not source.dialogs)
    source.vault.save_entry(source.vault.snapshot.root, "After Lock", "", "", "", "public lock password")
    view.show_vault(source.vault.snapshot)
    view.selection_toggle.emit("clicked")
    view._entry_keys(None, Gdk.KEY_a, 0, Gdk.ModifierType.CONTROL_MASK)
    assert view.selection_mode and len(view.selected_entries()) == 1
    view._entry_keys(None, Gdk.KEY_Escape, 0, Gdk.ModifierType(0))
    assert not view.selection_mode
    view.selection_toggle.emit("clicked")
    source.lock()
    yield from wait(lambda: not source.vault.unlocked)
    assert not view.selection_mode and not view.selected_entries() and not view.selection_bar.get_revealed()
    assert destination.vault.unlocked and len(destination.vault.snapshot.entries) == 4
    app.quit()


steps = scenario()
def tick():
    try:
        for session in app.sessions:
            if session.pending_errors:
                raise AssertionError(session.pending_errors)
            for dialog in session.dialogs:
                if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() in (
                    "Could Not Complete Operation", "Transfer Could Not Be Confirmed", "Transfer Did Not Complete"):
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
status = app.run(["keyslot-bulk-groups-fixture"])
x11.XCloseDisplay(display)
temporary.cleanup()
if failures:
    raise failures[0]
assert status == 0
print("GTK real pointer hover/checkbox/toggle/Shift-range/secondary selection, keyboard/filtering, atomic copy/move/recycle, recursive groups and lock cleanup: PASS")
