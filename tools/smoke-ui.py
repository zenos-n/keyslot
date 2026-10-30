"""Run inside a graphical session: dbus-run-session -- python3 tools/smoke-ui.py."""
from pathlib import Path
import os
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keyslot.app import Keyslot
from keyslot.application import INTERFACE, OBJECT_PATH
from keyslot import database_views, preferences
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

Gtk.init_check()
if Gdk.Display.get_default() is None:
    raise SystemExit("A graphical display is required for the UI smoke test.")

temporary = tempfile.TemporaryDirectory(prefix="keyslot-ui-")
os.environ["XDG_CONFIG_HOME"] = str(Path(temporary.name) / "config")
csv_source = Path(temporary.name) / "Source.csv"
app = Keyslot()
failure = []


def guard(fn):
    def wrapped(*args):
        try:
            return fn(*args)
        except Exception as exc:
            failure.append(exc)
            app.quit()
            return False
    return wrapped


@guard
def start():
    assert app.window is not None
    session = app.active_session
    path = Path(temporary.name) / "Demo.kdbx"
    session.requested_path = path
    session._unlock_dialog(str(path))
    GLib.timeout_add(200, unlock_sized)
    return False


@guard
def unlock_sized():
    session = app.active_session
    dialog = session.dialogs[-1]
    assert dialog.get_height() >= 360, "Unlock dialog collapsed instead of measuring its contents"
    session.close_dialogs()
    session.jobs.executor.submit(lambda: None).result(timeout=2)
    return start_vault()


@guard
def start_vault():
    app.active_session.vault.create(Path(temporary.name) / "Demo.kdbx", "test-master-password")
    app.active_session.vault.add_group(app.active_session.vault.snapshot.root, "Personal")
    group = next(g for g in app.active_session.vault.snapshot.groups if g.name == "Personal")
    app.active_session.vault.save_entry(group.uuid, "Example", "alice", "https://example.org", "Demo note", "demo-password")
    app.active_session.window.show_vault(app.active_session.vault.snapshot)
    session = app.active_session
    app.set_background(True)
    session.host_window.close()
    assert not session.host_window.get_visible()
    assert session.vault.unlocked and not session.jobs.closed
    assert app.background and not session.active
    app.select_session(session)
    assert session.host_window.get_visible() and not app.background
    assert session.vault.unlocked
    app.set_background(False)
    assert app.active_session.window.selected_entry.title == "Example"
    widgets = [app.active_session.window.detail]
    while widgets:
        widget = widgets.pop()
        if isinstance(widget, Gtk.Button):
            parent = widget.get_parent()
            while parent and not isinstance(parent, Adw.ActionRow):
                parent = parent.get_parent()
            if parent:
                assert widget.get_valign() == Gtk.Align.CENTER, "Row suffix buttons must not stretch vertically"
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
    database_settings = app.active_session.vault.settings()
    database_report = app.active_session.vault.report()
    existing_copy = Path(temporary.name) / "Copy.kdbx"
    existing_copy.write_bytes(b"public replacement confirmation fixture")
    csv_source.write_text("Title,Password\nPublic,public CSV smoke fixture\n")
    csv_data = app.active_session.vault.inspect_csv(csv_source, reveal=True)
    import_review = app.active_session.vault.inspect_import(csv_source, "csv")
    for show in (lambda: preferences.show(app.active_session), lambda: preferences.enroll(app.active_session),
                 app.active_session.edit_entry, app.active_session.new_group, app.active_session.edit_group,
                 lambda: app.active_session.edit_attribute(app.active_session.window.selected_entry),
                 lambda: app.active_session.setup_totp(app.active_session.window.selected_entry, ""),
                 lambda: app.active_session.move_entry(app.active_session.window.selected_entry),
                 lambda: database_views.settings(app.active_session, database_settings),
                 lambda: database_views.import_database(app.active_session),
                 lambda: database_views.csv_import(app.active_session, str(csv_source)),
                 lambda: database_views.csv_preview(app.active_session, str(csv_source), {}, dict(csv_data, preview=[list(row) for row in csv_data["preview"]])),
                 lambda: database_views.review_import(app.active_session, {"source":str(csv_source), "source_format":"csv"}, import_review),
                 lambda: database_views.change_key(app.active_session, database_settings),
                 lambda: database_views.merge(app.active_session, str(app.active_session.vault.path)),
                 lambda: database_views.report(app.active_session, database_report),
                 lambda: database_views.save_copy(app.active_session, existing_copy),
                 lambda: database_views.export(app.active_session), app.active_session.shortcuts, app.active_session.about):
        show()
        assert app.active_session.dialogs
        app.active_session.dialogs[-1].force_close()
    app.active_session.generator()
    dialog = app.active_session.dialogs[-1]
    GLib.timeout_add(50, generator_ready, dialog)
    return False


@guard
def generator_ready(dialog):
    if app.busy:
        return True
    switches, buttons, output = {}, {}, None
    widgets = [dialog]
    while widgets:
        widget = widgets.pop()
        if isinstance(widget, Adw.SwitchRow):
            switches[widget.get_title()] = widget
        if isinstance(widget, Gtk.Button) and widget.get_label():
            buttons[widget.get_label()] = widget
        if isinstance(widget, Adw.PasswordEntryRow):
            output = widget
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
    assert output is not None and output.get_text()
    for title in ("Lowercase (a–z)", "Uppercase (A–Z)", "Symbols (!@#$…)"):
        switches[title].set_active(False)
    assert not output.get_text() and not buttons["Copy"].get_sensitive(), "Character changes must invalidate the previous output"
    buttons["Generate"].emit("clicked")
    GLib.timeout_add(50, generator_selected, dialog, output)
    return False


@guard
def generator_selected(dialog, output):
    if app.busy:
        return True
    value = output.get_text()
    assert len(value) == 24 and value.isascii() and value.isdigit(), "Numbers-only selection was not respected"
    app.active_session.close_dialogs()
    return start_csv()


@guard
def start_csv():
    database_views.csv_import(app.active_session, str(csv_source))
    dialog = app.active_session.dialogs[-1]
    widgets = [dialog]
    while widgets:
        widget = widgets.pop()
        if isinstance(widget, Gtk.Button) and widget.get_label() == "Read Columns":
            widget.emit("clicked")
            break
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
    else:
        raise AssertionError("CSV parser action is missing")
    GLib.timeout_add(50, csv_mapped, dialog)
    return False


@guard
def csv_mapped(dialog):
    if app.busy:
        return True
    fields = {}
    widgets = [dialog]
    while widgets:
        widget = widgets.pop()
        if isinstance(widget, Adw.ComboRow):
            fields[widget.get_title()] = widget.get_selected()
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
    assert fields["Title"] == 1
    assert fields["Password"] == 2
    app.active_session.close_dialogs()
    first = app.active_session
    second = app.new_window()
    second.vault.create(Path(temporary.name) / "Second.kdbx", "second-master")
    second.vault.save_entry(second.vault.snapshot.root, "Second Entry", "bob", "", "", "public second fixture")
    second.window.show_vault(second.vault.snapshot)
    assert first.vault.unlocked and second.vault.unlocked
    app.open_database(first.vault.path)
    assert app.active_session is first
    assert len(app.sessions) == 2, "Opening an existing path must select its window"
    second.lock()
    assert first.vault.unlocked and not second.vault.unlocked
    app.active_session.window.search.set_text("no matching entries")
    app.active_session.window.search_matches = set()
    app.active_session.window.render_entries()
    assert app.active_session.window.entries.get_first_child() is None
    app.active_session.window.search.set_text("")
    app.active_session.window.search_matches = None
    app.active_session.window.render_entries()
    app.active_session.copy("demo clipboard")
    app.active_session.clear_clipboard()
    app.window.set_default_size(420, 700)
    GLib.timeout_add(300, narrow)
    return False


@guard
def narrow():
    view = app.sessions[0].window
    assert view.outer.get_collapsed(), (view.get_width(), view.breakpoints.get_width())
    assert view.inner.get_collapsed(), (view.get_width(), view.breakpoints.get_width(), app.sessions[0].host_window.get_width())
    rows_height = 0
    child = view.entries.get_first_child()
    while child:
        rows_height += child.get_height()
        child = child.get_next_sibling()
    assert view.entries.get_height() <= rows_height + 8, "The boxed entry list must fit its rows"
    app.select_session(app.sessions[1])
    assert not app.active_session.vault.unlocked and not app.locked
    app.connection.call(app.get_application_id(), OBJECT_PATH, "org.freedesktop.DBus.Properties",
        "Get", GLib.Variant("(ss)", (INTERFACE, "Locked")), GLib.VariantType.new("(v)"),
        Gio.DBusCallFlags.NONE, 2000, None, state_received)
    return False


@guard
def state_received(connection, result):
    assert connection.call_finish(result).unpack() == (False,)
    app.select_session(app.sessions[0])
    database_views.change_key(app.active_session, app.active_session.vault.settings())
    password_rows = []
    widgets = [app.active_session.dialogs[-1]]
    while widgets:
        widget = widgets.pop()
        if isinstance(widget, Adw.PasswordEntryRow):
            password_rows.append(widget)
            widget.set_text("public smoke-test value")
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
    assert password_rows
    raw_data = app.active_session.vault.inspect_csv(csv_source, reveal=True)
    database_views.csv_preview(app.active_session, str(csv_source), {}, raw_data)
    raw_labels = []
    widgets = [app.active_session.dialogs[-1]]
    while widgets:
        widget = widgets.pop()
        if isinstance(widget, Gtk.Label) and widget.get_label() == "public CSV smoke fixture":
            raw_labels.append(widget)
        child = widget.get_first_child()
        while child:
            widgets.append(child)
            child = child.get_next_sibling()
    assert raw_labels
    selected = []
    class DeferredFileDialog:
        def open(self, parent, cancellable, callback):
            self.cancellable, self.callback = cancellable, callback
        def open_finish(self, result):
            return Gio.File.new_for_path(str(Path(temporary.name) / "selection"))
        select_folder = open
        select_folder_finish = open_finish
    pending = DeferredFileDialog()
    folder = DeferredFileDialog()
    with patch("keyslot.application.Gtk.FileDialog", side_effect=[pending, folder]):
        app.active_session.choose_file(selected.append)
        app.active_session.choose_file(selected.append, folder=True)
    app.lock()
    assert not app.active_session.dialogs
    assert all(row.get_text() == "" for row in password_rows)
    assert all(label.get_label() == "" for label in raw_labels)
    assert not raw_data["preview"]
    assert pending.cancellable.is_cancelled()
    assert folder.cancellable.is_cancelled()
    pending.callback(pending, None)
    folder.callback(folder, None)
    assert not selected, "A file-dialog result delivered after lock must not trigger an operation"
    assert app.active_session.window.stack.get_visible_child_name() == "locked"
    assert app.active_session.window.entries.get_first_child() is None
    assert not app.active_session.vault.unlocked
    assert all(not session.vault.unlocked and not session.dialogs for session in app.sessions)
    app.connection.call(app.get_application_id(), OBJECT_PATH, "org.freedesktop.DBus.Properties",
        "Get", GLib.Variant("(ss)", (INTERFACE, "Locked")), GLib.VariantType.new("(v)"),
        Gio.DBusCallFlags.NONE, 2000, None, locked_received)


@guard
def locked_received(connection, result):
    assert connection.call_finish(result).unpack() == (True,)
    closed = app.active_session
    closed.host_window.close()
    assert closed.jobs.closed
    assert len(app.sessions) == 1
    print("GTK dialogs, CSV mapping, database windows, duplicate-path selection, D-Bus aggregate state and lock-all cleanup: PASS")
    app._smoke_completed = True
    app.quit()


GLib.timeout_add(300, start)
GLib.timeout_add_seconds(60, lambda: (failure.append(TimeoutError("UI smoke timed out")), app.quit(), False)[-1])
try:
    app.run([])
finally:
    temporary.cleanup()
if failure:
    raise failure[0]
assert getattr(app, "_smoke_completed", False), "GTK workflow did not execute to completion"
