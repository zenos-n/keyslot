"""Revision-bound native history inspection; protected values are fetched on demand."""
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango
from .database_views import _dialog

SECTIONS = {"attributes": "Fields", "properties": "Entry Properties", "autotype": "Auto-Type",
            "data": "Custom Data", "attachments": "Attachments"}
NAMES = {"UserName": "Username", "URL": "Website"}


def _modified(item):
    stamp = GLib.DateTime.new_from_iso8601(item["modified"], None)
    return stamp.to_local().format("%x %X") if stamp else item["modified"]


def _button(icon, title, callback):
    button = Gtk.Button(icon_name=icon, tooltip_text=title, valign=Gtk.Align.CENTER)
    button.connect("clicked", lambda *_: callback())
    return button


def _confirm(app, dialogs, title, body, label, operation):
    if app.busy:
        return
    alert = Adw.AlertDialog(heading=title, body=body)
    alert.add_response("cancel", "Cancel")
    alert.add_response("apply", label)
    alert.set_default_response("cancel")
    alert.set_close_response("cancel")
    alert.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE)
    def response(_dialog, answer):
        if answer != "apply" or app.busy:
            return
        for dialog in reversed(dialogs):
            dialog.close()
        app.run_job(operation, app.window.show_vault)
    alert.connect("response", response)
    app.present_dialog(alert)


def show(app, entry, history=None):
    if app.busy:
        return
    if history is None:
        app.run_job(lambda: app.vault.history(entry), lambda items: show(app, entry, items))
        return
    if not history:
        app.toast("This entry has no saved versions")
        return
    revision = history[0]["revision"]
    dialog, header, box = _dialog("Entry History", height=480)
    group = Adw.PreferencesGroup(description="Inspect a version to compare its fields and attachments. Restoring keeps the current version in history.")
    box.append(group)
    for item in reversed(history):
        index = item["index"]
        row = Adw.ActionRow(title=GLib.markup_escape_text(item["title"] or "Untitled"), subtitle=_modified(item), activatable=True)
        row.connect("activated", lambda _row, i=index: compare(app, entry, history, i, dialog))
        row.add_suffix(_button("view-reveal-symbolic", "Inspect and Compare Version",
                               lambda i=index: compare(app, entry, history, i, dialog)))
        row.add_suffix(_button("edit-undo-symbolic", "Restore This Version", lambda i=index: _confirm(app, [dialog],
            "Restore History Version?", "This replaces the entry with the selected version. The current version is kept in history.",
            "Restore", lambda: app.vault.restore_history(entry, i, revision))))
        row.add_suffix(_button("user-trash-symbolic", "Delete This Version", lambda i=index: _confirm(app, [dialog],
            "Delete History Version?", "This saved version will be removed from the database.", "Delete",
            lambda: app.vault.remove_history(entry, i, revision))))
        group.add(row)
    delete_all = Gtk.Button(label="Delete All History…", css_classes=["destructive-action"], halign=Gtk.Align.CENTER)
    delete_all.connect("clicked", lambda *_: _confirm(app, [dialog], "Delete All Entry History?",
        "All saved versions of this entry will be removed. The current entry is kept.", "Delete All",
        lambda: app.vault.clear_history(entry, revision)))
    box.append(delete_all)
    def clear(*_):
        # Normal dismissal must clear labels too, not only the lock path.
        def clear_labels(widget):
            if isinstance(widget, Gtk.Label):
                widget.set_label("")
            child = widget.get_first_child()
            while child:
                clear_labels(child)
                child = child.get_next_sibling()
        clear_labels(box)
        while box.get_first_child():
            box.remove(box.get_first_child())
    dialog._clear_sensitive_fields = clear
    dialog.connect("closed", clear)
    app.present_dialog(dialog)


def compare(app, entry, history, index, parent):
    if app.busy:
        return
    revision = history[0]["revision"]
    versions = [-1] + [item["index"] for item in reversed(history)]
    labels = ["Current Version"] + [f"Version {item['index'] + 1} · {_modified(item)}" for item in reversed(history)]
    dialog, header, box = _dialog("Compare Entry Versions", width=760, height=700)
    controls = Adw.PreferencesGroup()
    left = Adw.ComboRow(title="Selected Version", model=Gtk.StringList.new(labels))
    right = Adw.ComboRow(title="Compare With", model=Gtk.StringList.new(labels))
    left.set_selected(versions.index(index))
    only_changes = Adw.SwitchRow(title="Only Show Changes", active=True)
    for widget in (left, right, only_changes):
        controls.add(widget)
    box.append(controls)
    summary = Gtk.Label(xalign=0, wrap=True)
    box.append(summary)
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
    box.append(content)
    restore = Gtk.Button(label="Restore Selected Version…", css_classes=["suggested-action"], valign=Gtk.Align.CENTER)
    header.pack_end(restore)
    state = {"closed": False, "request": 0, "data": None, "display": 0, "reload": 0}
    def clear_values():
        state["display"] += 1
        # Clear before unparenting; GTK/accessibility may retain the detached widgets.
        def clear_labels(widget):
            if isinstance(widget, Gtk.Label):
                widget.set_label("")
            child = widget.get_first_child()
            while child:
                clear_labels(child)
                child = child.get_next_sibling()
        clear_labels(content)
        while content.get_first_child():
            content.remove(content.get_first_child())
    def close(*_):
        state.update(closed=True, data=None, request=state["request"] + 1)
        clear_values()
        if state["reload"]:
            GLib.source_remove(state["reload"])
            state["reload"] = 0
        summary.set_label("")
    dialog._clear_sensitive_fields = close
    dialog.connect("closed", close)
    def selected(which):
        return versions[which.get_selected()]
    def download(version, key):
        def save(path):
            if state["closed"] or app.busy:
                return
            app.run_job(lambda: app.vault.export_history_attachment(entry, version, revision, key, path),
                        lambda _value: app.toast("Attachment saved"))
        app.choose_file(save, save=True, name=Path(key).name)
    def cell(pair, side, cell_data, section, key, version, request, field, protection_changed):
        column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
        column.append(Gtk.Label(label="Selected Version" if side == "left" else "Comparison Version", xalign=0,
                                css_classes=["caption", "dim-label"]))
        value = Gtk.Label(xalign=0, yalign=0, wrap=True, selectable=True)
        value.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        column.append(value)
        if protection_changed and cell_data["present"]:
            column.append(Gtk.Label(label="Field Protection Enabled" if cell_data.get("storage_protected") else "Field Protection Disabled",
                                    xalign=0, css_classes=["caption", "dim-label"]))
        def reset():
            value.set_label("Hidden" if cell_data["protected"] else cell_data.get("value", "") or "Empty")
        if not cell_data["present"]:
            value.set_label("Not Present")
        else:
            reset()
            if cell_data["protected"]:
                actions = Gtk.Box(spacing=6)
                shown = {"value": False, "request": 0}
                reveal = Gtk.Button(label="Reveal", halign=Gtk.Align.START)
                def conceal(*_):
                    if not field.get_expanded():
                        shown["request"] += 1
                        shown["value"] = False
                        reveal.set_label("Reveal")
                        reset()
                field.connect("notify::expanded", conceal)
                def clicked(*_):
                    if shown["value"]:
                        shown["value"] = False
                        reveal.set_label("Reveal")
                        reset()
                        return
                    if app.busy or state["closed"]:
                        return
                    shown["request"] += 1
                    secret_request = shown["request"]
                    def revealed(text):
                        if state["closed"] or request != state["display"] or secret_request != shown["request"]:
                            return
                        shown["value"] = True
                        value.set_label(text or "Empty")
                        reveal.set_label("Hide")
                    app.run_job(lambda: app.vault.history_value(entry, version, revision, section, key), revealed)
                reveal.connect("clicked", clicked)
                actions.append(reveal)
                column.append(actions)
            if section == "attachments":
                save = _button("document-save-symbolic", "Save This Version’s Attachment", lambda: download(version, key))
                column.append(save)
        pair.append(column)
    def render():
        clear_values()
        data = state["data"]
        if state["closed"] or data is None:
            return
        summary.set_label(f"{data['changed']} fields differ. Protected values stay hidden until revealed.")
        for section in data["sections"]:
            rows = [row for row in section["rows"] if row["changed"] or not only_changes.get_active()]
            if not rows:
                continue
            group = Adw.PreferencesGroup(title=SECTIONS[section["section"]])
            for row in rows:
                label = "Changed" if row["changed"] else "Unchanged"
                if not row["left"]["present"]:
                    label = "Only in Comparison Version"
                elif not row["right"]["present"]:
                    label = "Only in Selected Version"
                field = Adw.ExpanderRow(title=GLib.markup_escape_text(NAMES.get(row["key"], row["key"])), subtitle=label)
                pair = Gtk.Box(spacing=24, homogeneous=True, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
                for side, chooser in (("left", left), ("right", right)):
                    cell(pair, side, row[side], section["section"], row["key"], selected(chooser), state["display"], field,
                         section["section"] == "attributes" and row["left"].get("storage_protected") != row["right"].get("storage_protected"))
                field.add_row(pair)
                group.add(field)
            content.append(group)
        if not content.get_first_child():
            content.append(Gtk.Label(label="No differences between these versions", wrap=True, css_classes=["dim-label"]))
    def load(*_):
        if state["closed"]:
            return
        if app.busy:
            # A running read may finish, but its result must not repaint different selectors.
            state["request"] += 1
            state["data"] = None
            clear_values()
            if not state["reload"]:
                def retry():
                    if state["closed"]:
                        state["reload"] = 0
                        return False
                    if app.busy:
                        return True
                    state["reload"] = 0
                    load()
                    return False
                state["reload"] = GLib.timeout_add(40, retry)
            return
        state["request"] += 1
        request = state["request"]
        state["data"] = None
        clear_values()
        summary.set_label("Loading versions…")
        restore.set_sensitive(selected(left) != -1)
        def done(data):
            if state["closed"] or request != state["request"]:
                return
            state["data"] = data
            render()
        before, after = selected(left), selected(right)
        app.run_job(lambda: app.vault.compare_history(entry, before, after, revision), done)
    left.connect("notify::selected", load)
    right.connect("notify::selected", load)
    only_changes.connect("notify::active", lambda *_: render())
    def restore_selected(*_):
        version = selected(left)
        if version == -1 or state["closed"]:
            return
        _confirm(app, [parent, dialog], "Restore History Version?",
            "This replaces the entry with the selected version. The current version is kept in history.", "Restore",
            lambda: app.vault.restore_history(entry, version, revision))
    restore.connect("clicked", restore_selected)
    app.present_dialog(dialog)
    load()
