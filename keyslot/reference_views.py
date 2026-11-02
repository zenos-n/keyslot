"""Insert standard KeePass field references using entry metadata only."""
from .i18n import mark as _mark, tr as _tr
from uuid import UUID

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from .database_views import _dialog, _save


FIELDS = [("T", _mark('Title')), ("U", _mark('Username')), ("P", _mark('Password')),
          ("A", _mark('Website')), ("N", _mark('Notes')), ("I", _mark('Entry ID'))]


def insert_text(row, text):
    selection = row.get_selection_bounds()
    start, end = selection[-2:] if selection else (row.get_position(), row.get_position())
    current = row.get_text()
    row.set_text(current[:start] + text + current[end:])
    row.set_position(start + len(text))
    row.grab_focus()


def menu(session, parent, header, targets, current_entry=None):
    button = Gtk.MenuButton(icon_name="insert-link-symbolic", tooltip_text=_tr("Insert Field Reference"),
                            valign=Gtk.Align.CENTER)
    popover = Gtk.Popover()
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                  margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
    for label, field, apply in targets:
        item = Gtk.Button(label=label, css_classes=["flat"], halign=Gtk.Align.FILL)
        def choose(*_, field=field, apply=apply):
            popover.popdown()
            show(session, parent, apply, field, current_entry)
        item.connect("clicked", choose)
        box.append(item)
    popover.set_child(box)
    button.set_popover(popover)
    header.pack_start(button)


def show(session, parent, apply, destination="P", current_entry=None):
    if not session.active or not session.vault.unlocked:
        return
    epoch, generation = session.epoch, session.vault.generation
    dialog, header, box = _dialog(_tr("Insert Field Reference"), width=520, height=580)
    state = {"closed": False, "matches": [], "shown": 0}
    group = Adw.PreferencesGroup(description=_tr("Use a field from another entry in this database. The reference follows its entry even if it is renamed or moved."))
    field = Adw.ComboRow(title=_tr("Reference Field"), model=Gtk.StringList.new([_tr(label) for _, label in FIELDS]))
    field.set_selected(next((i for i, (code, _) in enumerate(FIELDS) if code == destination), 2))
    group.add(field)
    box.append(group)
    search = Gtk.SearchEntry(placeholder_text=_tr("Search entries"))
    box.append(search)
    rows = Gtk.ListBox(css_classes=["boxed-list"], selection_mode=Gtk.SelectionMode.SINGLE,
                      valign=Gtk.Align.START, vexpand=False)
    box.append(rows)
    more = Gtk.Button(label=_tr("Show More Entries"))
    box.append(more)
    empty = Gtk.Label(label=_tr("No matching entries"), css_classes=["dim-label"])
    box.append(empty)
    preview = Gtk.Label(wrap=True, selectable=True, css_classes=["monospace"])
    box.append(preview)

    def valid():
        return (not state["closed"] and session.active and session.vault.unlocked
                and session.epoch == epoch and session.vault.generation == generation)

    def expression():
        row = rows.get_selected_row()
        if not valid() or row is None:
            return ""
        target = next((e for e in session.vault.snapshot.entries
                       if e.uuid == row.entry_uuid and e.addressable and not e.recycled), None)
        wanted = FIELDS[field.get_selected()][0]
        if target is None or (current_entry and target.uuid == current_entry.uuid and wanted == destination):
            return ""
        return "{REF:" + wanted + "@I:" + UUID(target.uuid).hex.upper() + "}"

    def update(*_):
        text = expression()
        preview.set_label(text or (_tr("Choose a different entry or field") if rows.get_selected_row() else _tr("Select an entry")))
        insert.set_sensitive(bool(text))

    def submit(*_):
        text = expression()
        if text:
            dialog.close()
            apply(text)

    insert = _save(header, submit, _tr('Insert'))
    insert.set_sensitive(False)
    rows.connect("row-selected", update)
    field.connect("notify::selected", update)

    def append_page(*_):
        end = min(len(state["matches"]), state["shown"] + 100)
        for entry in state["matches"][state["shown"]:end]:
            subtitle = " · ".join(value for value in (entry.username, entry.group_path) if value)
            row = Adw.ActionRow(title=entry.title or _tr("Untitled Entry"), subtitle=subtitle,
                                use_markup=False, activatable=True)
            row.entry_uuid = entry.uuid
            rows.append(row)
        state["shown"] = end
        more.set_visible(end < len(state["matches"]))

    def filter_entries(*_):
        if not valid():
            return
        while child := rows.get_first_child():
            rows.remove(child)
        query = search.get_text().casefold()
        state["matches"] = [entry for entry in session.vault.snapshot.entries
                            if entry.addressable and not entry.recycled
                            and query in " ".join((entry.title, entry.username, entry.group_path)).casefold()]
        state["shown"] = 0
        empty.set_visible(not state["matches"])
        append_page()
        update()

    search.connect("search-changed", filter_entries)
    more.connect("clicked", append_page)
    parent_closed = parent.connect("closed", lambda *_: dialog.force_close())
    def closed(*_):
        state["closed"] = True
        state["matches"].clear()
        parent.disconnect(parent_closed)
        preview.set_label("")
    dialog.connect("closed", closed)
    filter_entries()
    session.present_dialog(dialog)
