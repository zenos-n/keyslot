"""Auto-type settings, destination review and character picking."""
from .i18n import trc as _trc, ntrf as _ntrf, mark as _mark, tr as _tr, trf as _trf
import os
import re
import weakref
from gi.repository import Gio, GLib
from .database_views import Adw, Gtk, _dialog, _save, _spin
from .passkey_views import _lifetime
from .backend import VaultError
from . import autotype
from .autotype_flow import Flow
from .autotype_fields import TYPE_LABELS, COPY_LABELS, TYPES, COPY_FIELDS, SELECTOR_KEYS, FieldInfo


def shortcut_sender(connection, sender):
    try:
        return connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "GetNameOwner", GLib.Variant("(s)", ("org.gnome.Shell",)), GLib.VariantType.new("(s)"),
            Gio.DBusCallFlags.NO_AUTO_START, 1000, None).unpack()[0] == sender
    except GLib.Error:
        return False


def _guarded_lifetime(session, dialog, clearer=None):
    alive = _lifetime(session, dialog)
    state = {"closing": False}
    def clear_sensitive(*_):
        state["closing"] = True
        if clearer:
            clearer()
    dialog._clear_sensitive_fields = clear_sensitive
    dialog.connect("closed", clear_sensitive)
    def close_attempt(*_):
        from .application import clear_dialog_fields
        clear_dialog_fields(dialog)
        dialog.force_close()
    dialog.set_can_close(False)
    dialog.connect("close-attempt", close_attempt)
    return lambda: not state["closing"] and alive() and session.active


def settings(session, entry=None, group=None, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(lambda: session.vault.autotype_settings(entry, group),
                        lambda value: settings(session, entry, group, value))
        return
    dialog, header, box = _dialog(_tr("Auto-Type Settings"), height=620)
    current = _lifetime(session, dialog)
    fields = Adw.PreferencesGroup(description=_tr("Leave the sequence empty to inherit the group’s sequence."))
    if entry:
        enabled = Adw.SwitchRow(title=_tr("Enable Auto-Type"), active=data["enabled"])
    else:
        enabled = Adw.ComboRow(title=_tr("Auto-Type"), model=Gtk.StringList.new([_tr("Inherit"), _tr("Enabled"), _tr("Disabled")]))
        enabled.set_selected(data["enabled"])
    fields.add(enabled)
    sequence = Adw.EntryRow(title=_tr("Default Sequence"), text=data["sequence"])
    fields.add(sequence)
    effective = Adw.ActionRow(title=_tr("Inherited Sequence"), subtitle=data["effective_sequence"], use_markup=False,
                             subtitle_lines=3)
    fields.add(effective)
    box.append(fields)
    associations = []
    if entry:
        if not data["group_enabled"]:
            box.append(Gtk.Label(label=_tr("Auto-type is disabled by the parent group."), wrap=True, xalign=0))
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(section)
        def add_association(window="", custom=""):
            group_box = Adw.PreferencesGroup(title=_tr("Window Association"))
            pattern = Adw.EntryRow(title=_tr("Window Pattern"), text=window)
            custom_sequence = Adw.EntryRow(title=_tr("Sequence (Optional)"), text=custom)
            group_box.add(pattern)
            group_box.add(custom_sequence)
            item = (group_box, pattern, custom_sequence)
            remove = Gtk.Button(icon_name="edit-delete-symbolic", tooltip_text=_tr("Remove Window Association"), valign=Gtk.Align.CENTER)
            remove.connect("clicked", lambda *_: (associations.remove(item), section.remove(group_box)) if current() else None)
            pattern.add_suffix(remove)
            section.append(group_box)
            associations.append(item)
        for item in data["associations"]:
            add_association(item["window"], item["sequence"])
        add = Gtk.Button(label=_tr("Add Window Association"), halign=Gtk.Align.START)
        add.connect("clicked", lambda *_: add_association() if current() else None)
        box.append(add)
    box.append(Gtk.Label(label=_tr("Use * in window patterns, or //regular expression//. Sequences support {USERNAME}, "
        "{PASSWORD}, {TAB}, {ENTER}, {TOTP}, {PICKCHARS}, {S:Custom Field}, delays and key modifiers."),
        wrap=True, xalign=0, css_classes=["dim-label"]))
    def save(*_):
        if not current():
            return
        values = dict(sequence=sequence.get_text(), enabled=enabled.get_active() if entry else enabled.get_selected())
        if entry:
            values["associations"] = [dict(window=pattern.get_text(), sequence=custom.get_text())
                                      for _, pattern, custom in associations]
        def saved(snapshot):
            if current():
                dialog.close()
                session.window.show_vault(snapshot)
                session.toast(_tr("Auto-type settings saved"))
        session.run_job(lambda: session.vault.save_autotype_settings(entry, group, **values), saved)
    _save(header, save)
    session.present_dialog(dialog)


def choose(session, entry=None, target=None, windows=None, *, flow=None, allow_automatic=True, global_shortcut=False, field=None, temporary=False):
    if not session.vault.unlocked:
        from .autotype_unlock import request
        request(session, allow_automatic=allow_automatic, global_shortcut=global_shortcut)
        return
    if session.busy:
        return
    if session.application.autotype_unlock:
        session.toast(_tr("Auto-Type is already in progress"))
        return
    if field is not None and (entry is None or field not in TYPES):
        session.error(_tr("Choose an entry and a supported Auto-Type field."))
        return
    if flow is None:
        if global_shortcut and any(item.host_window.is_active() for item in session.application.sessions):
            return
        previous = session.application.autotype_flow
        if previous:
            if previous.valid():
                session.toast(_tr("Auto-Type is already in progress"))
                return
            previous.cancel(lock=True)
        if session.dialogs or session.file_requests:
            session.toast(_tr("Close the current dialog before using Auto-Type"))
            return
        flow = Flow(session, allow_automatic, temporary=temporary)
        session.application.autotype_flow = flow
    if not flow.valid():
        flow.cancel()
        return
    if target is None:
        if os.environ.get("XDG_SESSION_TYPE") == "wayland":
            flow.run(session, autotype.capture_target, lambda value: choose(session, entry, value, flow=flow, field=field))
            return
        if windows is None:
            flow.run(session, session.vault.autotype_targets, lambda value: choose(session, entry, windows=value, flow=flow, field=field))
            return
        dialog, header, box = _dialog(_tr("Auto-Type Destination"), height=420)
        current = _guarded_lifetime(session, dialog)
        def chosen(window):
            if current() and flow.valid():
                flow.release(dialog)
                dialog.close()
                choose(session, entry, dict(backend="x11", **window), flow=flow, field=field)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
        box.append(rows)
        for window in windows:
            row = Adw.ActionRow(title=window["title"], use_markup=False, title_lines=2, activatable=True)
            row.connect("activated", lambda _row, window=window: chosen(window))
            rows.append(row)
        if not windows:
            box.append(Adw.StatusPage(title=_tr("No Destination Windows"), description=_tr("Open the application you want to type into.")))
        flow.present(session, dialog)
        return
    options = session.application.startup.autotype
    if entry:
        confirm = options["always_ask"] and not options["skip_main_confirmation"]
        _prepare(session, entry, target, TYPES[field][1] if field else "", flow, confirm=confirm, field=field)
        return
    candidates = list(session.application.sessions)
    captured = [(owner, owner.epoch, owner.vault.identity, owner.vault.generation, owner.vault.snapshot)
                for owner in candidates if owner.vault.unlocked and not owner.jobs.closed]
    def collect():
        records = []
        for owner, epoch, identity, generation, snapshot in captured:
            if owner.epoch != epoch or owner.jobs.closed or not owner.vault.unlocked:
                continue
            with owner.vault.operation(generation):
                values = owner.vault.autotype_matches(target["title"], options["match_title"],
                                                      options["match_url"], options["hide_expired"])
            records.append((owner, epoch, identity, generation, snapshot, values))
        return records
    def matched(records):
        contexts, matches = [], []
        for owner, epoch, identity, generation, snapshot, values in records:
            if (owner.epoch != epoch or owner.vault.identity is not identity or owner.vault.generation != generation
                    or owner.vault.snapshot is not snapshot or not owner.vault.unlocked or owner.jobs.closed):
                continue
            contexts.append(Flow.capture(owner))
            entries = {item.uuid: item for item in snapshot.entries if not item.recycled and item.addressable}
            matches.extend((owner, entries[item["entry"]], item["sequence"]) for item in values if item["entry"] in entries)
        if len(matches) == 1 and target.get("title") and not options["always_ask"] and flow.allow_automatic:
            owner, candidate, sequence = matches[0]
            _prepare(owner, candidate, target, sequence, flow, confirm=False)
        else:
            _choose_match(session, target, matches, contexts, flow=flow)
    flow.run(session, collect, matched)


def _prepare(session, entry, target, sequence, flow, *, confirm, field=None):
    if not flow.valid() or session.jobs.closed or not session.vault.unlocked:
        flow.cancel()
        return
    flow.owner = flow.capture(session)
    flow.watch(session)
    options = session.application.startup.autotype
    snapshot = weakref.ref(session.vault.snapshot)
    def prepared(data):
        choice = (entry.uuid, snapshot)
        if confirm or data["pick"]:
            review(session, target, data, choice, flow=flow)
        else:
            _execute(session, target, data, [], choice, flow)
    flow.run(session, lambda: session.vault.autotype_prepare(entry, target, sequence,
        options["delay"], options["start_delay"], field=field), prepared)


def _choose_match(session, target, matches, contexts, *, flow):
    dialog, header, box = _dialog(_tr("Auto-Type"), height=520)
    current = _guarded_lifetime(session, dialog, lambda: clear_rows())
    state = {"rendered": None, "pending": False, "serial": 0, "timer": 0, "activate": None, "copying": False, "selection": None}
    sort_generation = session.vault.generation
    destination = Adw.PreferencesGroup(title=_tr("Destination"))
    destination.add(Adw.ActionRow(title=target["title"], use_markup=False, title_lines=3))
    box.append(destination)
    search = Gtk.SearchEntry(placeholder_text=_tr("Search entries"))
    box.append(search)
    scope = Gtk.CheckButton(label=_tr("Search All Unlocked Databases"), active=not matches, sensitive=bool(matches))
    box.append(scope)
    config = session.application.startup
    sort_column = Adw.ComboRow(title=_tr("Sort By"), model=Gtk.StringList.new([_tr("Group"), _tr("Title"), _tr("Username"), _tr("Sequence")]),
                               selected=config.autotype["sort_column"])
    sort_order = Adw.ComboRow(title=_tr("Order"), model=Gtk.StringList.new([_tr("Ascending"), _tr("Descending")]),
                              selected=config.autotype["sort_order"])
    sort_group = Adw.PreferencesGroup()
    sort_group.add(sort_column)
    sort_group.add(sort_order)
    sort_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, width_request=320,
                       margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
    sort_box.append(sort_group)
    sort_button = Gtk.MenuButton(icon_name="view-sort-ascending-symbolic", tooltip_text=_tr("Sort Entries"),
                                 popover=Gtk.Popover(child=sort_box), valign=Gtk.Align.CENTER)
    header.pack_start(sort_button)
    box.append(Gtk.Label(label=_tr("All databases: use KeePassXC search syntax, for example tag:work or title:mail. "
        "Window matches: filter group, title or username with wildcards."), wrap=True, xalign=0, css_classes=["dim-label"]))
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, activate_on_single_click=False,
                      css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    status = Gtk.Label(label=_tr("No matching entries. Search to choose another entry."), wrap=True)
    box.append(status)
    box.append(Gtk.Label(label=_tr("Select an entry, then type it or copy a field. Double-click to type its sequence."),
                         wrap=True, xalign=0, css_classes=["dim-label"]))
    def owner_current(owner):
        for context in contexts:
            reference, epoch, identity, generation, snapshot = context
            if reference() is owner:
                return bool(not owner.jobs.closed and owner.vault.unlocked and owner.epoch == epoch
                    and owner.vault.identity is identity and owner.vault.generation == generation
                    and owner.vault.snapshot is snapshot())
        return False
    def query_key():
        return search.get_text(), scope.get_active(), sort_column.get_selected(), sort_order.get_selected()
    def ready():
        return current() and flow.valid() and not state["copying"] and state["rendered"] == query_key()
    def prepare(owner, entry, sequence, field=None):
        if not ready() or not owner_current(owner):
            return
        flow.release(dialog)
        dialog.close()
        _prepare(owner, entry, target, sequence, flow, confirm=False, field=field)
    def continue_selected(*_):
        row = rows.get_selected_row()
        if ready() and row:
            row.emit("activated")
    actions = Gio.SimpleActionGroup()
    field_actions = {}
    menu = Gio.Menu()
    typing_menu, copy_menu = Gio.Menu(), Gio.Menu()
    def update_fields():
        live = ready()
        for name, action in field_actions.items():
            copy = name.startswith("copy-")
            action.set_enabled(live and info.available(name.split("-", 1)[1], typing=not copy))
        error.set_label(info.error if live else "")
        error.set_visible(live and bool(info.error))
    info = FieldInfo(update_fields)
    dialog.connect("closed", lambda *_: info.close())
    error = Gtk.Label(xalign=0, wrap=True, css_classes=["error"], visible=False)
    box.append(error)
    def copy_field(owner, entry, name):
        state["copying"] = True
        update_fields()
        proceed.set_sensitive(False)
        for control in (rows, search, scope, sort_button):
            control.set_sensitive(False)
        flow.owner = flow.capture(owner)
        flow.watch(owner)
        def read():
            if not owner.vault.autotype_fields(entry)[name]:
                raise VaultError("This entry does not contain the requested field.")
            return owner.vault.copy_totp(entry) if name == "totp" else owner.vault.attribute(entry, COPY_FIELDS[name])
        def copied(value):
            if not current() or not flow.valid():
                return
            def published(success):
                if not current() or not flow.valid():
                    return
                state["copying"] = False
                rows.set_sensitive(True)
                search.set_sensitive(True)
                scope.set_sensitive(bool(matches))
                sort_button.set_sensitive(True)
                proceed.set_sensitive(rows.get_selected_row() is not None)
                update_fields()
                if success:
                    seconds = session.application.startup.clipboard_seconds
                    session.toast(_ntrf('Copied · clipboard clears in {count} second', 'Copied · clipboard clears in {count} seconds', seconds) if seconds else _tr("Copied"))
                    session.windows.copied()
                else:
                    session.toast(_tr("Could not copy to the clipboard"))
            session.application.clipboards.copy(owner, value, published, valid=flow.valid)
        flow.run(owner, read, copied)
    def field_action(name, copy=False):
        if not ready() or not info.available(name, typing=not copy):
            return
        row = rows.get_selected_row()
        if row and owner_current(row.choice[0]) and info.available(name, typing=not copy, entry=row.choice[1]):
            owner, entry, _sequence = row.choice
            if copy:
                copy_field(owner, entry, name)
            else:
                prepare(owner, entry, TYPES[name][1], name)
    for name, (title, _sequence, _qt) in TYPES.items():
        action = Gio.SimpleAction.new("type-" + name, None)
        action.connect("activate", lambda *_args, name=name: field_action(name))
        actions.add_action(action)
        field_actions["type-" + name] = action
        typing_menu.append(_tr(TYPE_LABELS[name]), "autotype-fields.type-" + name)
    for name in COPY_FIELDS:
        action = Gio.SimpleAction.new("copy-" + name, None)
        action.connect("activate", lambda *_args, name=name: field_action(name, True))
        actions.add_action(action)
        field_actions["copy-" + name] = action
        copy_menu.append(_tr(COPY_LABELS[name]), "autotype-fields.copy-" + name)
    menu.append_section(None, typing_menu)
    menu.append_section(None, copy_menu)
    dialog.insert_action_group("autotype-fields", actions)
    keys = Gtk.ShortcutController(scope=Gtk.ShortcutScope.MANAGED)
    for name, accelerator in SELECTOR_KEYS.items():
        for prefix, key in (("type-", accelerator), ("copy-", accelerator.replace("<Control>", "<Control><Shift>"))):
            keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string(key),
                Gtk.NamedAction.new("autotype-fields." + prefix + name)))
    toggle = Gio.SimpleAction.new("scope", None)
    toggle.connect("activate", lambda *_: scope.set_active(not scope.get_active()) if scope.get_sensitive() else None)
    actions.add_action(toggle)
    keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string("<Control>f"),
                                       Gtk.NamedAction.new("autotype-fields.scope")))
    dialog.add_controller(keys)
    proceed = Adw.SplitButton(label=_trc("auto-type action", "Type"), menu_model=menu, valign=Gtk.Align.CENTER,
                             dropdown_tooltip="Type or Copy a Field", css_classes=["suggested-action"])
    proceed.connect("clicked", continue_selected)
    header.pack_end(proceed)
    proceed.set_sensitive(False)
    def selected(_rows, row):
        proceed.set_sensitive(ready() and row is not None)
        if row:
            owner, entry, _sequence = row.choice
            info.select(owner, entry)
        else:
            info.clear()
    rows.connect("row-selected", selected)
    update_fields()
    def clear_rows():
        state["selection"] = None
        while row := rows.get_first_child():
            row.set_activatable(False)
            row.set_title("")
            row.set_subtitle("")
            rows.remove(row)
            row.choice = None
        info.clear()
        proceed.set_sensitive(False)
    def display(choices, key):
        if not current() or not flow.valid() or key != query_key():
            return
        selection = state["selection"]
        clear_rows()
        state["rendered"] = key
        selected_row = remembered_row = fallback_row = None
        recent = session.application.autotype_recent
        remembered = recent.current()
        count = 0
        for owner, entry, sequence, metadata in choices:
            if not owner_current(owner):
                continue
            title = metadata["title"].replace("\0", "")
            username = metadata["username"].replace("\0", "")
            row = Adw.ActionRow(title=title or _tr("Untitled Entry"), subtitle=" · ".join(filter(None,
                (username, owner.vault.snapshot.name, entry.group_path, sequence))), use_markup=False, title_lines=2,
                subtitle_lines=2, activatable=True)
            row.connect("activated", lambda _row, owner=owner, entry=entry, sequence=sequence: prepare(owner, entry, sequence))
            row.choice = (owner, entry, sequence)
            rows.append(row)
            if selection and selection[0] is owner and selection[1].uuid == entry.uuid and selection[2] == sequence:
                selected_row = row
            if remembered and remembered["owner"]() is owner and remembered["uuid"] == entry.uuid:
                if fallback_row is None:
                    fallback_row = row
                if remembered["digest"] == recent.digest(sequence):
                    remembered_row = row
            count += 1
        choice = selected_row or ((remembered_row or fallback_row) if remembered and recent.current() is remembered else None)
        if choice:
            rows.select_row(choice)
        elif key[0]:
            rows.select_row(rows.get_row_at_index(0))
        status.set_label(_tr("No matching entries. Try searching all unlocked databases.") if not key[1] else _tr("No matching entries."))
        status.set_visible(not count)
        if state["activate"] == state["serial"]:
            state["activate"] = None
            continue_selected()
    def stop_timer():
        if state["timer"]:
            GLib.source_remove(state["timer"])
            state["timer"] = 0
    def request():
        state["timer"] = 0
        if not current() or not flow.valid() or state["pending"]:
            return GLib.SOURCE_REMOVE
        key, serial = query_key(), state["serial"]
        options = dict(session.application.startup.autotype)
        def collect():
            result = []
            for context in contexts:
                reference, _epoch, _identity, generation, snapshot_ref = context
                owner = reference()
                if owner is None or not owner_current(owner):
                    continue
                snapshot = snapshot_ref()
                with owner.vault.operation(generation):
                    values = owner.vault.autotype_search(key[0], target["title"], all_entries=key[1],
                        match_title=options["match_title"], match_url=options["match_url"], hide_expired=options["hide_expired"])
                if not owner_current(owner):
                    continue
                entries = {item.uuid: item for item in snapshot.entries if not item.recycled and item.addressable}
                result.extend((owner, entries[item["entry"]], item["sequence"], item) for item in values if item["entry"] in entries)
            if not flow.valid():
                result.clear()
                return result
            column = ("group", "title", "username", "sequence")[key[2]]
            with session.vault.operation(sort_generation):
                indices = session.vault.autotype_sort([item[3][column] for item in result], key[3])
            return [result[index] for index in indices]
        def completed(choices):
            state["pending"] = False
            try:
                if not current() or not flow.valid():
                    return
                if serial != state["serial"] or key != query_key():
                    stop_timer()
                    request()
                    return
                display(choices, key)
            finally:
                choices.clear()
        def failed(_message):
            state["pending"] = False
            if not current() or not flow.valid():
                return
            if serial != state["serial"] or key != query_key():
                stop_timer()
                request()
                return
            state["activate"] = None
            status.set_label(_tr("Could not search entries. Edit the query or change the search scope to retry."))
            status.set_visible(True)
        state["pending"] = True
        if not session.jobs.run(collect, completed, failed, interactive=False):
            state["pending"] = False
            state["timer"] = GLib.timeout_add(200, request)
        return GLib.SOURCE_REMOVE
    def changed(*_, selection=None):
        state["serial"] += 1
        state["rendered"] = state["activate"] = None
        stop_timer()
        clear_rows()
        if not current() or not flow.valid():
            return
        state["selection"] = selection
        status.set_label(_tr("Searching…"))
        status.set_visible(True)
        state["timer"] = GLib.timeout_add(150 if scope.get_active() else 1, request)
    search.connect("notify::text", changed)
    scope.connect("toggled", changed)
    updating_sort = False
    def sorting_changed(*_):
        nonlocal updating_sort
        if updating_sort:
            return
        old = config.autotype["sort_column"], config.autotype["sort_order"]
        selected_sort = sort_column.get_selected(), sort_order.get_selected()
        if not current() or not flow.valid() or state["copying"] or selected_sort == old:
            return
        state["activate"] = None
        try:
            config.save(config.remember, config.login, config.vault,
                        autotype=dict(config.autotype, sort_column=selected_sort[0], sort_order=selected_sort[1]))
            sort_button.set_icon_name("view-sort-descending-symbolic" if selected_sort[1] else "view-sort-ascending-symbolic")
            row = rows.get_selected_row()
            changed(selection=row.choice if row else state["selection"])
        except (OSError, ValueError, VaultError) as exc:
            updating_sort = True
            sort_column.set_selected(old[0])
            sort_order.set_selected(old[1])
            updating_sort = False
            session.error(str(exc))
    sort_button.set_icon_name("view-sort-descending-symbolic" if config.autotype["sort_order"] else "view-sort-ascending-symbolic")
    sort_column.connect("notify::selected", sorting_changed)
    sort_order.connect("notify::selected", sorting_changed)
    def entered(*_):
        if ready():
            continue_selected()
        elif current() and flow.valid():
            state["activate"] = state["serial"]
            stop_timer()
            request()
    search.connect("activate", entered)
    def closed(*_):
        state["serial"] += 1
        state["rendered"] = state["activate"] = None
        stop_timer()
        clear_rows()
        matches.clear()
        contexts.clear()
    dialog.connect("closed", closed)
    if flow.present(session, dialog):
        changed()
        search.grab_focus()


def review(session, target, data, choice=None, *, flow):
    if not flow.valid():
        data.clear()
        flow.cancel()
        return
    dialog, header, box = _dialog(_tr("Confirm Auto-Type"), height=460 if not data["pick"] else 600)
    current = _guarded_lifetime(session, dialog, data.clear)
    destination = Adw.PreferencesGroup(title=_tr("Destination"))
    destination.add(Adw.ActionRow(title=target["title"], use_markup=False, title_lines=3))
    destination.add(Adw.ActionRow(title=_tr("Sequence"), subtitle=data["sequence"], use_markup=False, subtitle_lines=4))
    box.append(destination)
    pick_rows = []
    for item in data["pick"]:
        group = Adw.PreferencesGroup(title=_trf('Pick Characters — {arg0}', arg0=item['attribute']),
            description=_trf('Enter positions from 1 to {arg0}, separated by spaces. Example: 2 4 6.', arg0=item['length']))
        positions = Adw.EntryRow(title=_tr("Character Positions"))
        tab = Adw.SwitchRow(title=_tr("Press Tab Between Characters"))
        group.add(positions)
        group.add(tab)
        box.append(group)
        pick_rows.append((positions, tab, item["length"]))
    box.append(Gtk.Label(label=_tr("The selected entry will be typed into this window. Switching windows stops auto-type.")
        + " " + (_tr("GNOME will ask for keyboard access.") if target["backend"] == "portal" else _tr("Release modifier keys before continuing.")),
        wrap=True, xalign=0))
    error = Gtk.Label(wrap=True, xalign=0, css_classes=["error"], visible=False)
    box.append(error)
    def type_now(*_):
        if not current() or not flow.valid() or session.busy:
            return
        picks = []
        for row, tab, length in pick_rows:
            values = re.split(r"[\s,;]+", row.get_text().strip())
            if not values or len(values) > 1024 or any(not re.fullmatch(r"[0-9]{1,6}", value)
                or not 1 <= int(value) <= length for value in values):
                error.set_label(_tr("Enter valid character positions for each PICKCHARS request."))
                error.set_visible(True)
                return
            picks.append(dict(positions=[int(value) for value in values], tab=tab.get_active()))
        request = dict(data)
        flow.release(dialog)
        dialog.close()
        _execute(session, target, request, picks, choice, flow)
    _save(header, type_now, _trc("auto-type action", "Type"))
    flow.present(session, dialog)


def _execute(session, target, data, picks, choice, flow):
    epoch, token = session.epoch, data["token"]
    sequence_digest = session.application.autotype_recent.digest(data["sequence"]) if choice else None
    data.clear()
    flow.typing = True
    def execute():
        if not flow.valid():
            raise VaultError("Auto-Type was cancelled.")
        if target["backend"] == "portal":
            return autotype.execute_portal(session, target, token, picks, epoch, flow.valid)
        return session.vault.autotype_finish(token, picks, approved=True)
    def done(_result):
        valid = flow.valid()
        flow.typing = False
        flow.cancel()
        if valid and session.vault.unlocked:
            if choice:
                session.application.autotype_recent.remember(session, choice[0], sequence_digest, choice[1]())
            session.toast(_tr("Auto-type completed"))
        else:
            session.application.autotype_recent.clear(session)
    def failed(message):
        flow.typing = False
        flow.cancel()
        session.application.autotype_recent.clear(session)
        session.error(message)
    if not flow.valid():
        flow.cancel()
        return
    if not session.run_job(execute, done, failed):
        flow.cancel()


def open_shortcut_preferences(session, control):
    if session.jobs.closed:
        return
    control.set_sensitive(False)
    def finished(connection, result):
        problem = False
        try:
            connection.call_finish(result)
        except GLib.Error:
            problem = True
        if session.jobs.closed or control.get_root() is None:
            return
        control.set_sensitive(True)
        if problem:
            session.error(_tr("Could not open Keyslot companion preferences. Close other extension preferences and check that the updated companion is installed."))
    try:
        session.application.connection.call("org.gnome.Shell.Extensions", "/org/gnome/Shell/Extensions",
            "org.gnome.Shell.Extensions", "OpenExtensionPrefs",
            GLib.Variant("(ssa{sv})", ("keyslot@neg-zero", "", {})), GLib.VariantType.new("()"),
            Gio.DBusCallFlags.NONE, 5000, None, finished)
    except GLib.Error:
        control.set_sensitive(True)
        session.error(_tr("Could not reach GNOME extension preferences. Check that the Keyslot companion is installed."))


def add_preferences(session, page):
    config = session.application.startup
    group = Adw.PreferencesGroup(title=_tr("Auto-Type"),
        description=_tr("The GNOME companion defaults to Ctrl+Alt+K. Wayland asks the desktop for keyboard permission."))
    shortcut = Adw.ActionRow(title=_tr("Desktop Auto-Type Shortcuts…"),
        subtitle=_tr("Configure the GNOME companion’s shortcuts"))
    shortcut.add_suffix(Gtk.Image(icon_name="go-next-symbolic", valign=Gtk.Align.CENTER))
    shortcut.set_activatable(True)
    shortcut.connect("activated", lambda row: open_shortcut_preferences(session, row))
    group.add(shortcut)
    values = config.autotype
    widgets = {}
    for key, title in (("match_title", _mark("Match Entry Titles")), ("match_url", _mark("Match Websites")),
                       ("hide_expired", _mark("Hide Expired Entries")), ("relock", _mark("Relock Vaults Opened for Auto-Type")),
                       ("always_ask", _mark("Always Show the Entry Selector")),
                       ("skip_main_confirmation", _mark("Skip Confirmation for the Selected Entry"))):
        widgets[key] = Adw.SwitchRow(title=_tr(title), active=values[key])
    widgets["relock"].set_subtitle(_tr("Applies only to vaults unlocked for an Auto-Type request"))
    widgets["always_ask"].set_subtitle(_tr("When off, a single matching entry can be typed automatically"))
    widgets["skip_main_confirmation"].set_subtitle(_tr("Applies to Type Entry from the vault window"))
    widgets["skip_main_confirmation"].set_sensitive(values["always_ask"])
    widgets["delay"] = _spin(_tr("Delay Between Keys (Milliseconds)"), values["delay"], 0, 500)
    widgets["start_delay"] = _spin(_tr("Delay Before Typing (Milliseconds)"), values["start_delay"], 100, 10000)
    widgets["retype_seconds"] = _spin(_tr("Remember Last Typed Entry (Seconds)"), values["retype_seconds"], 0, 60)
    widgets["retype_seconds"].set_subtitle(_tr("Preselect the previous choice and retain an idle keyboard connection; 0 disables both"))
    updating = False
    def changed(*_):
        nonlocal updating
        if updating:
            return
        try:
            options = dict(config.autotype, **{key: row.get_active() if isinstance(row, Adw.SwitchRow) else int(row.get_value())
                                               for key, row in widgets.items()})
            config.save(config.remember, config.login, config.vault, autotype=options)
            session.application.autotype_recent.clear()
            session.application.portal_connections.invalidate()
            widgets["skip_main_confirmation"].set_sensitive(config.autotype["always_ask"])
        except (OSError, ValueError, VaultError) as exc:
            updating = True
            for key, row in widgets.items():
                if isinstance(row, Adw.SwitchRow):
                    row.set_active(config.autotype[key])
                else:
                    row.set_value(config.autotype[key])
            updating = False
            widgets["skip_main_confirmation"].set_sensitive(config.autotype["always_ask"])
            session.error(str(exc))
    for row in widgets.values():
        row.connect("notify::active" if isinstance(row, Adw.SwitchRow) else "notify::value", changed)
        group.add(row)
    page.add(group)
    permission_group = Adw.PreferencesGroup(title=_tr("Wayland Keyboard Permission"),
        description=_tr("Your desktop controls prompts when a connection opens. Each Auto-Type invocation still checks its destination."))
    policy = Adw.ComboRow(title=_tr("Remember Access"), model=Gtk.StringList.new(
        [_tr("Do Not Remember"), _tr("Until Keyslot Quits"), _tr("Until I Forget")]), selected=config.autotype["portal_mode"])
    keep_connection = Adw.SwitchRow(title=_tr("Keep Keyboard Connection Open"),
        subtitle=_tr("Reuse the desktop connection between invocations; locking a vault closes it"),
        active=config.autotype["portal_connection"])
    use_clipboard = Adw.SwitchRow(title=_tr("Use Desktop Portal for Clipboard"),
        subtitle=_tr("Allow Copy through the Wayland keyboard connection"),
        active=config.autotype["portal_clipboard"])
    forget = Adw.ActionRow(title=_tr("Forget Remembered Access"), activatable=True,
        subtitle=_tr("Clear remembered access; the desktop controls future prompts"))
    forget.add_suffix(Gtk.Image(icon_name="edit-clear-symbolic", valign=Gtk.Align.CENTER))
    permission_group.add(policy)
    permission_group.add(keep_connection)
    permission_group.add(use_clipboard)
    permission_group.add(forget)
    page.add(permission_group)
    permission_state = {"updating": False, "busy": False}
    def restore_permission():
        permission_state["updating"] = True
        policy.set_selected(config.autotype["portal_mode"])
        keep_connection.set_active(config.autotype["portal_connection"])
        use_clipboard.set_active(config.autotype["portal_clipboard"])
        permission_state["updating"] = False
        permission_state["busy"] = False
        permission_group.set_sensitive(True)
    def permission_changed(*_, clear_only=False):
        if permission_state["updating"] or permission_state["busy"]:
            return
        selected_mode = policy.get_selected()
        selected_connection = keep_connection.get_active()
        selected_clipboard = use_clipboard.get_active()
        change_permission = clear_only or selected_mode != config.autotype["portal_mode"]
        if (not change_permission and selected_connection == config.autotype["portal_connection"]
                and selected_clipboard == config.autotype["portal_clipboard"]):
            return
        if session.busy or session.jobs.closed:
            restore_permission()
            session.toast(_tr("Wait for the current operation to finish"))
            return
        permissions = session.application.portal_permissions
        if change_permission:
            permissions.invalidate()
        else:
            session.application.portal_connections.invalidate()
        permission_state["busy"] = True
        permission_group.set_sensitive(False)
        def apply_permission():
            if change_permission:
                permissions.forget(config)
            if not clear_only:
                with config.mutex:
                    if session.application.startup is not config:
                        raise VaultError("The configuration changed. Open Preferences again.")
                    config.save(config.remember, config.login, config.vault,
                                autotype=dict(config.autotype, portal_mode=selected_mode,
                                              portal_connection=selected_connection, portal_clipboard=selected_clipboard))
            session.application.portal_connections.invalidate()
        def saved(_result):
            restore_permission()
            if permission_group.get_root():
                session.toast(_tr("Remembered keyboard access cleared") if clear_only else _tr("Keyboard permission preference saved"))
        def failed(message):
            restore_permission()
            if permission_group.get_root():
                session.error(message)
        if not session.run_job(apply_permission, saved, failed):
            restore_permission()
    policy.connect("notify::selected", permission_changed)
    keep_connection.connect("notify::active", permission_changed)
    use_clipboard.connect("notify::active", permission_changed)
    forget.connect("activated", lambda *_: permission_changed(clear_only=True))
