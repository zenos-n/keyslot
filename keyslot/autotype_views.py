"""Auto-type settings, destination review and character picking."""
import os
import re
import weakref
from gi.repository import Gio, GLib
from .database_views import Adw, Gtk, _dialog, _save, _spin
from .passkey_views import _lifetime
from .backend import VaultError
from . import autotype
from .autotype_flow import Flow
from .autotype_fields import TYPES, COPY_FIELDS, SELECTOR_KEYS, FieldInfo


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
    dialog, header, box = _dialog("Auto-Type Settings", height=620)
    current = _lifetime(session, dialog)
    fields = Adw.PreferencesGroup(description="Leave the sequence empty to inherit the group’s sequence.")
    if entry:
        enabled = Adw.SwitchRow(title="Enable Auto-Type", active=data["enabled"])
    else:
        enabled = Adw.ComboRow(title="Auto-Type", model=Gtk.StringList.new(["Inherit", "Enabled", "Disabled"]))
        enabled.set_selected(data["enabled"])
    fields.add(enabled)
    sequence = Adw.EntryRow(title="Default Sequence", text=data["sequence"])
    fields.add(sequence)
    effective = Adw.ActionRow(title="Inherited Sequence", subtitle=data["effective_sequence"], use_markup=False,
                             subtitle_lines=3)
    fields.add(effective)
    box.append(fields)
    associations = []
    if entry:
        if not data["group_enabled"]:
            box.append(Gtk.Label(label="Auto-type is disabled by the parent group.", wrap=True, xalign=0))
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(section)
        def add_association(window="", custom=""):
            group_box = Adw.PreferencesGroup(title="Window Association")
            pattern = Adw.EntryRow(title="Window Pattern", text=window)
            custom_sequence = Adw.EntryRow(title="Sequence (Optional)", text=custom)
            group_box.add(pattern)
            group_box.add(custom_sequence)
            item = (group_box, pattern, custom_sequence)
            remove = Gtk.Button(icon_name="edit-delete-symbolic", tooltip_text="Remove Window Association", valign=Gtk.Align.CENTER)
            remove.connect("clicked", lambda *_: (associations.remove(item), section.remove(group_box)) if current() else None)
            pattern.add_suffix(remove)
            section.append(group_box)
            associations.append(item)
        for item in data["associations"]:
            add_association(item["window"], item["sequence"])
        add = Gtk.Button(label="Add Window Association", halign=Gtk.Align.START)
        add.connect("clicked", lambda *_: add_association() if current() else None)
        box.append(add)
    box.append(Gtk.Label(label="Use * in window patterns, or //regular expression//. Sequences support {USERNAME}, "
        "{PASSWORD}, {TAB}, {ENTER}, {TOTP}, {PICKCHARS}, {S:Custom Field}, delays and key modifiers.",
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
                session.toast("Auto-type settings saved")
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
        session.toast("Auto-Type is already in progress")
        return
    if field is not None and (entry is None or field not in TYPES):
        session.error("Choose an entry and a supported Auto-Type field.")
        return
    if flow is None:
        if global_shortcut and any(item.host_window.is_active() for item in session.application.sessions):
            return
        previous = session.application.autotype_flow
        if previous:
            if previous.valid():
                session.toast("Auto-Type is already in progress")
                return
            previous.cancel(lock=True)
        if session.dialogs or session.file_requests:
            session.toast("Close the current dialog before using Auto-Type")
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
        dialog, header, box = _dialog("Auto-Type Destination", height=420)
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
            box.append(Adw.StatusPage(title="No Destination Windows", description="Open the application you want to type into."))
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
    dialog, header, box = _dialog("Auto-Type", height=520)
    current = _guarded_lifetime(session, dialog)
    state = {"rendered": None, "pending": False, "serial": 0, "timer": 0, "activate": None, "copying": False}
    destination = Adw.PreferencesGroup(title="Destination")
    destination.add(Adw.ActionRow(title=target["title"], use_markup=False, title_lines=3))
    box.append(destination)
    search = Gtk.SearchEntry(placeholder_text="Search entries")
    box.append(search)
    scope = Gtk.CheckButton(label="Search All Unlocked Databases", active=not matches, sensitive=bool(matches))
    box.append(scope)
    box.append(Gtk.Label(label="All databases: use KeePassXC search syntax, for example tag:work or title:mail. "
        "Window matches: filter group, title or username with wildcards.", wrap=True, xalign=0, css_classes=["dim-label"]))
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, activate_on_single_click=False,
                      css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    status = Gtk.Label(label="No matching entries. Search to choose another entry.", wrap=True)
    box.append(status)
    box.append(Gtk.Label(label="Select an entry, then type it or copy a field. Double-click to type its sequence.",
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
        return search.get_text(), scope.get_active()
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
        for control in (rows, search, scope):
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
            state["copying"] = False
            rows.set_sensitive(True)
            search.set_sensitive(True)
            scope.set_sensitive(bool(matches))
            proceed.set_sensitive(rows.get_selected_row() is not None)
            update_fields()
            if session.application.clipboards.copy(owner, value):
                seconds = session.application.startup.clipboard_seconds
                session.toast(f"Copied · clipboard clears in {seconds} seconds" if seconds else "Copied")
                session.windows.copied()
            else:
                session.toast("Could not copy to the clipboard")
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
        typing_menu.append("Type " + title, "autotype-fields.type-" + name)
    for name in COPY_FIELDS:
        action = Gio.SimpleAction.new("copy-" + name, None)
        action.connect("activate", lambda *_args, name=name: field_action(name, True))
        actions.add_action(action)
        field_actions["copy-" + name] = action
        copy_menu.append("Copy " + TYPES[name][0], "autotype-fields.copy-" + name)
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
    proceed = Adw.SplitButton(label="Type", menu_model=menu, valign=Gtk.Align.CENTER,
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
        while rows.get_first_child():
            rows.remove(rows.get_first_child())
        info.clear()
        proceed.set_sensitive(False)
    def display(choices, key):
        if not current() or not flow.valid() or key != query_key():
            return
        clear_rows()
        state["rendered"] = key
        remembered_row = fallback_row = None
        recent = session.application.autotype_recent
        remembered = recent.current()
        count = 0
        for owner, entry, sequence in choices:
            if not owner_current(owner):
                continue
            row = Adw.ActionRow(title=entry.title or "Untitled Entry", subtitle=" · ".join(filter(None,
                (entry.username, owner.vault.snapshot.name, entry.group_path, sequence))), use_markup=False, title_lines=2,
                subtitle_lines=2, activatable=True)
            row.connect("activated", lambda _row, owner=owner, entry=entry, sequence=sequence: prepare(owner, entry, sequence))
            row.choice = (owner, entry, sequence)
            rows.append(row)
            if remembered and remembered["owner"]() is owner and remembered["uuid"] == entry.uuid:
                if fallback_row is None:
                    fallback_row = row
                if remembered["digest"] == recent.digest(sequence):
                    remembered_row = row
            count += 1
        choice = (remembered_row or fallback_row) if remembered and recent.current() is remembered else None
        if choice:
            rows.select_row(choice)
        elif key[0]:
            rows.select_row(rows.get_row_at_index(0))
        status.set_label("No matching entries. Try searching all unlocked databases." if not key[1] else "No matching entries.")
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
                result.extend((owner, entries[item["entry"]], item["sequence"]) for item in values if item["entry"] in entries)
            return result
        def completed(choices):
            state["pending"] = False
            if not current() or not flow.valid():
                return
            if serial != state["serial"] or key != query_key():
                stop_timer()
                request()
                return
            display(choices, key)
        def failed(_message):
            state["pending"] = False
            if not current() or not flow.valid():
                return
            if serial != state["serial"] or key != query_key():
                stop_timer()
                request()
                return
            state["activate"] = None
            status.set_label("Could not search entries. Edit the query or change the search scope to retry.")
            status.set_visible(True)
        state["pending"] = True
        if not session.jobs.run(collect, completed, failed, interactive=False):
            state["pending"] = False
            state["timer"] = GLib.timeout_add(200, request)
        return GLib.SOURCE_REMOVE
    def changed(*_):
        state["serial"] += 1
        state["rendered"] = state["activate"] = None
        stop_timer()
        clear_rows()
        if not current() or not flow.valid():
            return
        status.set_label("Searching…")
        status.set_visible(True)
        state["timer"] = GLib.timeout_add(150 if scope.get_active() else 1, request)
    search.connect("notify::text", changed)
    scope.connect("toggled", changed)
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
        if matches:
            display(matches, query_key())
        else:
            changed()
        search.grab_focus()


def review(session, target, data, choice=None, *, flow):
    if not flow.valid():
        data.clear()
        flow.cancel()
        return
    dialog, header, box = _dialog("Confirm Auto-Type", height=460 if not data["pick"] else 600)
    current = _guarded_lifetime(session, dialog, data.clear)
    destination = Adw.PreferencesGroup(title="Destination")
    destination.add(Adw.ActionRow(title=target["title"], use_markup=False, title_lines=3))
    destination.add(Adw.ActionRow(title="Sequence", subtitle=data["sequence"], use_markup=False, subtitle_lines=4))
    box.append(destination)
    pick_rows = []
    for item in data["pick"]:
        group = Adw.PreferencesGroup(title=f'Pick Characters — {item["attribute"]}',
            description=f'Enter positions from 1 to {item["length"]}, separated by spaces. Example: 2 4 6.')
        positions = Adw.EntryRow(title="Character Positions")
        tab = Adw.SwitchRow(title="Press Tab Between Characters")
        group.add(positions)
        group.add(tab)
        box.append(group)
        pick_rows.append((positions, tab, item["length"]))
    box.append(Gtk.Label(label="The selected entry will be typed into this window. Switching windows stops auto-type. "
        + ("GNOME will ask for keyboard access." if target["backend"] == "portal" else "Release modifier keys before continuing."),
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
                error.set_label("Enter valid character positions for each PICKCHARS request.")
                error.set_visible(True)
                return
            picks.append(dict(positions=[int(value) for value in values], tab=tab.get_active()))
        request = dict(data)
        flow.release(dialog)
        dialog.close()
        _execute(session, target, request, picks, choice, flow)
    _save(header, type_now, "Type")
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
            session.toast("Auto-type completed")
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


def add_preferences(session, page):
    config = session.application.startup
    group = Adw.PreferencesGroup(title="Auto-Type",
        description="GNOME companion shortcut: Ctrl+Alt+K. Wayland uses a temporary keyboard portal permission.")
    values = config.autotype
    widgets = {}
    for key, title in (("match_title", "Match Entry Titles"), ("match_url", "Match Websites"),
                       ("hide_expired", "Hide Expired Entries"), ("relock", "Relock Vaults Opened for Auto-Type"),
                       ("always_ask", "Always Show the Entry Selector"),
                       ("skip_main_confirmation", "Skip Confirmation for the Selected Entry")):
        widgets[key] = Adw.SwitchRow(title=title, active=values[key])
    widgets["relock"].set_subtitle("Applies only to vaults unlocked for an Auto-Type request")
    widgets["always_ask"].set_subtitle("When off, a single matching entry can be typed automatically")
    widgets["skip_main_confirmation"].set_subtitle("Applies to Type Entry from the vault window")
    widgets["skip_main_confirmation"].set_sensitive(values["always_ask"])
    widgets["delay"] = _spin("Delay Between Keys (Milliseconds)", values["delay"], 0, 500)
    widgets["start_delay"] = _spin("Delay Before Typing (Milliseconds)", values["start_delay"], 100, 10000)
    widgets["retype_seconds"] = _spin("Remember Last Typed Entry (Seconds)", values["retype_seconds"], 0, 60)
    widgets["retype_seconds"].set_subtitle("Preselect the previous choice; 0 disables remembering")
    updating = False
    def changed(*_):
        nonlocal updating
        if updating:
            return
        try:
            options = {key: row.get_active() if isinstance(row, Adw.SwitchRow) else int(row.get_value())
                       for key, row in widgets.items()}
            config.save(config.remember, config.login, config.vault, autotype=options)
            session.application.autotype_recent.clear()
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
