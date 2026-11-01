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


def choose(session, entry=None, target=None, windows=None, *, flow=None, allow_automatic=True, global_shortcut=False):
    if not session.vault.unlocked or session.busy:
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
        flow = Flow(session, allow_automatic)
        session.application.autotype_flow = flow
    if not flow.valid():
        flow.cancel()
        return
    if target is None:
        if os.environ.get("XDG_SESSION_TYPE") == "wayland":
            flow.run(session, autotype.capture_target, lambda value: choose(session, entry, value, flow=flow))
            return
        if windows is None:
            flow.run(session, session.vault.autotype_targets, lambda value: choose(session, entry, windows=value, flow=flow))
            return
        dialog, header, box = _dialog("Auto-Type Destination", height=420)
        current = _guarded_lifetime(session, dialog)
        def chosen(window):
            if current() and flow.valid():
                flow.release(dialog)
                dialog.close()
                choose(session, entry, dict(backend="x11", **window), flow=flow)
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
        _prepare(session, entry, target, "", flow, confirm=confirm)
        return
    candidates = list(session.application.sessions)
    captured = [(owner, owner.epoch, owner.vault.identity, owner.vault.generation, owner.vault.snapshot)
                for owner in candidates if owner.vault.unlocked and not owner.jobs.closed]
    recent = session.application.autotype_recent
    previous = recent.current()
    previous_owner = previous["owner"]() if previous else None
    previous_uuid = previous["uuid"] if previous else None
    def collect():
        records = []
        for owner, epoch, identity, generation, snapshot in captured:
            if owner.epoch != epoch or owner.jobs.closed or not owner.vault.unlocked:
                continue
            with owner.vault.operation(generation):
                values = owner.vault.autotype_matches(target["title"], options["match_title"],
                                                      options["match_url"], options["hide_expired"])
                default_digest = None
                if owner is previous_owner:
                    remembered = next((item for item in snapshot.entries if item.uuid == previous_uuid and not item.recycled), None)
                    if remembered:
                        try:
                            settings = owner.vault.autotype_settings(remembered)
                            if settings["enabled"] and settings["group_enabled"]:
                                default_digest = recent.digest(settings["effective_sequence"])
                        except (VaultError, OSError, ValueError):
                            pass
            records.append((owner, epoch, identity, snapshot, values, default_digest))
        return records
    def matched(records):
        available, matches = [], []
        defaults = {}
        for owner, epoch, identity, snapshot, values, default_digest in records:
            if owner.epoch != epoch or owner.vault.identity is not identity or owner.vault.snapshot is not snapshot:
                continue
            entries = {item.uuid: item for item in snapshot.entries if not item.recycled}
            available.extend((owner, item, "") for item in entries.values())
            matches.extend((owner, entries[item["entry"]], item["sequence"]) for item in values if item["entry"] in entries)
            if default_digest is not None:
                defaults[owner, previous_uuid] = default_digest
        if len(matches) == 1 and target.get("title") and not options["always_ask"] and flow.allow_automatic:
            owner, candidate, sequence = matches[0]
            _prepare(owner, candidate, target, sequence, flow, confirm=False)
        else:
            _choose_match(session, target, matches, available, defaults, flow=flow)
    flow.run(session, collect, matched)


def _prepare(session, entry, target, sequence, flow, *, confirm):
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
        options["delay"], options["start_delay"]), prepared)


def _choose_match(session, target, matches, available, defaults=None, *, flow):
    dialog, header, box = _dialog("Auto-Type", height=520)
    current = _guarded_lifetime(session, dialog)
    state = {"query": None}
    destination = Adw.PreferencesGroup(title="Destination")
    destination.add(Adw.ActionRow(title=target["title"], use_markup=False, title_lines=3))
    box.append(destination)
    search = Gtk.SearchEntry(placeholder_text="Search entries")
    box.append(search)
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    status = Gtk.Label(label="No matching entries. Search to choose another entry.", wrap=True)
    box.append(status)
    box.append(Gtk.Label(label="Choose an entry to start Auto-Type in the selected window.",
                         wrap=True, xalign=0, css_classes=["dim-label"]))
    def prepare(owner, entry, sequence):
        if not current() or not flow.valid():
            return
        flow.release(dialog)
        dialog.close()
        _prepare(owner, entry, target, sequence, flow, confirm=False)
    def continue_selected(*_):
        row = rows.get_selected_row()
        if current() and row:
            row.emit("activated")
    proceed = _save(header, continue_selected, "Type")
    proceed.set_sensitive(False)
    rows.connect("row-selected", lambda _rows, row: proceed.set_sensitive(row is not None))
    def render(*_):
        if not current() or not flow.valid():
            return
        while rows.get_first_child():
            rows.remove(rows.get_first_child())
        query = search.get_text().casefold()
        state["query"] = query
        choices = matches if not query else [(owner, entry, "") for owner, entry, _ in available
            if query in " ".join((entry.title, entry.username, entry.group_path)).casefold()
            and (not session.application.startup.autotype["hide_expired"] or not entry.expired)]
        count = 0
        remembered_row = None
        for owner, entry, sequence in choices:
            if not owner.vault.unlocked or owner.jobs.closed:
                continue
            row = Adw.ActionRow(title=entry.title or "Untitled Entry", subtitle=" · ".join(filter(None,
                (entry.username, owner.vault.snapshot.name, entry.group_path, sequence))), use_markup=False, title_lines=2,
                subtitle_lines=2, activatable=True)
            row.connect("activated", lambda _row, owner=owner, entry=entry, sequence=sequence: prepare(owner, entry, sequence))
            rows.append(row)
            if session.application.autotype_recent.matches(owner, entry, sequence, (defaults or {}).get((owner, entry.uuid))):
                remembered_row = row
            count += 1
        if remembered_row:
            rows.select_row(remembered_row)
        elif query:
            rows.select_row(rows.get_row_at_index(0))
        status.set_visible(not count)
    search.connect("search-changed", render)
    def entered(*_):
        if state["query"] != search.get_text().casefold():
            render()
        continue_selected()
    search.connect("activate", entered)
    if flow.present(session, dialog):
        render()
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
        if session.application.startup.autotype["relock"]:
            session.lock()
        elif valid:
            if choice:
                session.application.autotype_recent.remember(session, choice[0], sequence_digest, choice[1]())
            session.toast("Auto-type completed")
        else:
            session.application.autotype_recent.clear(session)
    def failed(message):
        flow.typing = False
        flow.cancel()
        session.application.autotype_recent.clear(session)
        if session.application.startup.autotype["relock"]:
            session.lock()
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
                       ("hide_expired", "Hide Expired Entries"), ("relock", "Lock Vault After Auto-Type"),
                       ("always_ask", "Always Show the Entry Selector"),
                       ("skip_main_confirmation", "Skip Confirmation for the Selected Entry")):
        widgets[key] = Adw.SwitchRow(title=title, active=values[key])
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
