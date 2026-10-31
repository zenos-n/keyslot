"""Auto-type settings, destination review and character picking."""
import os
import re
from .database_views import Adw, Gtk, _dialog, _save, _spin
from .passkey_views import _lifetime
from .backend import VaultError
from . import autotype


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


def choose(session, entry=None, target=None, windows=None):
    if not session.vault.unlocked or session.busy:
        return
    if target is None:
        if os.environ.get("XDG_SESSION_TYPE") == "wayland":
            session.run_job(autotype.capture_target, lambda value: choose(session, entry, value))
            return
        if windows is None:
            session.run_job(session.vault.autotype_targets, lambda value: choose(session, entry, windows=value))
            return
        dialog, header, box = _dialog("Auto-Type Destination", height=420)
        current = _lifetime(session, dialog)
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
        box.append(rows)
        for window in windows:
            row = Adw.ActionRow(title=window["title"], use_markup=False, title_lines=2, activatable=True)
            row.connect("activated", lambda _row, window=window: (dialog.close(), choose(session, entry,
                dict(backend="x11", **window))) if current() else None)
            rows.append(row)
        if not windows:
            box.append(Adw.StatusPage(title="No Destination Windows", description="Open the application you want to type into."))
        session.application.select_session(session)
        session.present_dialog(dialog)
        return
    options = session.application.startup.autotype
    candidates = [session] if entry else list(session.application.sessions)
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
            records.append((owner, epoch, identity, snapshot, values))
        return records
    def matched(records):
        available, matches = [], []
        for owner, epoch, identity, snapshot, values in records:
            if owner.epoch != epoch or owner.vault.identity is not identity or owner.vault.snapshot is not snapshot:
                continue
            entries = {item.uuid: item for item in snapshot.entries if not item.recycled}
            available.extend((owner, item, "") for item in entries.values())
            matches.extend((owner, entries[item["entry"]], item["sequence"]) for item in values if item["entry"] in entries)
        _choose_match(session, entry, target, matches, available)
    session.run_job(collect, matched)


def _choose_match(session, selected, target, matches, available):
    if selected:
        matches = [(session, selected, "")]
    dialog, header, box = _dialog("Auto-Type", height=520)
    current = _lifetime(session, dialog)
    destination = Adw.PreferencesGroup(title="Destination")
    destination.add(Adw.ActionRow(title=target["title"], use_markup=False, title_lines=3))
    box.append(destination)
    search = Gtk.SearchEntry(placeholder_text="Search entries")
    box.append(search)
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    status = Gtk.Label(label="No matching entries. Search to choose another entry.", wrap=True)
    box.append(status)
    def prepare(owner, entry, sequence):
        if not current():
            return
        dialog.close()
        if owner.jobs.closed or not owner.vault.unlocked:
            session.error("This vault was locked. Choose an unlocked entry again.")
            return
        session.application.select_session(owner)
        options = session.application.startup.autotype
        owner.run_job(lambda: owner.vault.autotype_prepare(entry, target, sequence,
            options["delay"], options["start_delay"]), lambda value: review(owner, target, value))
    def render(*_):
        while rows.get_first_child():
            rows.remove(rows.get_first_child())
        query = search.get_text().casefold()
        choices = matches if not query else [(owner, entry, "") for owner, entry, _ in available
            if query in " ".join((entry.title, entry.username, entry.group_path)).casefold()
            and (not session.application.startup.autotype["hide_expired"] or not entry.expired)]
        count = 0
        for owner, entry, sequence in choices:
            if not owner.vault.unlocked or owner.jobs.closed:
                continue
            row = Adw.ActionRow(title=entry.title or "Untitled Entry", subtitle=" · ".join(filter(None,
                (entry.username, owner.vault.snapshot.name, entry.group_path, sequence))), use_markup=False, title_lines=2,
                subtitle_lines=2, activatable=True)
            row.connect("activated", lambda _row, owner=owner, entry=entry, sequence=sequence: prepare(owner, entry, sequence))
            rows.append(row)
            count += 1
        status.set_visible(not count)
    search.connect("search-changed", render)
    render()
    session.application.select_session(session)
    session.present_dialog(dialog)


def review(session, target, data):
    dialog, header, box = _dialog("Confirm Auto-Type", height=460 if not data["pick"] else 600)
    current = _lifetime(session, dialog)
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
    def type_now(*_):
        if not current() or session.busy:
            return
        picks = []
        for row, tab, length in pick_rows:
            values = re.split(r"[\s,;]+", row.get_text().strip())
            if not values or len(values) > 1024 or any(not re.fullmatch(r"[0-9]{1,6}", value)
                or not 1 <= int(value) <= length for value in values):
                session.error("Enter valid character positions for each PICKCHARS request.")
                return
            picks.append(dict(positions=[int(value) for value in values], tab=tab.get_active()))
        epoch = session.epoch
        dialog.close()
        def execute():
            if target["backend"] == "portal":
                return autotype.execute_portal(session, target, data["token"], picks, epoch)
            return session.vault.autotype_finish(data["token"], picks, approved=True)
        def done(_result):
            if session.application.startup.autotype["relock"]:
                session.lock()
            else:
                session.toast("Auto-type completed")
        def failed(message):
            if session.application.startup.autotype["relock"]:
                session.lock()
            session.error(message)
        session.run_job(execute, done, failed)
    _save(header, type_now, "Type")
    session.present_dialog(dialog)


def add_preferences(session, page):
    config = session.application.startup
    group = Adw.PreferencesGroup(title="Auto-Type",
        description="GNOME companion shortcut: Ctrl+Alt+K. Wayland uses a temporary keyboard portal permission.")
    values = config.autotype
    widgets = {}
    for key, title in (("match_title", "Match Entry Titles"), ("match_url", "Match Websites"),
                       ("hide_expired", "Hide Expired Entries"), ("relock", "Lock Vault After Auto-Type")):
        widgets[key] = Adw.SwitchRow(title=title, active=values[key])
    widgets["delay"] = _spin("Delay Between Keys (Milliseconds)", values["delay"], 0, 500)
    widgets["start_delay"] = _spin("Delay Before Typing (Milliseconds)", values["start_delay"], 100, 10000)
    def changed(*_):
        try:
            options = {key: row.get_active() if isinstance(row, Adw.SwitchRow) else int(row.get_value())
                       for key, row in widgets.items()}
            config.save(config.remember, config.login, config.vault, autotype=options)
        except (OSError, ValueError) as exc:
            session.error(str(exc))
    for row in widgets.values():
        row.connect("notify::active" if isinstance(row, Adw.SwitchRow) else "notify::value", changed)
        group.add(row)
    page.add(group)
