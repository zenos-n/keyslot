"""Entry/group identity, timestamps and reviewed native plugin-data removal."""
from .i18n import mark as _mark, tr as _tr, trf as _trf
from gi.repository import Adw, GLib, Gtk
from .database_views import _dialog
from .passkey_views import _lifetime


def _date(value):
    stamp = GLib.DateTime.new_from_iso8601(value, None) if value else None
    return stamp.to_local().format("%x %X") if stamp else value or "Not recorded"


def _button(icon, title, callback):
    button = Gtk.Button(icon_name=icon, tooltip_text=title, valign=Gtk.Align.CENTER)
    button.connect("clicked", lambda *_: callback())
    return button


def show(session, *, entry=None, group=None, data=None):
    if session.busy or not session.vault.unlocked:
        return
    target = {"entry": entry} if entry is not None else {"group": group}
    if data is None:
        session.run_job(lambda: session.vault.object_properties(target),
                        lambda value: show(session, entry=entry, group=group, data=value))
        return
    dialog, header, box = _dialog(_tr("Entry Properties") if entry is not None else _tr("Group Properties"), width=580, height=700)
    alive = _lifetime(session, dialog)
    state = {"data": data, "revision": data["revision"], "serial": 0, "offset": 0, "loading": False, "closed": False}
    current = lambda: alive() and session.active and not state["closed"]
    selected = set()
    identity = Adw.PreferencesGroup(title=_tr("Identity"))
    identity_rows = {}
    for title, key in ((_mark("Name"), "name"), ("UUID", "uuid"), (_mark("UUID (Hex)"), "uuid_hex"), (_mark("Parent Group"), "parent"), (_mark("Previous Parent"), "previous_parent")):
        value = data[key]
        row = Adw.ActionRow(title=_tr(title), subtitle=value or _tr("None"), use_markup=False, subtitle_selectable=True)
        if key in {"uuid", "uuid_hex", "parent", "previous_parent"}:
            row.add_suffix(_button("edit-copy-symbolic", _trf("Copy {field}", field=title),
                lambda key=key: session.copy(state["data"][key]) if current() and state["data"] else None))
        identity.add(row)
        identity_rows[key] = row
    box.append(identity)
    times = Adw.PreferencesGroup(title=_tr("Activity"))
    time_rows = {}
    for title, key in ((_mark("Created"), "created"), (_mark("Modified"), "modified"), (_mark("Last Accessed"), "accessed"), (_mark("Location Changed"), "location_changed")):
        row = Adw.ActionRow(title=_tr(title), subtitle=_date(data[key]), subtitle_selectable=True)
        times.add(row); time_rows[key] = row
    other_rows = {}
    for title, key in ((_mark("Expiry"), "expiry"), (_mark("Usage Count"), "usage_count"), (_mark("In Recycle Bin"), "recycled")):
        row = Adw.ActionRow(title=_tr(title))
        times.add(row); other_rows[key] = row
    box.append(times)
    counts = Adw.PreferencesGroup(title=_tr("Contents"))
    count_rows = {}
    for title, key in ((_mark("History Versions"), "history"), (_mark("Entries"), "entries"), (_mark("Entries Including Subgroups"), "entries_recursive"),
                       (_mark("Subgroups"), "groups"), (_mark("All Descendant Groups"), "groups_recursive")):
        if key in data:
            row = Adw.ActionRow(title=_tr(title), subtitle=str(data[key]))
            counts.add(row); count_rows[key] = row
    box.append(counts)
    box.append(Gtk.Label(label=_tr("Plugin Data"), xalign=0, css_classes=["heading"]))
    box.append(Gtk.Label(label=_tr("Values may contain credentials or integration settings. Inspect them only when needed. "
                         "Removing data can disable plugins, clear remembered approvals, or change inherited access rules. "
                         "Automatic metadata may be recreated by KeePassXC."), xalign=0, wrap=True))
    search = Gtk.SearchEntry(placeholder_text=_tr("Search plugin-data names"))
    box.append(search)
    selection_bar = Gtk.Box(spacing=12, homogeneous=True)
    select_page, clear_selection = Gtk.Button(label=_tr("Select Page")), Gtk.Button(label=_tr("Clear Selection"))
    selection_bar.append(select_page); selection_bar.append(clear_selection); box.append(selection_bar)
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"], valign=Gtk.Align.START)
    box.append(rows)
    status = Gtk.Label(xalign=0, wrap=True, css_classes=["dim-label"])
    box.append(status)
    navigation = Gtk.Box(spacing=12, homogeneous=True)
    previous, following = Gtk.Button(label=_tr("Previous")), Gtk.Button(label=_tr("Next"))
    navigation.append(previous); navigation.append(following); box.append(navigation)
    remove = Gtk.Button(label=_tr("Remove Selected…"), valign=Gtk.Align.CENTER, sensitive=False, css_classes=["destructive-action"])
    box.append(remove)
    def selection(*_):
        remove.set_label(_trf('Remove Selected ({arg0})…', arg0=len(selected)) if selected else _tr("Remove Selected…"))
        remove.set_sensitive(bool(selected) and state["data"] is not None and not state["loading"])
        clear_selection.set_sensitive(bool(selected))
    def inspect(item):
        if current() and state["data"] and not state["loading"]:
            value_dialog(session, target, item, state["data"]["revision"])
    def copy(item):
        if current() and state["data"] and not state["loading"]:
            revision = state["data"]["revision"]
            session.run_job(lambda: session.vault.plugin_value(target, item["name"], revision),
                            lambda value: session.copy(value) if current() else None)
    def export(item):
        if current() and state["data"] and not state["loading"]:
            export_value(session, target, item["name"], state["data"]["revision"], current)
    def render(value):
        if state["revision"] != value["revision"]:
            selected.clear()
            session.toast(_tr("Vault changed; plugin-data selection cleared"))
        state["data"] = value
        state["revision"] = value["revision"]; state["loading"] = False
        for key, row in identity_rows.items():
            row.set_subtitle(value[key] or _tr("None"))
        for key, row in time_rows.items():
            row.set_subtitle(_date(value[key]))
        other_rows["expiry"].set_subtitle(_date(value["expiry"]) if value["expires"] else _tr("Never"))
        other_rows["usage_count"].set_subtitle(str(value["usage_count"]))
        other_rows["recycled"].set_subtitle(_tr("Yes") if value["recycled"] else _tr("No"))
        for key, row in count_rows.items():
            row.set_subtitle(str(value[key]))
        child = rows.get_first_child()
        while child:
            following_child = child.get_next_sibling(); rows.remove(child); child = following_child
        for item in value["plugin_data"]:
            caption = f'{item["characters"]} characters · {_date(item["modified"])}'
            if item["automatic"]:
                caption += " · Automatic"
            row = Adw.ActionRow(title=item["name"] or _tr("(Empty Name)"), subtitle=caption, use_markup=False, title_lines=2, subtitle_lines=2)
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER, active=item["name"] in selected)
            check.update_property([Gtk.AccessibleProperty.LABEL], ["Select " + (item["name"] or "Empty Name")])
            def toggle(check, name=item["name"]):
                if check.get_active() and len(selected) >= 256 and name not in selected:
                    check.set_active(False); session.toast(_tr("Select at most 256 items per removal")); return
                (selected.add if check.get_active() else selected.discard)(name)
                selection()
            check.connect("toggled", toggle); row.add_prefix(check); row.set_activatable_widget(check)
            row.selection_check = check
            for icon, title, callback in (("document-properties-symbolic", _mark("Inspect Plugin Value"), inspect),
                                          ("edit-copy-symbolic", _mark("Copy Plugin Value"), copy),
                                          ("document-save-symbolic", _mark("Export Plugin Value"), export)):
                row.add_suffix(_button(icon, _tr(title), lambda item=item, callback=callback: callback(item)))
            rows.append(row)
        total, start = value["total"], state["offset"]
        status.set_label((f'{start + 1}–{start + len(value["plugin_data"])} of {total}' if value["plugin_data"] else "No matching plugin data")
                         + (". Some oversized names cannot be shown." if value["omitted"] else ""))
        previous.set_sensitive(start > 0); following.set_sensitive(start + len(value["plugin_data"]) < total)
        select_page.set_sensitive(bool(value["plugin_data"]))
        selection()
    def load(*_, reset=False):
        if not current():
            return
        state["serial"] += 1; serial = state["serial"]
        if reset:
            state["offset"] = 0
        query, offset = search.get_text(), state["offset"]
        state["loading"] = True
        remove.set_sensitive(False); previous.set_sensitive(False); following.set_sensitive(False)
        select_page.set_sensitive(False)
        status.set_label(_tr("Loading properties…"))
        def received(value):
            if current() and serial == state["serial"]:
                render(value)
        def failed(message):
            if current() and serial == state["serial"]:
                state["data"] = None; state["loading"] = False
                status.set_label(message)
                selection()
        def start():
            if not current() or serial != state["serial"]:
                return False
            return not session.jobs.run(lambda: session.vault.object_properties(target, query, offset), received, failed, interactive=False)
        if start():
            GLib.timeout_add(100, start)
    def move(delta):
        state["offset"] += delta; load()
    previous.connect("clicked", lambda *_: move(-100))
    following.connect("clicked", lambda *_: move(100))
    def select_visible(*_):
        if not current() or state["loading"]:
            return
        row = rows.get_first_child()
        while row and len(selected) < 256:
            row.selection_check.set_active(True); row = row.get_next_sibling()
    def deselect(*_):
        selected.clear()
        row = rows.get_first_child()
        while row:
            row.selection_check.set_active(False); row = row.get_next_sibling()
        selection()
    select_page.connect("clicked", select_visible)
    clear_selection.connect("clicked", deselect)
    search.connect("search-changed", lambda *_: load(reset=True))
    header.pack_start(_button("view-refresh-symbolic", _tr("Refresh Properties"), lambda: load(reset=True)))
    def removal(*_):
        if not current() or not state["data"] or state["loading"] or not selected or session.busy:
            return
        names, revision = sorted(selected), state["data"]["revision"]
        def reviewed(plan):
            if current():
                confirm_removal(session, plan, lambda: (dialog.close(), session.window.show_vault(session.vault.snapshot),
                    show(session, entry=entry, group=group)))
            else:
                cancel_review(session, plan["token"])
        session.run_job(lambda: session.vault.review_plugin_removal(target, names, revision), reviewed)
    remove.connect("clicked", removal)
    def clear(*_):
        state["serial"] += 1; state["data"] = None; state["closed"] = True; selected.clear()
    dialog._clear_sensitive_fields = clear
    dialog.connect("closed", clear)
    render(data)
    session.present_dialog(dialog)


def cancel_review(session, token):
    if session.vault.unlocked and not session.jobs.closed:
        session.jobs.run(lambda: session.vault.cancel_plugin_removal(token), failed=lambda _message: None, interactive=False)


def confirm_removal(session, plan, done):
    dialog = Adw.AlertDialog(heading=_tr("Remove Plugin Data?"), body_use_markup=False,
        body=f'Remove {len(plan["names"])} selected items from “{plan["name"] or "Untitled"}”? '
             "This can disable plugins or change inherited access rules. "
             + ("The previous entry state is kept subject to this vault’s history limits." if plan["entry"] else "Groups do not have entry history; use your vault backup if you need to restore this data."))
    current = _lifetime(session, dialog)
    listing = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                           left_margin=12, right_margin=12, top_margin=12, bottom_margin=12)
    listing.get_buffer().set_text("\n".join(plan["names"]))
    dialog.set_extra_child(Gtk.ScrolledWindow(child=listing, min_content_height=80, max_content_height=160,
        propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN))
    dialog.add_response("cancel", _tr("Cancel")); dialog.add_response("remove", _tr("Remove"))
    dialog.set_default_response("cancel"); dialog.set_close_response("cancel")
    dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
    def response(_dialog, answer):
        if answer == "remove" and current() and not session.busy:
            session.run_job(lambda: session.vault.remove_plugin_data(plan["token"]), lambda _snapshot: done())
        else:
            cancel_review(session, plan["token"])
    dialog.connect("response", response)
    session.present_dialog(dialog)


def value_dialog(session, target, item, revision):
    dialog, _header, box = _dialog(_tr("Plugin Value"), width=560, height=500)
    alive = _lifetime(session, dialog)
    closed = [False]
    current = lambda: alive() and session.active and not closed[0]
    box.append(Gtk.Label(label=item["name"] or _tr("(Empty Name)"), xalign=0, wrap=True, css_classes=["heading"]))
    box.append(Gtk.Label(label=_tr("This value may contain credentials. It is shown only while this dialog is open."), wrap=True, xalign=0))
    value = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                         left_margin=12, right_margin=12, top_margin=12, bottom_margin=12, monospace=True)
    value.get_buffer().set_enable_undo(False)
    box.append(Gtk.ScrolledWindow(child=value, min_content_height=180, max_content_height=350,
        propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER, css_classes=["card"], overflow=Gtk.Overflow.HIDDEN))
    status = Gtk.Label(label=_tr("Loading value…"), xalign=0, wrap=True); box.append(status)
    def received(text):
        if current():
            value.get_buffer().set_text(text); status.set_label("")
    def failed(message):
        if current():
            status.set_label(message)
    def clear(*_):
        closed[0] = True; value.get_buffer().set_text("")
    dialog._clear_sensitive_fields = clear
    dialog.connect("closed", clear)
    if not session.present_dialog(dialog):
        return
    session.run_job(lambda: session.vault.plugin_value(target, item["name"], revision), received, failed)


def export_value(session, target, name, revision, current):
    alert = Adw.AlertDialog(heading=_tr("Export Unencrypted Plugin Data?"),
        body=_tr("The file may contain credentials or other private information. Anyone who can read it can see the complete value."))
    alert.add_response("cancel", _tr("Cancel")); alert.add_response("export", _tr("Choose File…"))
    alert.set_default_response("cancel"); alert.set_close_response("cancel")
    alert.set_response_appearance("export", Adw.ResponseAppearance.DESTRUCTIVE)
    def response(_dialog, answer):
        if answer == "export" and current():
            session.choose_file(lambda path: session.run_job(lambda: session.vault.plugin_value(target, name, revision, path),
                lambda _value: session.toast(_tr("Plugin data exported"))) if current() else None, save=True, name="Plugin Data.txt")
    alert.connect("response", response)
    session.present_dialog(alert)
