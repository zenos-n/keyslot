"""Reviewed entry duplication and selected-entry tag/expiry actions."""
from .i18n import mark as _mark, tr as _tr, trf as _trf
from datetime import datetime, timedelta, timezone

from .database_views import Adw, GLib, Gtk, _dialog, _save
from .passkey_views import _lifetime


def _release(session, token):
    if session.vault.unlocked and not session.jobs.closed:
        session.jobs.run(lambda: session.vault.cancel_entry_action(token), failed=lambda _message: None, interactive=False)


def choose(session, entries, action="tag", data=None):
    entries = list(entries)
    if not entries or session.busy or not session.vault.unlocked:
        return
    if data is None:
        if action == "tag":
            session.run_job(session.vault.entry_actions_info, lambda value: choose(session, entries, action, value))
            return
        data = {}
    dialog, header, box = _dialog(_tr("Duplicate Entry") if action == "duplicate" else _tr("Edit Tags") if action == "tag" else _tr("Set Expiry"),
                                  width=480, height=360)
    current = _lifetime(session, dialog)
    fields = Adw.PreferencesGroup(description=_tr("Create a copy in the same group, retaining attachments, icons and custom settings.")
        if action == "duplicate" else _trf('Apply to {arg0} selected entries. Only entries that need a change will be saved.', arg0=len(entries)))
    controls = {}
    if action == "duplicate":
        for key, title, default in (("rename", _mark("Append ‘ - Clone’ to the Title"), True),
                                    ("references", _mark("Reference the Original Username and Password"), False),
                                    ("history", _mark("Include Entry History"), True)):
            row = Adw.SwitchRow(title=_tr(title), active=default)
            fields.add(row)
            controls[key] = row
        if any(entry.totp or entry.passkey for entry in entries):
            fields.set_description(_tr("The copy keeps the same one-time password setup and passkeys, along with attachments, icons and custom settings."))
    elif action == "tag":
        operation = Adw.ComboRow(title=_tr("Action"), model=Gtk.StringList.new([_tr("Add Tag"), _tr("Remove Tag")]))
        tags = data["tags"]
        tag = Adw.ComboRow(title=_tr("Tag"), model=Gtk.StringList.new(tags + [_tr("New Tag…")]))
        custom = Adw.EntryRow(title=_tr("New Tag"), visible=not tags)
        tag.connect("notify::selected", lambda *_: custom.set_visible(tag.get_selected() == len(tags)))
        for row in (operation, tag, custom):
            fields.add(row)
    else:
        mode = Adw.ComboRow(title=_tr("Expiry"), model=Gtk.StringList.new([_tr("Expire Now"), _tr("Never Expires"), _tr("At a Specific Time")]))
        at = Adw.EntryRow(title=_tr("Expiry (ISO 8601)"), visible=False,
                          text=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z"))
        mode.connect("notify::selected", lambda *_: at.set_visible(mode.get_selected() == 2))
        fields.add(mode)
        fields.add(at)
    box.append(fields)
    def submit(*_):
        if not current() or session.busy:
            return
        values = {"action": action}
        if action == "duplicate":
            values.update({key: row.get_active() for key, row in controls.items()})
        elif action == "tag":
            index = tag.get_selected()
            values.update(tag=tags[index] if index < len(tags) else custom.get_text(), add=operation.get_selected() == 0)
        else:
            values.update(mode=["now", "never", "at"][mode.get_selected()])
            if values["mode"] == "at":
                values["at"] = at.get_text()
        def reviewed(review):
            if not current():
                _release(session, review["token"])
            elif not review["changes"]:
                _release(session, review["token"])
                session.toast(_tr("The selected entries already have this setting"))
            else:
                dialog.close()
                _review(session, review)
        session.run_job(lambda: session.vault.review_entry_action(entries, **values), reviewed)
    _save(header, submit, _tr('Review…'))
    session.present_dialog(dialog)


def _review(session, review):
    token = review["token"]
    epoch, identity = session.epoch, session.vault.identity
    state = {"phase": "review"}
    def release():
        if state["phase"] == "review":
            state["phase"] = "released"
            if session.epoch == epoch and session.vault.identity is identity:
                _release(session, token)
        return False
    action = review["action"]
    if action == "duplicate":
        heading, label = "Duplicate Entry?", "Duplicate"
        summary = "Create a new entry in the same group."
        summary += "\nInclude history." if review["history"] else "\nStart without history."
        summary += "\nReference the original username and password." if review["references"] else "\nCopy the username and password."
        if review["rename"]:
            summary += "\nAppend ‘ - Clone’ to the title."
    elif action == "tag":
        heading, label = ("Add Tag to Entries?", "Add Tag") if review["add"] else ("Remove Tag from Entries?", "Remove Tag")
        summary = f'Tag: {review["tag"]}\nChange {review["changes"]} of {review["count"]} selected entries.'
    else:
        heading, label = "Change Entry Expiry?", "Apply"
        summary = "Never expires." if review["mode"] == "never" else f'Expires: {review["at"]}'
        summary += f'\nChange {review["changes"]} of {review["count"]} selected entries.'
    body = "\n".join(review["names"])
    if review["count"] > len(review["names"]):
        body += f'\n…and {review["count"] - len(review["names"])} more.'
    dialog = Adw.AlertDialog(heading=heading, body=body + "\n\n" + summary, body_use_markup=False)
    dialog.add_response("cancel", _tr("Cancel"))
    dialog.add_response("apply", label)
    dialog.set_close_response("cancel")
    dialog.set_default_response("cancel")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
    def response(_dialog, answer):
        if state["phase"] != "review":
            return
        if answer != "apply" or session.epoch != epoch or session.vault.identity is not identity:
            release()
            return
        state["phase"] = "applying"
        def done(result):
            state["phase"] = "done"
            snapshot, created = result
            session.apply_refreshed(snapshot)
            if created:
                window = session.window
                window.set_selection_mode(False)
                window.search.set_text("")
                window.search_matches = None
                window.groups.select_row(window.groups.get_first_child())
                window.render_entries(created)
                window.inner.set_show_content(True)
            session.toast(_tr("Entry duplicated") if created else _tr("Entry settings saved"))
        def failed(message):
            state["phase"] = "review"
            release()
            session.error(message)
        if not session.run_job(lambda: session.vault.apply_entry_action(token), done, failed):
            state["phase"] = "review"
            release()
            session.toast(_tr("Entries unchanged; wait for the current operation and try again"))
    dialog.connect("response", response)
    dialog.connect("closed", lambda *_: GLib.idle_add(release))
    if not session.present_dialog(dialog):
        release()


def selection_menu(session, entries):
    menu = Gtk.MenuButton(icon_name="view-more-symbolic", tooltip_text=_tr("More Selected Entry Actions"), valign=Gtk.Align.CENTER)
    popover = Gtk.Popover()
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3, margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
    for title, action in ((_mark("Edit Tags…"), "tag"), (_mark("Set Expiry…"), "expiry")):
        item = Gtk.Button(label=_tr(title), css_classes=["flat"])
        def clicked(_button, action=action):
            selected = entries()
            popover.popdown()
            choose(session, selected, action)
        item.connect("clicked", clicked)
        box.append(item)
    popover.set_child(box)
    menu.set_popover(popover)
    return menu
