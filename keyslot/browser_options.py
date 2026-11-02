"""Entry/group browser rules using upstream custom-data inheritance."""
from .i18n import mark as _mark, tr as _tr, trf as _trf
from .database_views import Adw, Gtk, _dialog, _save
from .passkey_views import _lifetime
from .backend import VaultError


OPTIONS = [("hide", _mark('Hide from Browsers')), ("skip_submit", _mark('Prevent Automatic Form Submission')),
           ("only_http", _mark('Only Match HTTP Authentication')), ("not_http", _mark('Exclude HTTP Authentication')),
           ("omit_www", _mark('Ignore www in Website Matching'))]


def settings(session, entry=None, group=None, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(lambda: session.vault.browser_options(entry, group),
                        lambda value: settings(session, entry, group, value))
        return
    dialog, header, box = _dialog(_tr("Browser Integration"), width=520, height=600)
    current = _lifetime(session, dialog)
    rules = Adw.PreferencesGroup(title=_tr("Entry Rules") if entry else _tr("Group Rules"),
        description=_tr("Group rules take precedence where shown.") if entry else
                    _tr("Rules apply to this group and its descendants. Subgroups can override inherited rules."))
    rows = {}
    for code, title in OPTIONS:
        if code not in data["values"]:
            continue
        parent = _tr("Enabled") if data["inherited"][code] == 1 else _tr("Disabled")
        row = Adw.ComboRow(title=_tr(title), model=Gtk.StringList.new([_trf('Inherit ({arg0})', arg0=parent), _tr("Enabled"), _tr("Disabled")]))
        if data["forced"][code]:
            row.set_selected(1 if data["effective"][code] else 2)
            row.set_subtitle(_tr("Controlled by this entry’s group"))
            row.set_sensitive(False)
        else:
            row.set_selected(data["values"][code])
        rules.add(row)
        rows[code] = row
    box.append(rules)
    warning = Gtk.Label(label=_tr("These rules exclude both website forms and HTTP authentication. Entries will not match login requests."),
                        xalign=0, wrap=True, css_classes=["warning"])
    def enabled(code):
        selected = rows[code].get_selected()
        return selected == 1 or (selected == 0 and data["inherited"][code] == 1)
    def warn(*_):
        warning.set_visible(enabled("only_http") and enabled("not_http"))
    for code in ("only_http", "not_http"):
        rows[code].connect("notify::selected", warn)
    warn()
    box.append(warning)
    restriction = data["restriction"]
    connections = set(restriction["connections"])
    def label(identifier):
        if not identifier:
            return _tr("All Connections")
        return identifier if identifier in connections else _trf("{connection} (Disconnected)", connection=identifier)
    section = Adw.PreferencesGroup(title=_tr("Browser Connections"))
    key_row = None
    key_choices = []
    if entry:
        section.add(Adw.ActionRow(title=_tr("Allowed Connection"), subtitle=label(restriction["inherited"]),
                                 use_markup=False, subtitle_lines=2))
        section.set_description(_tr("Connection restrictions are set in the group’s browser settings."))
    else:
        ids = sorted(connections | ({restriction["id"]} if restriction["id"] else set()), key=str.casefold)
        key_choices = [("inherit", ""), ("all", "")] + [("connection", identifier) for identifier in ids]
        key_row = Adw.ComboRow(title=_tr("Allowed Connection"), model=Gtk.StringList.new(
            [_trf('Inherit ({arg0})', arg0=label(restriction['inherited'])), _tr("All Connections")] + [label(identifier) for identifier in ids]))
        key_row.set_selected(key_choices.index((restriction["mode"], restriction["id"])))
        section.set_description(_tr("Restrict matching to one paired browser connection, or inherit the parent group’s restriction."))
        section.add(key_row)
    box.append(section)
    if not session.application.startup.browser:
        box.append(Gtk.Label(label=_tr("Enable Browser Integration in Preferences to use these rules with your browser."),
                             xalign=0, wrap=True, css_classes=["dim-label"]))
    def save(*_):
        if not current() or session.busy:
            return
        values = {code: row.get_selected() for code, row in rows.items()
                  if not data["forced"][code] and row.get_selected() != data["values"][code]}
        changed_key = None
        if key_row:
            mode, identifier = key_choices[key_row.get_selected()]
            if (mode, identifier) != (restriction["mode"], restriction["id"]):
                changed_key = {"mode": mode, "id": identifier}
        if not values and changed_key is None:
            dialog.close()
            return
        def saved(snapshot):
            if current():
                dialog.close()
                session.window.show_vault(snapshot)
                session.toast(_tr("Browser settings saved"))
        session.run_job(lambda: session.vault.save_browser_options(entry, group, revision=data["revision"],
                        values=values, restriction=changed_key), saved)
    _save(header, save)
    session.present_dialog(dialog)


def websites(session, entry, data=None):
    if not session.vault.unlocked or session.busy or entry.recycled:
        return
    if data is None:
        def read():
            revision = session.vault.browser_options(entry)["revision"]
            items = []
            for name in entry.attributes:
                if not name.startswith("KP2A_URL"):
                    continue
                item = session.vault.attribute_info(entry, name, review=True)
                if item["revision"] != revision:
                    raise VaultError("The database changed. Open the website list again.")
                if item["protected"]:
                    item["value"] = ""
                items.append({"name": name, **item})
            return {"revision": revision, "items": items}
        session.run_job(read, lambda value: websites(session, entry, value))
        return
    dialog, header, box = _dialog(_tr("Additional Websites"), height=420)
    current = _lifetime(session, dialog)
    group = Adw.PreferencesGroup(description=_tr("These websites use the same login as this entry. Edit the primary website in Edit Entry."))
    for index, item in enumerate(data["items"], 1):
        row = Adw.ActionRow(title=_tr("Protected Website") if item["protected"] else item["value"] or _tr("Empty Website"),
                            subtitle=_trf('Additional Website {arg0}', arg0=index), title_lines=2, use_markup=False, activatable=True)
        row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
        def edit(_row, name=item["name"]):
            if current():
                dialog.close()
                _website(session, entry, name)
        row.connect("activated", edit)
        group.add(row)
    if not data["items"]:
        group.add(Adw.ActionRow(title=_tr("No Additional Websites")))
    box.append(group)
    add = Gtk.Button(label=_tr("Add Website"), valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
    def create(*_):
        if not current():
            return
        name, index = "KP2A_URL", 1
        while name in entry.attributes:
            name, index = f"KP2A_URL_{index}", index + 1
        info = {"value": "", "protected": False, "revision": data["revision"]}
        dialog.close()
        _website(session, entry, name, info, creating=True)
    add.connect("clicked", create)
    header.pack_start(add)
    def clear(*_):
        for item in data["items"]:
            item["value"] = ""
    dialog.connect("closed", clear)
    session.present_dialog(dialog)


def _website(session, entry, name, info=None, *, creating=False):
    if not session.vault.unlocked or session.busy:
        return
    if info is None:
        session.run_job(lambda: session.vault.attribute_info(entry, name, review=True),
                        lambda value: _website(session, entry, name, value))
        return
    dialog, header, box = _dialog(_tr("Add Website") if creating else _tr("Edit Website"), height=300)
    current = _lifetime(session, dialog)
    fields = Adw.PreferencesGroup(description=_tr("Placeholders and field references are kept as entered."))
    value = Adw.PasswordEntryRow(title=_tr("Website"), text=info["value"])
    protected = Adw.SwitchRow(title=_tr("Protect Website"), active=info["protected"],
                             subtitle=_tr("Hide its address in the website list"))
    fields.add(value)
    fields.add(protected)
    box.append(fields)
    from . import reference_views
    reference_views.menu(session, dialog, header, [
        (_tr('Website'), "A", lambda text: reference_views.insert_text(value, text)),
    ], entry)
    def saved(snapshot):
        if current():
            dialog.close()
            session.window.show_vault(snapshot)
            fresh = next((item for item in snapshot.entries if item.uuid == entry.uuid), None)
            if fresh:
                websites(session, fresh)
    def save(*_):
        if current() and not session.busy:
            text, protect = value.get_text(), protected.get_active()
            session.run_job(lambda: session.vault.set_attribute(entry, name, text, protect,
                original_name="" if creating else name, revision=info["revision"]), saved)
    _save(header, save)
    if not creating:
        remove = Gtk.Button(label=_tr("Remove Website…"), css_classes=["destructive-action"])
        def confirm(*_):
            from .passkey_views import _confirm
            _confirm(session, "Remove Website?", "This website will no longer match the entry’s login.", "Remove",
                lambda: session.run_job(lambda: session.vault.remove_attribute(entry, name, revision=info["revision"]), saved)
                if current() else None)
        remove.connect("clicked", confirm)
        box.append(remove)
    dialog.connect("closed", lambda *_: (value.set_text(""), info.__setitem__("value", "")))
    session.present_dialog(dialog)
