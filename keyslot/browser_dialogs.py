"""GNOME browser consent surfaces keep password values out of dialogs."""
from .i18n import ntrf as _ntrf, tr as _tr, trf as _trf
from urllib.parse import urlsplit

from .application import Adw, Gtk, GLib, clear_dialog_fields
from .database_views import _dialog
from .backend import VaultError


def website_origin(value):
    try:
        url = urlsplit(value)
        if url.scheme in {"http", "https"}:
            host = (url.hostname or "").encode("idna").decode()
            if ":" in host:
                host = "[" + host + "]"
            port = ":" + str(url.port) if url.port is not None else ""
            return url.scheme + "://" + host + port
        return "Local File" if url.scheme == "file" else "Direct Entry Lookup"
    except (ValueError, UnicodeError):
        return "Unknown Website"


def add_preferences(session, page, preferences):
    application, settings = session.application, session.application.startup
    group = Adw.PreferencesGroup(title=_tr("Browser Integration"),
        description=_tr("Fill and save logins with KeePassXC-Browser. Keep Keyslot running to provide browser access."))
    enabled = Adw.SwitchRow(title=_tr("Browser Integration"), subtitle=_tr("Allow connected browsers to request credentials"), active=settings.browser)
    listing = Adw.SwitchRow(title=_tr("Allow Browsers to List All Entries"), active=settings.browser_listing,
        subtitle=_tr("Share all entry titles, IDs and resolved website fields with paired browsers"))
    setup = Adw.ActionRow(title=_tr("Browser Setup"), subtitle=_tr("Choose browsers that can connect to Keyslot"))
    configure = Gtk.Button(label=_tr("Configure…"), valign=Gtk.Align.CENTER)
    configure.connect("clicked", lambda *_: (preferences.close(), browser_setup(session)))
    setup.add_suffix(configure)
    setup.set_activatable_widget(configure)
    changing = [False]
    closed = [False]
    preferences.connect("closed", lambda *_: closed.__setitem__(0, True))

    def status():
        if closed[0]:
            return False
        browser = application.browser
        enabled.set_subtitle(_tr("Allow connected browsers to request credentials") if not settings.browser else
            _tr("Ready for browser requests") if browser and browser.ready else
            _tr("Unavailable. Try turning this option off and on again.") if browser is None or browser.pipe.closed else
            _tr("Starting browser access…"))
        if listing.get_active() != settings.browser_listing:
            changing[0] = True
            listing.set_active(settings.browser_listing)
            changing[0] = False
        return True

    def changed(*_):
        if changing[0]:
            return
        try:
            application.set_browser(enabled.get_active(), persist=True)
        except (OSError, ValueError, VaultError):
            session.error(_tr("Browser integration could not start. Check your installation and try again."))
        changing[0] = True
        enabled.set_active(settings.browser)
        status()
        changing[0] = False
    enabled.connect("notify::active", changed)
    def set_listing(value):
        if closed[0]:
            return
        try:
            settings.set_browser_listing(value)
        except (OSError, ValueError, VaultError) as exc:
            session.error(str(exc))
        changing[0] = True
        listing.set_active(settings.browser_listing)
        changing[0] = False
    def listing_changed(*_):
        if changing[0]:
            return
        if not listing.get_active() or settings.browser_listing:
            set_listing(listing.get_active())
            return
        changing[0] = True
        listing.set_active(False)
        changing[0] = False
        alert = Adw.AlertDialog(heading=_tr("Allow Browsers to List All Entries?"), body=
            _tr("Any paired browser can retrieve entry titles, IDs and resolved website fields, including entries hidden from normal filling. "
            "References in these fields are resolved and can include protected values."), body_use_markup=False)
        alert.add_response("cancel", _tr("Cancel"))
        alert.add_response("allow", _tr("Allow Listing"))
        alert.set_close_response("cancel")
        alert.set_default_response("cancel")
        alert.set_response_appearance("allow", Adw.ResponseAppearance.SUGGESTED)
        alert.connect("response", lambda _alert, response: set_listing(True) if response == "allow" else None)
        session.present_dialog(alert)
    listing.connect("notify::active", listing_changed)
    group.add(enabled)
    group.add(setup)
    group.add(listing)
    page.add(group)
    def refreshed_listing(value):
        if not closed[0]:
            changing[0] = True
            listing.set_active(value)
            changing[0] = False
    session.jobs.run(settings.browser_listing_allowed, refreshed_listing,
                     lambda message: session.error(message) if not closed[0] else None, interactive=False)
    status()
    GLib.timeout_add(200, status)


def browser_setup(session):
    from .browser_hosts import BROWSERS
    try:
        manager = session.application.native_hosts()
        statuses = {name: manager.status(name) for name in BROWSERS}
    except (OSError, ValueError, VaultError) as exc:
        session.error(str(exc))
        return
    dialog, _header, box = _dialog(_tr("Browser Setup"), width=520, height=560)
    box.append(Gtk.Label(label=_tr("Enable Browser Integration in Preferences, then install KeePassXC-Browser in the browsers you select. Turning a browser off restores its previous connection settings."),
                         wrap=True, xalign=0))
    group = Adw.PreferencesGroup(title=_tr("Browsers"))
    box.append(group)
    state = {"updating": False, "closed": False}
    rows = {}
    dialog.connect("closed", lambda *_: state.update(closed=True))

    def refresh(browser, row):
        try:
            status = manager.status(browser)
            statuses[browser] = status
            state["updating"] = True
            row.set_active(status["enabled"])
            row.set_subtitle(_tr("Connected to Keyslot") if status["enabled"] else
                             _tr("Another connection is configured") if status["exists"] else _tr("Not configured"))
        except (OSError, ValueError, VaultError) as exc:
            session.error(str(exc))
        finally:
            state["updating"] = False

    def apply(browser, row, enabled, reviewed, replace=False):
        if state["closed"]:
            return
        try:
            if enabled:
                integration = session.application.browser
                if integration is None or not integration.ready:
                    raise VaultError("Start browser integration before connecting a browser.")
                manager.enable(browser, reviewed, replace=replace)
            else:
                manager.disable(browser)
        except (OSError, ValueError, VaultError) as exc:
            session.error(str(exc))
        refresh(browser, row)

    def changed(browser, row):
        if state["updating"] or state["closed"]:
            return
        enable = row.get_active()
        try:
            status = manager.status(browser)
        except (OSError, ValueError, VaultError) as exc:
            session.error(str(exc))
            return
        if enable and status["exists"] and not status["enabled"]:
            refresh(browser, row)
            alert = Adw.AlertDialog(heading=_trf('Use Keyslot for {arg0}?', arg0=BROWSERS[browser]),
                body=_tr("This replaces the browser’s current KeePassXC connection. Its settings will be saved so you can restore them."))
            alert.add_response("cancel", _tr("Cancel"))
            alert.add_response("use", _tr("Use Keyslot"))
            alert.set_default_response("cancel")
            alert.set_close_response("cancel")
            alert.set_response_appearance("use", Adw.ResponseAppearance.SUGGESTED)
            alert.connect("response", lambda _alert, response: apply(browser, row, True, status["fingerprint"], True)
                          if response == "use" else None)
            session.present_dialog(alert)
        else:
            apply(browser, row, enable, status["fingerprint"])

    for browser, title in BROWSERS.items():
        row = Adw.SwitchRow(title=title, active=statuses[browser]["enabled"])
        refresh(browser, row)
        row.connect("notify::active", lambda row, _property, browser=browser: changed(browser, row))
        rows[browser] = row
        group.add(row)
    def readiness():
        if state["closed"]:
            return False
        integration = session.application.browser
        ready = integration is not None and integration.ready
        for browser, row in rows.items():
            row.set_sensitive(ready or statuses[browser]["enabled"])
        return True
    readiness()
    GLib.timeout_add(200, readiness)
    session.present_dialog(dialog)


class BrowserDialogs:
    def __init__(self, application):
        self.app = application

    def unlock(self, session):
        self.app.select_session(session)
        if session.path and not session.busy and not session.dialogs:
            session._unlock_dialog(str(session.path))

    def generate(self, session, _data, done):
        state = {"closed": False}
        def applied(value):
            if value is None:
                state["closed"] = True
            done(value)
        dialog = session.generator(on_apply=applied)
        def dismiss():
            if dialog:
                clear_dialog_fields(dialog)
                if not state["closed"]:
                    state["closed"] = True
                    dialog.force_close()
        return dismiss

    def deleted(self, session):
        session.window.show_vault(session.vault.snapshot)
        session.toast(_tr("Entry deleted"))

    def passkey_saved(self, session):
        session.window.show_vault(session.vault.snapshot)
        session.toast(_tr("Passkey saved"))

    def passkey(self, session, data, done):
        registration = data["registration"]
        dialog, header, box = _dialog(_tr("Create Passkey") if registration else _tr("Sign In with Passkey"), width=520,
                                     height=620 if registration else 500)
        box.append(Gtk.Label(label=_tr("Create a passkey for this account.") if registration else _tr("Choose a passkey to sign in."),
                             wrap=True, xalign=0))
        website = Adw.PreferencesGroup(title=_tr("Website"))
        website.add(Adw.ActionRow(title=website_origin(data["origin"]), subtitle=_tr("Website requesting a passkey"), use_markup=False))
        website.add(Adw.ActionRow(title=data["rp"], subtitle=_tr("Passkey domain"), use_markup=False))
        box.append(website)
        selected = {}
        if registration:
            account = Adw.PreferencesGroup(title=_tr("Account"))
            account.add(Adw.ActionRow(title=data.get("username") or data.get("display_name") or _tr("Unnamed Account"),
                subtitle=data.get("display_name") or "", use_markup=False))
            box.append(account)
            entries = [None] + [entry for entry in session.vault.snapshot.entries if not entry.recycled]
            targets = Adw.ComboRow(title=_tr("Save To"), model=Gtk.StringList.new([_tr("New Entry")] +
                [(entry.title or "Untitled Entry") + " · " + (entry.username or entry.group_path) for entry in entries[1:]]))
            destination = Adw.PreferencesGroup()
            destination.add(targets)
            groups = [None] + [group for group in session.vault.snapshot.groups if not group.recycled]
            group_row = Adw.ComboRow(title=_tr("Group"), model=Gtk.StringList.new([data["group_path"] + " (Default)"] +
                                     [group.path for group in groups[1:]]))
            destination.add(group_row)
            targets.connect("notify::selected", lambda *_: group_row.set_visible(targets.get_selected() == 0))
            box.append(destination)
        else:
            accounts = Adw.PreferencesGroup(title=_tr("Accounts"))
            first = None
            for entry in data["entries"]:
                row = Adw.ActionRow(title=entry["username"] or entry["title"] or _tr("Unnamed Account"),
                    subtitle=(entry["title"] or "Untitled Entry") + " · " + entry["group"], use_markup=False)
                check = Gtk.CheckButton(valign=Gtk.Align.CENTER, active=first is None)
                if first is not None:
                    check.set_group(first)
                else:
                    first = check
                row.add_prefix(check)
                row.set_activatable_widget(check)
                accounts.add(row)
                selected[entry["uuid"]] = check
            box.append(accounts)
        approve = Gtk.Button(label=_tr("Create") if registration else _tr("Sign In"), valign=Gtk.Align.CENTER,
                             css_classes=["suggested-action"])
        header.pack_end(approve)
        timeout = Gtk.Label(xalign=0, css_classes=["dim-label"])
        box.append(timeout)
        state, dialogs, choose, dismiss = self._lifecycle(session, dialog, done)
        deadline = GLib.get_monotonic_time() + data["timeout_ms"] * 1000
        def countdown():
            if state["closed"]:
                return False
            seconds = max(0, (deadline - GLib.get_monotonic_time() + 999999) // 1000000)
            timeout.set_label(_ntrf('Request expires in {count} second', 'Request expires in {count} seconds', seconds) if seconds else _tr("Request expired"))
            if not seconds:
                approve.set_sensitive(False)
            return seconds > 0
        countdown()
        GLib.timeout_add(1000, countdown)

        def submit(replace=False):
            if state["closed"] or state["answered"]:
                return
            approve.set_sensitive(False)
            if registration:
                entry = entries[targets.get_selected()]
                group = groups[group_row.get_selected()]
                choose({"entry": entry.uuid.replace("-", "") if entry else "",
                        "group": group.uuid.replace("-", "") if group and not entry else "", "replace": replace})
            else:
                choose({"entry": next((uuid for uuid, check in selected.items() if check.get_active()), ""),
                        "group": "", "replace": False})

        def clicked(*_):
            if state["closed"] or state["answered"]:
                return
            entry = entries[targets.get_selected()] if registration else None
            if entry and entry.passkey:
                alert = Adw.AlertDialog(heading=_tr("Replace Existing Passkey?"),
                    body="This entry already contains a passkey. Replacing it removes the current passkey from the entry.\n\n" + entry.title,
                    body_use_markup=False)
                alert.add_response("cancel", _tr("Cancel"))
                alert.add_response("replace", _tr("Replace Passkey"))
                alert.set_default_response("cancel")
                alert.set_close_response("cancel")
                alert.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
                dialogs.append(alert)
                alert.connect("closed", lambda item: dialogs.remove(item) if item in dialogs else None)
                alert.connect("response", lambda _alert, response: submit(True)
                              if response == "replace" and not state["closed"] else None)
                session.present_dialog(alert)
            else:
                submit()
        approve.connect("clicked", clicked)
        return dismiss

    def delete_entry(self, session, data, done):
        permanent = data["permanent"]
        dialog = Adw.AlertDialog(heading=_tr("Delete Entry Permanently?") if permanent else _tr("Move Entry to Recycle Bin?"),
            body=("The recycle bin is disabled. This entry and its saved history will be permanently removed.\n\n" if permanent
                  else "A browser wants to move this entry to the recycle bin.\n\n")
                 + (data["title"] or "Untitled Entry") + "\n" + data["group"], body_use_markup=False)
        dialog.add_response("cancel", _tr("Cancel"))
        dialog.add_response("delete", _tr("Delete Permanently") if permanent else _tr("Move to Recycle Bin"))
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        state = {"closed": False, "answered": False, "dismissed": False}
        dialog.connect("closed", lambda *_: state.update(closed=True))
        def response(_dialog, name):
            if not state["dismissed"] and not state["answered"]:
                state["answered"] = True
                done(name == "delete")
        def dismiss():
            state["dismissed"] = True
            clear_dialog_fields(dialog)
            if not state["closed"]:
                dialog.force_close()
        # AlertDialog emits response after closed; the response owns its cancellation decision.
        dialog.connect("response", response)
        session.present_dialog(dialog)
        return dismiss

    def saved(self, session):
        session.window.show_vault(session.vault.snapshot)
        session.toast(_tr("Login saved"))

    def favicon_saved(self, session, entry, options, reservation):
        epoch, identity = session.epoch, session.vault.identity
        def start():
            if (not session.jobs.closed and session.vault.unlocked and session.epoch == epoch
                    and session.vault.identity is identity and self.app.startup.browser):
                from .icon_views import BrowserFavicon
                try:
                    BrowserFavicon(session, entry, dict(options), reservation)
                except Exception:
                    from .icon_views import _release
                    _release(session, reservation)
                    session.toast(_tr("Login saved; its website icon could not be started"))
            else:
                from .icon_views import _release
                _release(session, reservation)
            return False
        GLib.idle_add(start)

    def group_created(self, session):
        session.window.show_vault(session.vault.snapshot)
        session.toast(_tr("Group created"))

    def create_group(self, session, data, done):
        dialog, header, box = _dialog(_tr("Create Group"), width=440, height=300)
        box.append(Gtk.Label(label=_tr("A browser wants to create this group. Missing parent groups will also be created."),
                             wrap=True, xalign=0))
        group = Adw.PreferencesGroup()
        group.add(Adw.ActionRow(title=data["path"], subtitle=data["database"] or _tr("Password Database"),
                               use_markup=False, title_lines=3, subtitle_lines=2))
        box.append(group)
        cancel = Gtk.Button(label=_tr("Cancel"), valign=Gtk.Align.CENTER)
        create = Gtk.Button(label=_tr("Create"), valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.pack_start(cancel)
        header.pack_end(create)
        state, _dialogs, choose, dismiss = self._lifecycle(session, dialog, done)

        def submit(*_):
            if state["closed"] or state["answered"]:
                return
            create.set_sensitive(False)
            cancel.set_sensitive(False)
            choose(True)
        create.connect("clicked", submit)
        cancel.connect("clicked", lambda *_: choose(None))
        return dismiss

    def save_login(self, session, data, done):
        updating = data["update"]
        dialog, header, box = _dialog(_tr("Update Login") if updating else _tr("Save Login"), width=520, height=560)
        box.append(Gtk.Label(label=_tr("A browser wants to update this login.") if updating else _tr("A browser wants to save a new login."),
                             wrap=True, xalign=0))
        website = Adw.PreferencesGroup(title=_tr("Website"))
        origin = website_origin(data["url"])
        website.add(Adw.ActionRow(title=origin, use_markup=False))
        if data["submit_url"] and website_origin(data["submit_url"]) != origin:
            website.add(Adw.ActionRow(title=website_origin(data["submit_url"]), subtitle=_tr("Sign-in form destination"), use_markup=False))
        if updating and data["entry_url"] and website_origin(data["entry_url"]) != origin:
            website.add(Adw.ActionRow(title=website_origin(data["entry_url"]), subtitle=_tr("Current entry website"), use_markup=False))
        box.append(website)
        entry = Adw.PreferencesGroup(title=_tr("Original Password Entry") if data["reference"] else _tr("Entry"))
        entry.add(Adw.ActionRow(title=data["title"] or _tr("Untitled Entry"), subtitle=data["group"] if updating else _tr("New entry"), use_markup=False))
        entry.add(Adw.ActionRow(title=_tr("Username"), subtitle=data["username"] or _tr("None"), use_markup=False))
        entry.add(Adw.ActionRow(title=_tr("Password"), subtitle=_tr("The browser supplied a password"), use_markup=False))
        box.append(entry)
        favicon = None
        icon_options = None
        if data.get("favicon_requested") and not updating:
            available = {"browser-save-result", "favicon-entry", "browser-icon-reservation"} <= session.vault.capabilities
            reason = "Update the native helper to enable website icons."
            if available:
                try:
                    storage = getattr(session.application.startup, "storage", None)
                    icon_options = storage.read_icon_options() if storage else {"timeout": 10, "fallback": False}
                except (OSError, ValueError, VaultError) as error:
                    available, reason = False, str(error)
            subtitle = ("Contact this website and its parent domain without login credentials or cookies."
                        + (" Also use DuckDuckGo's icon service." if icon_options and icon_options["fallback"] else "")) if available else reason
            favicon = Adw.SwitchRow(title=_tr("Download Website Icon"), subtitle=subtitle, subtitle_lines=3,
                                    active=available, sensitive=available)
            icons = Adw.PreferencesGroup(description=_tr("The browser requested an icon. The login is saved before the download starts."))
            icons.add(favicon)
            box.append(icons)
        group_ids = [""] + [item["uuid"] for item in data["groups"]]
        if not updating:
            choices = Gtk.StringList.new([_tr("KeePassXC-Browser Passwords (Default)")] + [item["name"] for item in data["groups"]])
            group = Adw.ComboRow(title=_tr("Group"), model=choices, selected=group_ids.index(data["selected_group"]))
            destination = Adw.PreferencesGroup()
            destination.add(group)
            box.append(destination)
        cancel = Gtk.Button(label=_tr("Cancel"), valign=Gtk.Align.CENTER)
        save = Gtk.Button(label=_tr("Update Login") if updating else _tr("Save Login"), valign=Gtk.Align.CENTER,
                          css_classes=["suggested-action"])
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.pack_start(cancel)
        header.pack_end(save)
        state, _dialogs, choose, dismiss = self._lifecycle(session, dialog, done)

        def submit(*_):
            if state["closed"] or state["answered"]:
                return
            save.set_sensitive(False)
            cancel.set_sensitive(False)
            choose({"group": "" if updating else group_ids[group.get_selected()],
                    "favicon": bool(favicon and favicon.get_active()), "icon_options": icon_options})
        save.connect("clicked", submit)
        cancel.connect("clicked", lambda *_: choose(None))
        return dismiss

    def failure(self, message):
        if self.app.active_session:
            session = self.app.active_session
            if session.active:
                session.toast(message)
            else:
                session.error(message)
        else:
            self.app.startup_error = message

    def _lifecycle(self, session, dialog, done):
        state = {"answered": False, "closed": False}
        dialogs = [dialog]

        def closed(*_):
            cancelled = not state["answered"] and not state["closed"]
            state["closed"] = True
            if cancelled:
                done(None)

        dialog.connect("closed", closed)

        def choose(value):
            if state["closed"] or state["answered"]:
                return
            state["answered"] = True
            done(value)

        def dismiss():
            already_closed = state["closed"]
            state["closed"] = True
            for item in list(reversed(dialogs)):
                clear_dialog_fields(item)
                if item is not dialog or not already_closed:
                    item.force_close()
            dialogs.clear()
        session.present_dialog(dialog)
        return state, dialogs, choose, dismiss

    def pair(self, session, data, done):
        dialog, _header, box = _dialog(_tr("Connect Browser"), width=440, height=360)
        box.append(Gtk.Label(label=data["database"] or _tr("Password Database"), wrap=True, css_classes=["title-2"]))
        box.append(Gtk.Label(label=_tr("A browser wants to connect to this database. Give the connection a name you can recognize later."),
                             wrap=True, xalign=0))
        group = Adw.PreferencesGroup()
        name = Adw.EntryRow(title=_tr("Connection Name"))
        group.add(name)
        box.append(group)
        connect = Gtk.Button(label=_tr("Connect Browser"), sensitive=False, css_classes=["suggested-action", "pill"])
        box.append(connect)
        existing = {item["id"] for item in data["connections"]}
        state, dialogs, choose, dismiss = self._lifecycle(session, dialog, done)

        def submit(identifier, replace=False):
            connect.set_sensitive(False)
            name.set_sensitive(False)
            choose({"name": identifier, "replace": replace})

        def clicked(*_):
            identifier = name.get_text().strip()
            if not identifier or state["closed"] or state["answered"]:
                return
            if identifier not in existing:
                submit(identifier)
                return
            alert = Adw.AlertDialog(heading=_tr("Replace Browser Connection?"),
                body=_trf('“{arg0}” is already connected. Replacing it will require the previous browser to connect again.', arg0=identifier))
            alert.add_response("cancel", _tr("Cancel"))
            alert.add_response("replace", _tr("Replace Connection"))
            alert.set_default_response("cancel")
            alert.set_close_response("cancel")
            alert.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
            dialogs.append(alert)
            alert.connect("closed", lambda item: dialogs.remove(item) if item in dialogs else None)
            alert.connect("response", lambda _alert, response: submit(identifier, True)
                          if response == "replace" and not state["closed"] else None)
            session.present_dialog(alert)
        name.connect("notify::text", lambda *_: connect.set_sensitive(bool(name.get_text().strip()) and not state["answered"]))
        name.connect("entry-activated", clicked)
        connect.connect("clicked", clicked)
        return dismiss

    def access(self, session, data, done):
        from .browser_shell import approve
        def fallback():
            self.app.select_session(session)
            return self._access_dialog(session, data, done)
        return approve(session, data, done, fallback)

    def _access_dialog(self, session, data, done):
        dialog, _header, box = _dialog(_tr("Browser Access"), width=520, height=520)
        box.append(Gtk.Label(label=_tr("A browser wants credentials for this website. Choose which entries to share."), wrap=True, xalign=0))
        website = Adw.PreferencesGroup(title=_tr("Website"))
        origin = website_origin(data["url"])
        website.add(Adw.ActionRow(title=origin, subtitle=_tr("HTTP authentication request")
                                 if data.get("http_auth") else _tr("Website requesting access"), use_markup=False))
        website.add(Adw.ActionRow(title=data["connection"], subtitle=_tr("Browser connection"), use_markup=False))
        website.add(Adw.ActionRow(title=data["database"] or _tr("Password Database"), subtitle=_tr("Database"), use_markup=False))
        form = website_origin(data["submit_url"]) if data["submit_url"] else origin
        if form != origin:
            website.add(Adw.ActionRow(title=form, subtitle=_tr("Sign-in form destination"), use_markup=False))
        box.append(website)
        group = Adw.PreferencesGroup(title=_tr("Entries"))
        selected = {}
        for entry in data["entries"]:
            row = Adw.ActionRow(title=entry["title"] or _tr("Untitled Entry"),
                subtitle=entry["username"] or entry["group"], use_markup=False, title_lines=2, subtitle_lines=2)
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER, active=entry["allowed"] or len(data["entries"]) == 1)
            row.add_prefix(check)
            row.set_activatable_widget(check)
            group.add(row)
            selected[entry["uuid"]] = check
        box.append(group)
        permissions = Adw.PreferencesGroup()
        remember = Adw.SwitchRow(title=_tr("Remember This Decision"), subtitle=_tr("Save access rules in this encrypted database"))
        permissions.add(remember)
        box.append(permissions)
        trust = Gtk.Button(label=_tr("Fully Trust This Browser"))
        box.append(trust)
        box.append(Gtk.Label(label=_tr("Automatically share matching logins with this browser in this database. "
            "Hidden entries and denied websites stay blocked. Manage trust in Database Settings → Browser Connections."),
            wrap=True, xalign=0, css_classes=["dim-label"]))
        buttons = Gtk.Box(spacing=12, homogeneous=True)
        deny = Gtk.Button(label=_tr("Deny All"))
        allow = Gtk.Button(label=_tr("Allow Selected"), css_classes=["suggested-action"])
        buttons.append(deny)
        buttons.append(allow)
        box.append(buttons)
        state, _dialogs, choose, dismiss = self._lifecycle(session, dialog, done)

        def update(*_):
            allow.set_sensitive(not state["answered"] and any(check.get_active() for check in selected.values()))
            trust.set_sensitive(allow.get_sensitive())

        def submit(approved, trusted=False):
            if state["closed"] or state["answered"]:
                return
            allow.set_sensitive(False)
            deny.set_sensitive(False)
            trust.set_sensitive(False)
            choose({"allow": approved, "selected": [uuid for uuid, check in selected.items() if check.get_active()],
                    "remember": remember.get_active(), "trust": trusted})
        for check in selected.values():
            check.connect("toggled", update)
        deny.connect("clicked", lambda *_: submit(False))
        allow.connect("clicked", lambda *_: submit(True))
        trust.connect("clicked", lambda *_: submit(True, True))
        update()
        return dismiss
