"""GNOME browser consent surfaces keep password values out of dialogs."""
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
    group = Adw.PreferencesGroup(title="Browser Integration",
        description="Fill and save logins with KeePassXC-Browser. Keep Keyslot running to provide browser access.")
    enabled = Adw.SwitchRow(title="Browser Integration", subtitle="Allow connected browsers to request credentials", active=settings.browser)
    setup = Adw.ActionRow(title="Browser Setup", subtitle="Choose browsers that can connect to Keyslot")
    configure = Gtk.Button(label="Configure…", valign=Gtk.Align.CENTER)
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
        enabled.set_subtitle("Allow connected browsers to request credentials" if not settings.browser else
            "Ready for browser requests" if browser and browser.ready else
            "Unavailable. Try turning this option off and on again." if browser is None or browser.pipe.closed else
            "Starting browser access…")
        return True

    def changed(*_):
        if changing[0]:
            return
        try:
            application.set_browser(enabled.get_active(), persist=True)
        except (OSError, ValueError, VaultError):
            session.error("Browser integration could not start. Check your installation and try again.")
        changing[0] = True
        enabled.set_active(settings.browser)
        status()
        changing[0] = False
    enabled.connect("notify::active", changed)
    group.add(enabled)
    group.add(setup)
    page.add(group)
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
    dialog, _header, box = _dialog("Browser Setup", width=520, height=560)
    box.append(Gtk.Label(label="Enable Browser Integration in Preferences, then install KeePassXC-Browser in the browsers you select. Turning a browser off restores its previous connection settings.",
                         wrap=True, xalign=0))
    group = Adw.PreferencesGroup(title="Browsers")
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
            row.set_subtitle("Connected to Keyslot" if status["enabled"] else
                             "Another connection is configured" if status["exists"] else "Not configured")
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
            alert = Adw.AlertDialog(heading=f"Use Keyslot for {BROWSERS[browser]}?",
                body="This replaces the browser’s current KeePassXC connection. Its settings will be saved so you can restore them.")
            alert.add_response("cancel", "Cancel")
            alert.add_response("use", "Use Keyslot")
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
        session.toast("Entry deleted")

    def passkey_saved(self, session):
        session.window.show_vault(session.vault.snapshot)
        session.toast("Passkey saved")

    def passkey(self, session, data, done):
        registration = data["registration"]
        dialog, header, box = _dialog("Create Passkey" if registration else "Sign In with Passkey", width=520,
                                     height=620 if registration else 500)
        box.append(Gtk.Label(label="Create a passkey for this account." if registration else "Choose a passkey to sign in.",
                             wrap=True, xalign=0))
        website = Adw.PreferencesGroup(title="Website")
        website.add(Adw.ActionRow(title=website_origin(data["origin"]), subtitle="Website requesting a passkey", use_markup=False))
        website.add(Adw.ActionRow(title=data["rp"], subtitle="Passkey domain", use_markup=False))
        box.append(website)
        selected = {}
        if registration:
            account = Adw.PreferencesGroup(title="Account")
            account.add(Adw.ActionRow(title=data.get("username") or data.get("display_name") or "Unnamed Account",
                subtitle=data.get("display_name") or "", use_markup=False))
            box.append(account)
            entries = [None] + [entry for entry in session.vault.snapshot.entries if not entry.recycled]
            targets = Adw.ComboRow(title="Save To", model=Gtk.StringList.new(["New Entry"] +
                [(entry.title or "Untitled Entry") + " · " + (entry.username or entry.group_path) for entry in entries[1:]]))
            destination = Adw.PreferencesGroup()
            destination.add(targets)
            groups = [None] + [group for group in session.vault.snapshot.groups if not group.recycled]
            group_row = Adw.ComboRow(title="Group", model=Gtk.StringList.new([data["group_path"] + " (Default)"] +
                                     [group.path for group in groups[1:]]))
            destination.add(group_row)
            targets.connect("notify::selected", lambda *_: group_row.set_visible(targets.get_selected() == 0))
            box.append(destination)
        else:
            accounts = Adw.PreferencesGroup(title="Accounts")
            first = None
            for entry in data["entries"]:
                row = Adw.ActionRow(title=entry["username"] or entry["title"] or "Unnamed Account",
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
        approve = Gtk.Button(label="Create" if registration else "Sign In", valign=Gtk.Align.CENTER,
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
            timeout.set_label(f"Request expires in {seconds} seconds" if seconds else "Request expired")
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
                alert = Adw.AlertDialog(heading="Replace Existing Passkey?",
                    body="This entry already contains a passkey. Replacing it removes the current passkey from the entry.\n\n" + entry.title,
                    body_use_markup=False)
                alert.add_response("cancel", "Cancel")
                alert.add_response("replace", "Replace Passkey")
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
        dialog = Adw.AlertDialog(heading="Delete Entry Permanently?" if permanent else "Move Entry to Recycle Bin?",
            body=("The recycle bin is disabled. This entry and its saved history will be permanently removed.\n\n" if permanent
                  else "A browser wants to move this entry to the recycle bin.\n\n")
                 + (data["title"] or "Untitled Entry") + "\n" + data["group"], body_use_markup=False)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete Permanently" if permanent else "Move to Recycle Bin")
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
        session.toast("Login saved")

    def group_created(self, session):
        session.window.show_vault(session.vault.snapshot)
        session.toast("Group created")

    def create_group(self, session, data, done):
        dialog, header, box = _dialog("Create Group", width=440, height=300)
        box.append(Gtk.Label(label="A browser wants to create this group. Missing parent groups will also be created.",
                             wrap=True, xalign=0))
        group = Adw.PreferencesGroup()
        group.add(Adw.ActionRow(title=data["path"], subtitle=data["database"] or "Password Database",
                               use_markup=False, title_lines=3, subtitle_lines=2))
        box.append(group)
        cancel = Gtk.Button(label="Cancel", valign=Gtk.Align.CENTER)
        create = Gtk.Button(label="Create", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
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
        dialog, header, box = _dialog("Update Login" if updating else "Save Login", width=520, height=560)
        box.append(Gtk.Label(label="A browser wants to update this login." if updating else "A browser wants to save a new login.",
                             wrap=True, xalign=0))
        website = Adw.PreferencesGroup(title="Website")
        origin = website_origin(data["url"])
        website.add(Adw.ActionRow(title=origin, use_markup=False))
        if data["submit_url"] and website_origin(data["submit_url"]) != origin:
            website.add(Adw.ActionRow(title=website_origin(data["submit_url"]), subtitle="Sign-in form destination", use_markup=False))
        if updating and data["entry_url"] and website_origin(data["entry_url"]) != origin:
            website.add(Adw.ActionRow(title=website_origin(data["entry_url"]), subtitle="Current entry website", use_markup=False))
        box.append(website)
        entry = Adw.PreferencesGroup(title="Original Password Entry" if data["reference"] else "Entry")
        entry.add(Adw.ActionRow(title=data["title"] or "Untitled Entry", subtitle=data["group"] if updating else "New entry", use_markup=False))
        entry.add(Adw.ActionRow(title="Username", subtitle=data["username"] or "None", use_markup=False))
        entry.add(Adw.ActionRow(title="Password", subtitle="The browser supplied a password", use_markup=False))
        box.append(entry)
        group_ids = [""] + [item["uuid"] for item in data["groups"]]
        if not updating:
            choices = Gtk.StringList.new(["KeePassXC-Browser Passwords (Default)"] + [item["name"] for item in data["groups"]])
            group = Adw.ComboRow(title="Group", model=choices, selected=group_ids.index(data["selected_group"]))
            destination = Adw.PreferencesGroup()
            destination.add(group)
            box.append(destination)
        cancel = Gtk.Button(label="Cancel", valign=Gtk.Align.CENTER)
        save = Gtk.Button(label="Update Login" if updating else "Save Login", valign=Gtk.Align.CENTER,
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
            choose({"group": "" if updating else group_ids[group.get_selected()]})
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
        dialog, _header, box = _dialog("Connect Browser", width=440, height=360)
        box.append(Gtk.Label(label=data["database"] or "Password Database", wrap=True, css_classes=["title-2"]))
        box.append(Gtk.Label(label="A browser wants to connect to this database. Give the connection a name you can recognize later.",
                             wrap=True, xalign=0))
        group = Adw.PreferencesGroup()
        name = Adw.EntryRow(title="Connection Name")
        group.add(name)
        box.append(group)
        connect = Gtk.Button(label="Connect Browser", sensitive=False, css_classes=["suggested-action", "pill"])
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
            alert = Adw.AlertDialog(heading="Replace Browser Connection?",
                body=f'“{identifier}” is already connected. Replacing it will require the previous browser to connect again.')
            alert.add_response("cancel", "Cancel")
            alert.add_response("replace", "Replace Connection")
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
        dialog, _header, box = _dialog("Browser Access", width=520, height=520)
        box.append(Gtk.Label(label="A browser wants credentials for this website. Choose which entries to share.", wrap=True, xalign=0))
        website = Adw.PreferencesGroup(title="Website")
        origin = website_origin(data["url"])
        website.add(Adw.ActionRow(title=origin, subtitle="HTTP authentication requires confirmation each time"
                                 if data.get("http_auth") else "Website requesting access", use_markup=False))
        form = website_origin(data["submit_url"]) if data["submit_url"] else origin
        if form != origin:
            website.add(Adw.ActionRow(title=form, subtitle="Sign-in form destination", use_markup=False))
        box.append(website)
        group = Adw.PreferencesGroup(title="Entries")
        selected = {}
        for entry in data["entries"]:
            row = Adw.ActionRow(title=entry["title"] or "Untitled Entry",
                subtitle=entry["username"] or entry["group"], use_markup=False, title_lines=2, subtitle_lines=2)
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER, active=entry["allowed"] or len(data["entries"]) == 1)
            row.add_prefix(check)
            row.set_activatable_widget(check)
            group.add(row)
            selected[entry["uuid"]] = check
        box.append(group)
        permissions = Adw.PreferencesGroup()
        remember = Adw.SwitchRow(title="Remember This Decision", subtitle="Save access rules in this encrypted database")
        permissions.add(remember)
        box.append(permissions)
        buttons = Gtk.Box(spacing=12, homogeneous=True)
        deny = Gtk.Button(label="Deny All")
        allow = Gtk.Button(label="Allow Selected", css_classes=["suggested-action"])
        buttons.append(deny)
        buttons.append(allow)
        box.append(buttons)
        state, _dialogs, choose, dismiss = self._lifecycle(session, dialog, done)

        def update(*_):
            allow.set_sensitive(not state["answered"] and any(check.get_active() for check in selected.values()))

        def submit(approved):
            if state["closed"] or state["answered"]:
                return
            allow.set_sensitive(False)
            deny.set_sensitive(False)
            choose({"allow": approved, "selected": [uuid for uuid, check in selected.items() if check.get_active()],
                    "remember": remember.get_active()})
        for check in selected.values():
            check.connect("toggled", update)
        deny.connect("clicked", lambda *_: submit(False))
        allow.connect("clicked", lambda *_: submit(True))
        update()
        return dismiss
