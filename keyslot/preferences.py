"""GNOME startup preferences and explicit login-keyring enrollment."""
from pathlib import Path

from .application import Adw, Gio, Gtk, button, margins, scroll


def show(session):
    from .browser_dialogs import add_preferences
    from .ssh_views import add_preferences as ssh_preferences
    if session.application.busy:
        session.toast("Wait for the current operation to finish")
        return
    settings = session.application.startup
    dialog = Adw.PreferencesDialog(title="Preferences")
    page = Adw.PreferencesPage()
    group = Adw.PreferencesGroup(title="Startup")
    remember = Adw.SwitchRow(title="Remember Last Opened Vault",
        subtitle="Open its unlock screen when Keyslot starts", active=settings.remember)
    login = Adw.SwitchRow(title="Unlock at Login",
        subtitle="Save the vault credential in the GNOME login keyring", active=settings.login,
        sensitive=settings.remember)
    group.add(remember)
    group.add(login)
    background = Adw.SwitchRow(title="Run in Background",
        subtitle="Keep vaults available when windows close; use Quit to exit", active=settings.background)
    group.add(background)
    def changed_background(*_):
        try:
            session.application.set_background(background.get_active(), persist=True)
        except (OSError, ValueError) as exc:
            session.error(str(exc))
            background.set_active(settings.background)
    background.connect("notify::active", changed_background)
    forget = Adw.ActionRow(title="Forget Login Credentials",
        subtitle="Disable login unlock and remove Keyslot’s saved credentials")
    group.add(forget)
    page.add(group)
    security = Adw.PreferencesGroup(title="Security",
        description="Screen lock and suspend still lock your vaults.")
    timeouts = [0, 1, 5, 10, 15, 30, 60]
    timeout = Adw.ComboRow(title="Lock When Inactive", model=Gtk.StringList.new([
        "Never", "1 Minute", "5 Minutes", "10 Minutes", "15 Minutes", "30 Minutes", "1 Hour", "Custom…"]))
    timeout.set_selected(timeouts.index(settings.lock_minutes) if settings.lock_minutes in timeouts else len(timeouts))
    custom = Adw.SpinRow.new_with_range(1, 1440, 1)
    custom.set_title("Inactivity Timeout (Minutes)")
    custom.set_value(settings.lock_minutes or 5)
    custom.set_visible(timeout.get_selected() == len(timeouts))
    def changed_timeout(*_):
        selected = timeout.get_selected()
        custom.set_visible(selected == len(timeouts))
        minutes = timeouts[selected] if selected < len(timeouts) else int(custom.get_value())
        try:
            settings.save(settings.remember, settings.login, settings.vault, lock_minutes=minutes)
            session.application.touch()
        except (OSError, ValueError) as exc:
            session.error(str(exc))
    timeout.connect("notify::selected", changed_timeout)
    custom.connect("notify::value", changed_timeout)
    security.add(timeout)
    security.add(custom)
    quick = Adw.ActionRow(title="Quick Unlock",
        subtitle="Use a short password until Keyslot quits; the master password stays unchanged")
    setup = button("document-edit-symbolic", "Set Up Quick Unlock", lambda: (dialog.force_close(), enroll(session, quick=True)))
    setup.set_sensitive(session.vault.unlocked)
    quick.add_suffix(setup)
    if session.quick_blob:
        quick.add_suffix(button("edit-delete-symbolic", "Disable Quick Unlock",
                                lambda: (setattr(session, "quick_blob", None), dialog.close())))
    security.add(quick)
    page.add(security)
    add_preferences(session, page, dialog)
    ssh_preferences(session, page, dialog)
    dialog.add(page)
    updating = [False]
    def refresh():
        updating[0] = True
        remember.set_active(settings.remember)
        login.set_active(settings.login)
        login.set_sensitive(settings.remember)
        updating[0] = False
    def clear_saved():
        session.run_keyring_job(lambda request: session.application.login_keyring().clear(request))
    def forget_saved():
        if session.application.busy:
            return
        try:
            settings.save(settings.remember, False, settings.vault)
            clear_saved()
        except (OSError, ValueError) as exc:
            session.error(str(exc))
        refresh()
    forget.add_suffix(button("edit-delete-symbolic", "Forget Saved Login Credentials", forget_saved))
    def changed_remember(*_):
        if updating[0]:
            return
        if session.application.busy:
            refresh()
            return
        previous_login = settings.login
        try:
            settings.save(remember.get_active(), settings.login, session.path or settings.vault)
            if previous_login and not settings.login:
                clear_saved()
        except (OSError, ValueError) as exc:
            session.error(str(exc))
        refresh()
    def changed_login(*_):
        if updating[0]:
            return
        if session.application.busy:
            refresh()
            return
        if login.get_active():
            refresh()
            if not session.vault.unlocked:
                session.error("Unlock the vault first, then enable Unlock at Login.")
                return
            dialog.force_close()
            enroll(session)
        else:
            try:
                # Disable autostart even if removing the keyring item subsequently fails.
                settings.save(settings.remember, False, settings.vault)
                clear_saved()
            except (OSError, ValueError) as exc:
                session.error(str(exc))
            refresh()
    remember.connect("notify::active", changed_remember)
    login.connect("notify::active", changed_login)
    session.present_dialog(dialog)


def enroll(session, quick=False):
    if not session.vault.unlocked or session.busy:
        return
    path = session.vault.path
    dialog = Adw.Dialog(title="Set Up Quick Unlock" if quick else "Unlock at Login", content_width=440)
    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(Adw.HeaderBar())
    box = margins(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18), 24)
    box.append(Gtk.Label(label=path.name, css_classes=["title-2"], wrap=True))
    explanation = ("Confirm the master credential and choose a short password. Quick unlock is available until Keyslot quits. "
                   "Five failed attempts require the master password." if quick else
                   "Confirm this vault’s unlock credential to save it in your GNOME login keyring. "
                   "It will be used once when you sign in. Hardware keys may still require a touch.")
    box.append(Gtk.Label(label=explanation, wrap=True))
    group = Adw.PreferencesGroup()
    password = Adw.PasswordEntryRow(title="Master Password")
    keyfile = Adw.ActionRow(title="Key File", subtitle="None selected")
    selected_key = [""]
    def set_key(value):
        selected_key[0] = value
        keyfile.set_subtitle(Path(value).name if value else "None selected")
    keyfile.add_suffix(button("document-open-symbolic", "Choose Key File", lambda: session.choose_file(set_key)))
    keyfile.add_suffix(button("edit-clear-symbolic", "Clear Key File", lambda: set_key("")))
    hardware = Adw.EntryRow(title="Hardware Key Slot (optional)")
    key_only = Adw.SwitchRow(title="Key File / Hardware Key Only")
    key_only.connect("notify::active", lambda *_: password.set_sensitive(not key_only.get_active()))
    for row in (password, keyfile, hardware, key_only):
        group.add(row)
    box.append(group)
    short = Adw.PasswordEntryRow(title="Short Password")
    repeat = Adw.PasswordEntryRow(title="Repeat Short Password")
    if quick:
        short_group = Adw.PreferencesGroup(title="Quick Unlock Password")
        short_group.add(short)
        short_group.add(repeat)
        box.append(short_group)
    status = Gtk.Label(wrap=True, xalign=0, visible=False, css_classes=["error"])
    box.append(status)
    save = Gtk.Button(label="Enable Quick Unlock" if quick else "Enable Login Unlock", css_classes=["suggested-action", "pill"])
    box.append(save)
    state = {"closed": False}
    def failed(message):
        if state["closed"]:
            return
        box.set_sensitive(True)
        status.set_label(message)
        status.set_visible(True)
    def submit(*_):
        if session.busy:
            return
        pin = short.get_text()
        if quick and (not 4 <= len(pin) <= 128 or pin != repeat.get_text()):
            failed("Choose matching short passwords with 4 to 128 characters.")
            return
        credentials = {"password": "" if key_only.get_active() else password.get_text(),
                       "keyfile": selected_key[0], "yubikey": hardware.get_text(), "no_password": key_only.get_active()}
        status.set_visible(False)
        box.set_sensitive(False)
        def configure(request):
            session.vault.verify_credentials(**credentials)
            keyring = session.application.login_keyring()
            keyring.store(path, credentials, request)
            if request.is_cancelled():
                keyring.clear()
                request.set_error_if_cancelled()
            session.application.startup.save(True, True, path)
        def configured(_):
            if state["closed"]:
                return
            dialog.close()
            session.toast("Vault will unlock from the login keyring when you sign in")
        if quick:
            def sealed(blob):
                if state["closed"]:
                    return
                session.quick_blob, session.quick_path, session.quick_attempts = blob, path, 0
                dialog.close()
                session.toast("Quick unlock is available until Keyslot quits")
            session.run_job(lambda: session.vault.seal_quick_unlock(credentials, pin), sealed, failed)
        else:
            session.run_keyring_job(configure, configured, failed)
    save.connect("clicked", submit)
    password.connect("entry-activated", submit)
    def closed(*_):
        state["closed"] = True
        password.set_text("")
        short.set_text("")
        repeat.set_text("")
    dialog.connect("closed", closed)
    toolbar.set_content(scroll(box, natural=True))
    dialog.set_child(toolbar)
    session.present_dialog(dialog)
    password.grab_focus()
