"""Application-wide state and one native window per database."""
from pathlib import Path
import resource
import sys
import time

from .application import Adw, Gio, GLib, Gtk, Vault, VaultSession, VaultError, INTERFACE, OBJECT_PATH, DBUS_XML
from . import APP_ID, ICON_NAME, database_views, preferences, passkey_views, autotype_views, command_line as gui_cli
from .startup import Startup, LoginKeyring

SHORTCUTS = {
    "open": ["<Primary>o"], "new": ["<Primary><Shift>n"], "new-entry": ["<Primary>n"],
    "search": ["<Primary>f"], "lock": ["<Primary>l"], "generator": ["<Primary>g"],
    "refresh": ["<Primary>r"], "save-copy": ["<Primary><Shift>s"], "close": ["<Primary>w"],
    "shortcuts": ["<Primary>question"],
    "preferences": ["<Primary>comma"],
    "autotype": ["<Primary><Shift>v"],
    "open-url": ["<Primary>u"],
}


class Keyslot(Adw.Application):
    def __init__(self):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_OPEN | Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        executable = Path(sys.argv[0]).resolve().parent / "keyslot"
        self.startup = Startup(launcher=str(executable) if executable.is_file() else None)
        self.keyring = None
        self.browser = None
        from .ssh_integration import SSHIntegration
        self.ssh = SSHIntegration(self, GLib.idle_add)
        from .keeshare import KeeShareIntegration
        self.keeshare = KeeShareIntegration(self)
        self.secrets = None
        self.secret_service_error = ""
        self._native_hosts = None
        self.login_attempted = False
        self.background_enabled = False
        self.command_requests = set()
        gui_cli.configure(self)
        self.add_main_option("login", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Unlock the remembered vault using the login keyring", None)
        self.add_main_option("background", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Run without opening a window", None)
        self._initial_vault = Vault()
        self.window = None
        self.sessions = []
        self.active_session = None
        self.last_activity = time.monotonic()
        self.screen_subscription = self.sleep_subscription = 0
        self.connect("startup", self._startup)
        self.connect("activate", self._activate)
        self.connect("open", self._open_files)
        self.connect("shutdown", self._shutdown)
        self.connect("command-line", self._command_line)

    @property
    def locked(self):
        return not any(session.vault.unlocked for session in self.sessions)

    @property
    def busy(self):
        return any(session.busy for session in self.sessions)

    @property
    def background(self):
        return self.background_enabled and not any(session.host_window.get_visible() for session in self.sessions)

    def set_background(self, enabled, persist=False):
        if persist:
            self.startup.save(self.startup.remember, self.startup.login, self.startup.vault, background=enabled)
        if enabled != self.background_enabled:
            self.background_enabled = enabled
            (self.hold if enabled else self.release)()
        if not enabled and self.sessions and not any(item.host_window.get_visible() for item in self.sessions):
            self.select_session(self.active_session or self.sessions[0])
        self.emit_state()

    def native_hosts(self):
        if self._native_hosts is None:
            from .browser_hosts import NativeHosts
            import os
            self._native_hosts = NativeHosts(os.environ.get("KEYSLOT_BROWSER_PROXY") or
                Path(os.environ["KEYSLOT_ENGINE"]).parent / "keepassxc-proxy")
        return self._native_hosts

    def set_browser(self, enabled, persist=False):
        previous = self.startup.browser
        if persist:
            with self.startup.mutex:
                self.startup.save(self.startup.remember, self.startup.login, self.startup.vault, browser=enabled)
        try:
            if self.browser and (not enabled or self.browser.pipe.closed):
                self.browser.close()
                self.browser = None
            if enabled and self.browser is None:
                from .browser_transport import BrowserIntegration
                from .browser_dialogs import BrowserDialogs
                self.browser = BrowserIntegration(self, BrowserDialogs(self))
        except Exception:
            if persist:
                with self.startup.mutex:
                    self.startup.save(self.startup.remember, self.startup.login, self.startup.vault, browser=previous)
            raise
        self.emit_state()

    def _startup(self, *_):
        Gtk.Window.set_default_icon_name(ICON_NAME)
        self.set_background(self.startup.background)
        if self.startup.login and self.startup.launcher:
            # Refresh the launcher path after a package upgrade.
            try:
                self.startup.save(True, True, self.startup.vault)
            except OSError:
                self.startup_error = "The login launcher could not be updated. Check your configuration folder’s permissions."
        for name, callback, keys in [("new-window", self.new_window, []),
                                     ("lock-all", self.lock, ["<Primary><Shift>l"]),
                                     ("quit", self.quit, ["<Primary>q"])]:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda _a, _p, callback=callback: callback())
            self.add_action(action)
            self.set_accels_for_action("app." + name, keys)
        for name, keys in SHORTCUTS.items():
            self.set_accels_for_action("win." + name, keys)
        self.connection = self.get_dbus_connection()
        if self.connection is None:
            raise RuntimeError("A session D-Bus connection is required.")
        info = Gio.DBusNodeInfo.new_for_xml(DBUS_XML).interfaces[0]
        self.dbus_registration = self.connection.register_object(OBJECT_PATH, info, self._dbus_call, self._dbus_property, None)
        self.screen_subscription = self.connection.signal_subscribe("org.gnome.ScreenSaver", "org.gnome.ScreenSaver",
            "ActiveChanged", "/org/gnome/ScreenSaver", None, Gio.DBusSignalFlags.NONE,
            lambda _c, _s, _p, _i, _n, params: self.lock() if params.unpack()[0] else None)
        Gio.bus_get(Gio.BusType.SYSTEM, None, self._system_bus_ready)
        GLib.timeout_add_seconds(5, self._idle_check)
        GLib.timeout_add_seconds(1, self._ssh_check)
        GLib.timeout_add_seconds(5, self._keeshare_check)
        if self.startup.ssh:
            self.ssh.start()
        if self.startup.secret_service["enabled"]:
            try:
                self.set_secret_service(self.startup.secret_service, persist=False)
            except (VaultError, GLib.Error, OSError) as exc:
                self.secret_service_error = str(exc)
                self.startup_error = str(exc)
        if self.startup.browser:
            try:
                self.native_hosts().refresh()
            except (OSError, ValueError, VaultError):
                self.startup_error = "Browser setup could not be updated. Review Browser Setup in Preferences."
            try:
                self.set_browser(True)
            except (OSError, ValueError, VaultError):
                self.startup_error = "Browser integration could not start. Review Browser Setup in Preferences."
        self.emit_state()

    def _system_bus_ready(self, _source, result):
        try:
            self.system_bus = Gio.bus_get_finish(result)
            self.sleep_subscription = self.system_bus.signal_subscribe("org.freedesktop.login1",
                "org.freedesktop.login1.Manager", "PrepareForSleep", "/org/freedesktop/login1", None,
                Gio.DBusSignalFlags.NONE, lambda _c, _s, _p, _i, _n, params: self.lock() if params.unpack()[0] else None)
        except GLib.Error:
            pass

    def _dbus_property(self, _connection, _sender, _path, _interface, prop):
        return GLib.Variant("b", self.busy if prop == "Busy" else self.background if prop == "Background" else self.locked)

    def _dbus_call(self, _connection, _sender, _path, _interface, method, _params, invocation):
        if method == "Show":
            self.activate()
        elif method == "Lock":
            self.lock()
        elif method == "Quit":
            GLib.idle_add(lambda: (self.quit(), False)[1])
        elif method == "AutoType":
            session = self.active_session or next(iter(self.sessions), None)
            if session and session.vault.unlocked:
                autotype_views.choose(session)
            else:
                self.activate()
        else:
            invocation.return_dbus_error(INTERFACE + ".UnknownMethod", "Unknown method")
            return
        invocation.return_value(None)

    def emit_state(self):
        if secrets := getattr(self, "secrets", None):
            secrets.state_changed()
        if keeshare := getattr(self, "keeshare", None):
            keeshare.state_changed()
        if ssh := getattr(self, "ssh", None):
            ssh.state_changed()
        if browser := getattr(self, "browser", None):
            browser.state_changed()
        for session in self.sessions:
            editable = session.vault.unlocked and not session.busy
            for name in ("new-entry", "search", "refresh", "settings", "change-key", "merge", "export", "save-copy", "reports"):
                if action := session.host_window.lookup_action(name):
                    action.set_enabled(editable)
            if action := session.host_window.lookup_action("lock"):
                action.set_enabled(session.vault.unlocked or session.busy)
        if action := self.lookup_action("lock-all"):
            action.set_enabled(not self.locked or self.busy)
        if getattr(self, "connection", None):
            self.connection.emit_signal(None, OBJECT_PATH, "org.freedesktop.DBus.Properties", "PropertiesChanged",
                GLib.Variant("(sa{sv}as)", (INTERFACE, {"Locked": GLib.Variant("b", self.locked),
                    "Busy": GLib.Variant("b", self.busy), "Background": GLib.Variant("b", self.background)}, [])))

    def update_session(self, session):
        if session.host_window:
            path = session.path
            title = session.vault.snapshot.name if session.vault.unlocked else ""
            title = title or (path.name if path else "Keyslot")
            if session.needs_attention:
                title += " · Action Needed"
            session.host_window.set_title(title if title == "Keyslot" else title + " — Keyslot")
        self.emit_state()

    def _activate(self, *_):
        if not self.sessions:
            if self.startup.remember and self.startup.vault:
                self.open_database(self.startup.vault)
            else:
                self.new_window()
        else:
            self.select_session(self.active_session or self.sessions[0])

    def _command_line(self, _application, command_line):
        options = command_line.get_options_dict()
        arguments = gui_cli.arguments(options)
        background_requested = options.contains("background") or options.contains("minimized")
        if background_requested:
            self.set_background(True)
        if options.contains("login"):
            if self.startup.login and self.startup.vault and not self.login_attempted:
                self.login_attempted = True
                path = self.startup.vault
                existing = next((item for item in self.sessions if item.path == path), None)
                if existing:
                    self.select_session(existing)
                else:
                    session = self.new_window(present=not self.background_enabled)
                    if not self.active_session:
                        self.active_session = session
                        self.window = session.host_window
                    session.requested_path = path
                    session.unlock_at_login(path)
            return 0
        if background_requested and not arguments:
            if not self.sessions:
                session = self.new_window(present=False)
                self.active_session, self.window = session, session.host_window
                session.requested_path = self.startup.vault
            self.emit_state()
            return 0
        key_option = options.lookup_value("keyfile", None)
        keyfile = command_line.create_file_for_arg(key_option.unpack()).get_path() if key_option else ""
        if key_option and not keyfile:
            command_line.printerr_literal("The key file must be a local file.\n")
            return 1
        paths = []
        for argument in arguments:
            path = command_line.create_file_for_arg(argument).get_path()
            if not path:
                command_line.printerr_literal("The database must be a local file.\n")
                return 1
            paths.append(path)
        if options.contains("pw-stdin"):
            gui_cli.PasswordInput(self, command_line, paths, keyfile, background_requested)
            return 0
        if arguments:
            for path in paths:
                self.open_database(path, keyfile=keyfile, present=not background_requested)
        else:
            self.activate()
        return 0

    def login_keyring(self):
        if self.keyring is None:
            self.keyring = LoginKeyring()
        return self.keyring

    def new_window(self, present=True):
        window = MainWindow(self)
        session = VaultSession(self, self._initial_vault, host_window=window)
        self._initial_vault = None
        window.attach(session)
        self.sessions.append(session)
        self.update_session(session)
        if present:
            self.select_session(session)
        if message := getattr(self, "startup_error", None):
            self.startup_error = None
            GLib.idle_add(lambda: (session.error(message), False)[1])
        return session

    def select_session(self, session, activate=True):
        self.active_session = session
        self.window = session.host_window
        session.host_window.present()
        if activate:
            session.activate()
        self.update_session(session)

    def open_database(self, path, create=False, import_options=None, preferred=None, *, keyfile="", present=True, defer_unlock=False):
        if not self.sessions:
            preferred = self.new_window(present=False)
            self.active_session, self.window = preferred, preferred.host_window
        requested = Path(path).expanduser().absolute()
        canonical = requested.resolve()
        if create and (requested.exists() or requested.is_symlink()):
            self.active_session.error("Choose a new database file. An existing file cannot be replaced.")
            return
        session = next((item for item in self.sessions if item.path and item.path.resolve() == canonical), None)
        if session:
            if create:
                self.active_session.error("This database is already open in another window.")
                return
            if present:
                if defer_unlock:
                    self.select_session(session, activate=False)
                else:
                    self.select_session(session)
            if session.vault.unlocked or session.busy:
                return session
        else:
            candidate = preferred or self.active_session
            session = candidate if candidate and candidate.path is None and not candidate.busy and not candidate.dialogs else self.new_window(present=False)
        session.requested_path = canonical
        if not defer_unlock:
            session.pending_unlock = (str(canonical), create, import_options, keyfile)
        self.update_session(session)
        if present:
            if defer_unlock:
                self.select_session(session, activate=False)
            else:
                self.select_session(session)
        elif not self.active_session:
            self.active_session, self.window = session, session.host_window
        return session

    def _open_files(self, _app, files, _hint):
        for file in files:
            if path := file.get_path():
                self.open_database(path)

    def close_session(self, session):
        if session not in self.sessions:
            return
        session.shutdown()
        self.sessions.remove(session)
        if self.active_session is session:
            self.active_session = self.sessions[0] if self.sessions else None
            self.window = self.active_session.host_window if self.active_session else None
        self.emit_state()

    def lock(self):
        for request in list(self.command_requests):
            request.cancel()
        for session in list(self.sessions):
            session.lock()
        self.emit_state()

    def touch(self, *_):
        self.last_activity = time.monotonic()

    def _idle_check(self):
        timeout = getattr(self.startup, "lock_seconds", self.startup.lock_minutes * 60)
        if timeout and (not self.locked or self.busy) and time.monotonic() - self.last_activity >= timeout:
            self.lock()
        return GLib.SOURCE_CONTINUE

    def _shutdown(self, *_):
        for request in list(self.command_requests):
            request.cancel()
        gui_cli.restore_echo(self)
        if self.secrets:
            self.secrets.close()
            self.secrets = None
        self.keeshare.close()
        if self.browser:
            self.browser.close()
            self.browser = None
        if not self.ssh.close():
            message = "SSH key cleanup was not confirmed. Review and remove remaining keys in your SSH agent."
            notification = Gio.Notification.new("SSH Key Cleanup Failed")
            notification.set_body(message)
            self.send_notification("ssh-cleanup", notification)
            print(message, file=sys.stderr)
        for session in list(self.sessions):
            session.shutdown()
        self.sessions.clear()
        if self.screen_subscription:
            self.connection.signal_unsubscribe(self.screen_subscription)
        if self.sleep_subscription:
            self.system_bus.signal_unsubscribe(self.sleep_subscription)
        if getattr(self, "dbus_registration", 0):
            self.connection.unregister_object(self.dbus_registration)

    def set_ssh(self, enabled, socket=None, provider=None):
        previous = self.startup.ssh, self.startup.ssh_socket, self.startup.ssh_provider
        self.startup.save(self.startup.remember, self.startup.login, self.startup.vault,
                          ssh=enabled, ssh_socket=socket, ssh_provider=provider)
        if not enabled:
            self.ssh.stop()
        elif previous != (self.startup.ssh, self.startup.ssh_socket, self.startup.ssh_provider):
            self.ssh.restart()
        else:
            self.ssh.start()

    def set_secret_service(self, options, persist=True):
        if persist:
            self.startup.save(self.startup.remember, self.startup.login, self.startup.vault, secret_service=options)
        self.secret_service_error = ""
        if not options["enabled"]:
            if self.secrets:
                self.secrets.close()
                self.secrets = None
        elif self.secrets and not self.secrets.closed:
            self.secrets.state_changed()
        else:
            from .secret_service import SecretService
            try:
                self.secrets = SecretService(self)
            except Exception as exc:
                self.secret_service_error = str(exc)
                raise

    def _ssh_check(self):
        if self.ssh.closed:
            return GLib.SOURCE_REMOVE
        self.ssh.check()
        return GLib.SOURCE_CONTINUE

    def _keeshare_check(self):
        if self.keeshare.closed:
            return GLib.SOURCE_REMOVE
        self.keeshare.state_changed()
        return GLib.SOURCE_CONTINUE


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, application):
        super().__init__(application=application, title="Keyslot", default_width=1180, default_height=760)
        self.app = application
        self.session = None
        self.set_size_request(360, 400)
        self.connect("close-request", self._close)
        self.connect("notify::is-active", self._focused)
        self.connect("notify::visible", lambda *_: application.emit_state())
        motion = Gtk.EventControllerMotion()
        motion.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        motion.connect("motion", application.touch)
        self.add_controller(motion)
        keys = Gtk.EventControllerKey()
        keys.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        keys.connect("key-pressed", lambda *_: (application.touch(), False)[1])
        self.add_controller(keys)
        clicks = Gtk.GestureClick()
        clicks.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        clicks.connect("pressed", application.touch)
        self.add_controller(clicks)

    def attach(self, session):
        self.session = session
        self.set_content(session.window)
        for name, method in [("open", "choose_database"), ("new", "new_database"), ("lock", "lock"),
                             ("new-entry", "edit_entry"), ("search", "focus_search"), ("generator", "generator"),
                             ("refresh", "refresh"), ("about", "about"), ("shortcuts", "shortcuts"), ("open-url", "open_entry_url")]:
            self._action(name, lambda method=method: getattr(session, method)())
        for name, method in [("import", "import_database"), ("settings", "settings"), ("change-key", "change_key"),
                             ("merge", "merge"), ("export", "export"), ("save-copy", "save_copy"), ("reports", "report")]:
            self._action(name, lambda method=method: getattr(database_views, method)(session))
        self._action("close", self.close)
        self._action("preferences", lambda: preferences.show(session))
        self._action("passkeys", lambda: passkey_views.manage(session))
        self._action("autotype", lambda: autotype_views.choose(session))

    def _action(self, name, callback):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", lambda *_: callback())
        self.add_action(action)

    def menu(self):
        menu = Gio.Menu()
        opening = Gio.Menu()
        for label, action in [("New Window", "app.new-window"), ("Open Database…", "win.open"), ("New Database…", "win.new")]:
            opening.append(label, action)
        menu.append_section(None, opening)
        database = Gio.Menu()
        for actions in [[("Database Settings…", "settings"), ("Change Unlock Key…", "change-key"), ("Refresh", "refresh")],
                        [("Import Database…", "import"), ("Save Copy…", "save-copy"), ("Merge Database…", "merge"),
                         ("Export Unencrypted Data…", "export"), ("Reports…", "reports")],
                        [("Passkeys…", "passkeys"), ("Lock Database", "lock")]]:
            section = Gio.Menu()
            for label, action in actions:
                section.append(label, "win." + action)
            database.append_section(None, section)
        database.append("Lock All Databases", "app.lock-all")
        tools = Gio.Menu()
        tools.append_submenu("Database", database)
        tools.append("Password Generator", "win.generator")
        tools.append("Auto-Type…", "win.autotype")
        menu.append_section(None, tools)
        help_menu = Gio.Menu()
        help_menu.append("Preferences", "win.preferences")
        help_menu.append("Keyboard Shortcuts", "win.shortcuts")
        help_menu.append("About Keyslot", "win.about")
        menu.append_section(None, help_menu)
        return Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="Main Menu")

    def _focused(self, *_):
        if self.session and self.is_active():
            self.app.active_session = self.session
            self.app.window = self

    def _close(self, *_):
        if self.app.background_enabled:
            self.set_visible(False)
            self.app.emit_state()
            return True

        if self.session:
            self.app.close_session(self.session)
        return False
