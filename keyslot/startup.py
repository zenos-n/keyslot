"""Startup preferences contain paths and flags only; credentials live in libsecret."""
import json
import os
from pathlib import Path
import tempfile
import threading

from . import APP_ID

AUTO_TYPE_DEFAULTS = dict(match_title=True, match_url=True, hide_expired=False, relock=False,
                          delay=25, start_delay=500, retype_seconds=15, always_ask=True, skip_main_confirmation=False,
                          sort_column=0, sort_order=0, portal_mode=1, portal_connection=False, portal_clipboard=False)
SECRET_SERVICE_DEFAULTS = dict(enabled=False, confirm_access=True, confirm_delete=True, notify=True, unlock_before_search=True)
LOCK_DEFAULTS = dict(lock_on_screen=True, lock_on_user_switch=True, lock_on_minimize=False)
PRIVACY_DEFAULTS = dict(hide_usernames=False, hide_notes=False, hide_password_preview=True,
                        monospace_notes=False, password_empty_placeholder=False)
WINDOW_DEFAULTS = dict(hide_window_on_copy=False, minimize_on_copy=True, drop_to_background_on_copy=False,
                       minimize_after_unlock=False, minimize_to_background=False)
ENTRY_DEFAULTS = dict(inherit_group_icon=True, generate_password_on_create=False)
BEHAVIOR_DEFAULTS = dict(auto_save_non_data=True, show_expiry_warning=True, expiry_warning_days=3,
                         copy_on_double_click=False, url_double_click_action=0, language="system")


def _behavior_options(value):
    result = {name: value.get(name, default) for name, default in BEHAVIOR_DEFAULTS.items()}
    if (any(type(result[name]) is not bool for name in ("auto_save_non_data", "show_expiry_warning", "copy_on_double_click"))
            or type(result["expiry_warning_days"]) is not int or not 0 <= result["expiry_warning_days"] <= 90
            or type(result["url_double_click_action"]) is not int or result["url_double_click_action"] not in (0, 1, 2)
            or not isinstance(result["language"], str) or len(result["language"]) > 128 or "\0" in result["language"]):
        raise ValueError("Choose supported saving, expiry, field-action and language settings.")
    result["language"] = result["language"] or "system"
    return result


def _xdg_directory(name, fallback):
    value = os.environ.get(name, "")
    return Path(value) if value and Path(value).is_absolute() else Path.home() / fallback


def _autotype_options(value):
    connection_options = set(AUTO_TYPE_DEFAULTS) - {"portal_clipboard"}
    permission_options = connection_options - {"portal_connection"}
    sorted_options = permission_options - {"portal_mode"}
    previous = sorted_options - {"sort_column", "sort_order"}
    legacy = previous - {"always_ask", "skip_main_confirmation"}
    if isinstance(value, dict) and set(value) in (connection_options, permission_options, sorted_options, previous, legacy, legacy - {"retype_seconds"}):
        value = {**AUTO_TYPE_DEFAULTS, **value}
    if not isinstance(value, dict) or set(value) != set(AUTO_TYPE_DEFAULTS):
        raise ValueError("The auto-type settings are invalid.")
    for key in ("match_title", "match_url", "hide_expired", "relock", "always_ask", "skip_main_confirmation", "portal_connection", "portal_clipboard"):
        if type(value[key]) is not bool:
            raise ValueError("The auto-type switches are invalid.")
    for key, low, high in (("delay", 0, 500), ("start_delay", 100, 10000), ("retype_seconds", 0, 60)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError("Choose supported auto-type delays.")
    for key, high in (("sort_column", 3), ("sort_order", 1), ("portal_mode", 2)):
        if type(value[key]) is not int or not 0 <= value[key] <= high:
            raise ValueError("Choose supported Auto-Type sorting and keyboard permission settings.")
    return dict(value)


def _keeshare_options(value):
    if not isinstance(value, dict) or set(value) != {"import", "export"} or any(type(v) is not bool for v in value.values()):
        raise ValueError("The KeeShare settings are invalid.")
    return dict(value)


def _secret_service_options(value):
    if not isinstance(value, dict) or set(value) != set(SECRET_SERVICE_DEFAULTS) or any(type(v) is not bool for v in value.values()):
        raise ValueError("The Secret Service settings are invalid.")
    return dict(value)


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=".keyslot-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def _desktop_argument(value):
    value = str(value).replace("%", "%%")
    for char in ('\\', '"', '`', '$'):
        value = value.replace(char, '\\' + char)
    value = value.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')
    return '"' + value + '"'


class Startup:
    @property
    def lock_minutes(self):
        return (self.lock_seconds + 59) // 60

    @lock_minutes.setter
    def lock_minutes(self, value):
        self.lock_seconds = value * 60

    def __init__(self, config_home=None, launcher=None, storage=None):
        self.directory = Path(config_home) if config_home else _xdg_directory("XDG_CONFIG_HOME", ".config")
        self.autostart = self.directory / "autostart" / (APP_ID + ".desktop")
        self.storage = storage
        if storage:
            self.directory = storage.directory
        self.path = self.directory / "keyslot" / "startup.json"
        self.launcher = launcher
        self.mutex = threading.RLock()
        self.remember = self.login = False
        self.background = True
        self.browser = False
        self.browser_listing = False
        self.minimize_on_url = False
        self.auto_reload = True
        self.auto_save = self.auto_save_on_exit = True
        for name, value in BEHAVIOR_DEFAULTS.items():
            setattr(self, name, value)
        self.backup_before_save = False
        self.backup_path_pattern = "{DB_FILENAME}.old.kdbx"
        for name, value in LOCK_DEFAULTS.items():
            setattr(self, name, value)
        for name, value in PRIVACY_DEFAULTS.items():
            setattr(self, name, value)
        for name, value in WINDOW_DEFAULTS.items():
            setattr(self, name, value)
        for name, value in ENTRY_DEFAULTS.items():
            setattr(self, name, value)
        self.ssh = False
        self.ssh_socket = self.ssh_provider = ""
        self.autotype = dict(AUTO_TYPE_DEFAULTS)
        self.keeshare = {"import": False, "export": False}
        self.secret_service = dict(SECRET_SERVICE_DEFAULTS)
        self.lock_minutes = 5
        self.lock_seconds = 300
        self.clipboard_seconds = 20
        self.vault = None
        stored = storage.read_startup() if storage else None
        try:
            data = stored if storage else json.loads(self.path.read_text())
            self.background = data.get("background", True) is True
            self.browser = data.get("browser") is True
            self.browser_listing = data.get("browser_listing") is True
            self.minimize_on_url = data.get("minimize_on_url") is True
            self.auto_reload = data.get("auto_reload", True) is True
            self.auto_save = data.get("auto_save", True) is True
            self.auto_save_on_exit = data.get("auto_save_on_exit", True) is True
            for name, value in _behavior_options(data).items():
                setattr(self, name, value)
            self.backup_before_save = data.get("backup_before_save", False) is True
            pattern = data.get("backup_path_pattern", self.backup_path_pattern)
            if isinstance(pattern, str) and len(pattern) <= 16384 and "\0" not in pattern:
                self.backup_path_pattern = pattern
            for name, default in LOCK_DEFAULTS.items():
                value = data.get(name, default)
                if type(value) is bool:
                    setattr(self, name, value)
            for name, default in PRIVACY_DEFAULTS.items():
                value = data.get(name, default)
                if type(value) is bool:
                    setattr(self, name, value)
            for name, default in WINDOW_DEFAULTS.items():
                value = data.get(name, default)
                if type(value) is bool:
                    setattr(self, name, value)
            for name, default in ENTRY_DEFAULTS.items():
                value = data.get(name, default)
                if type(value) is bool:
                    setattr(self, name, value)
            self.ssh = data.get("ssh") is True
            try:
                self.autotype = _autotype_options(data.get("autotype", AUTO_TYPE_DEFAULTS))
            except ValueError:
                pass
            try:
                self.secret_service = _secret_service_options(data.get("secret_service", SECRET_SERVICE_DEFAULTS))
            except ValueError:
                pass
            try:
                self.keeshare = _keeshare_options(data.get("keeshare", self.keeshare))
            except ValueError:
                pass
            for field in ("ssh_socket", "ssh_provider"):
                value = data.get(field, "")
                if isinstance(value, str) and len(value) <= 4096 and not any(c in value for c in ("\0", "\n", "\r")):
                    if field != "ssh_socket" or not value or Path(value).is_absolute():
                        setattr(self, field, value)
                    else:
                        self.ssh = False
                else:
                    self.ssh = False
            timeout = data.get("lock_minutes", 5)
            if type(timeout) is int and 0 <= timeout <= 1440:
                self.lock_minutes = timeout
                self.lock_seconds = timeout * 60
            seconds = data.get("lock_seconds", self.lock_seconds)
            if type(seconds) is int and 0 <= seconds <= 86400:
                self.lock_seconds = seconds
            seconds = data.get("clipboard_seconds", 20)
            if type(seconds) is int and 0 <= seconds <= 3600:
                self.clipboard_seconds = seconds
            self.remember = data.get("remember") is True
            value = data.get("vault")
            if self.remember and isinstance(value, str) and Path(value).is_absolute():
                self.vault = Path(value)
            self.login = self.remember and self.vault is not None and data.get("login") is True
        except (OSError, ValueError, AttributeError):
            pass
        self.backup_policy_value = self.backup_before_save, self.backup_path_pattern
        self.save_policy_value = self.auto_save, self.auto_save_on_exit, self.auto_save_non_data

    def browser_listing_allowed(self):
        with self.mutex:
            if self.storage:
                value = self.storage.read_browser_listing()
            else:
                data = json.loads(self.path.read_text()) if self.path.exists() else {}
                if not isinstance(data, dict):
                    raise ValueError("The startup settings are invalid.")
                value = data.get("browser_listing", False)
            if type(value) is not bool:
                raise ValueError("The browser entry-list permission is invalid.")
            self.browser_listing = value
            return value

    def set_browser_listing(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("Choose whether paired browsers may list entries.")
        with self.mutex:
            if self.storage:
                self.storage.write_browser_listing(enabled)
            else:
                data = json.loads(self.path.read_text()) if self.path.exists() else {}
                if not isinstance(data, dict):
                    raise ValueError("The startup settings are invalid.")
                data["browser_listing"] = enabled
                _write(self.path, json.dumps(data) + "\n")
            self.browser_listing = enabled

    def save(self, remember, login, vault=None, background=None, lock_minutes=None, browser=None,
             ssh=None, ssh_socket=None, ssh_provider=None, autotype=None, keeshare=None, secret_service=None,
             minimize_on_url=None, lock_seconds=None, clipboard_seconds=None, auto_reload=None,
             auto_save=None, auto_save_on_exit=None, lock_on_screen=None, lock_on_user_switch=None, lock_on_minimize=None,
             backup_before_save=None, backup_path_pattern=None,
             auto_save_non_data=None, show_expiry_warning=None, expiry_warning_days=None,
             copy_on_double_click=None, url_double_click_action=None, language=None,
             hide_usernames=None, hide_notes=None, hide_password_preview=None, monospace_notes=None, password_empty_placeholder=None,
             hide_window_on_copy=None, minimize_on_copy=None, drop_to_background_on_copy=None,
             minimize_after_unlock=None, minimize_to_background=None,
             inherit_group_icon=None, generate_password_on_create=None):
        with self.mutex:
            behavior = _behavior_options({name: getattr(self, name) if value is None else value for name, value in (
                ("auto_save_non_data", auto_save_non_data), ("show_expiry_warning", show_expiry_warning),
                ("expiry_warning_days", expiry_warning_days), ("copy_on_double_click", copy_on_double_click),
                ("url_double_click_action", url_double_click_action), ("language", language))})
            locks = {name: getattr(self, name) if value is None else value for name, value in (
                ("lock_on_screen", lock_on_screen), ("lock_on_user_switch", lock_on_user_switch), ("lock_on_minimize", lock_on_minimize))}
            if any(type(value) is not bool for value in locks.values()):
                raise ValueError("Choose supported automatic locking switches.")
            privacy = {name: getattr(self, name) if value is None else value for name, value in (
                ("hide_usernames", hide_usernames), ("hide_notes", hide_notes), ("hide_password_preview", hide_password_preview),
                ("monospace_notes", monospace_notes), ("password_empty_placeholder", password_empty_placeholder))}
            if any(type(value) is not bool for value in privacy.values()):
                raise ValueError("Choose supported entry privacy switches.")
            windows = {name: getattr(self, name) if value is None else value for name, value in (
                ("hide_window_on_copy", hide_window_on_copy), ("minimize_on_copy", minimize_on_copy),
                ("drop_to_background_on_copy", drop_to_background_on_copy),
                ("minimize_after_unlock", minimize_after_unlock), ("minimize_to_background", minimize_to_background))}
            if any(type(value) is not bool for value in windows.values()):
                raise ValueError("Choose supported window behavior switches.")
            entries = {name: getattr(self, name) if value is None else value for name, value in (
                ("inherit_group_icon", inherit_group_icon), ("generate_password_on_create", generate_password_on_create))}
            if any(type(value) is not bool for value in entries.values()):
                raise ValueError("Choose supported new-entry switches.")
            background = self.background if background is None else bool(background)
            autotype = _autotype_options(self.autotype if autotype is None else autotype)
            keeshare = _keeshare_options(self.keeshare if keeshare is None else keeshare)
            secret_service = _secret_service_options(self.secret_service if secret_service is None else secret_service)
            browser = self.browser if browser is None else bool(browser)
            minimize_on_url = self.minimize_on_url if minimize_on_url is None else minimize_on_url
            auto_reload = self.auto_reload if auto_reload is None else auto_reload
            auto_save = self.auto_save if auto_save is None else auto_save
            auto_save_on_exit = self.auto_save_on_exit if auto_save_on_exit is None else auto_save_on_exit
            backup_before_save = self.backup_before_save if backup_before_save is None else backup_before_save
            backup_path_pattern = self.backup_path_pattern if backup_path_pattern is None else backup_path_pattern
            if (type(backup_before_save) is not bool or not isinstance(backup_path_pattern, str)
                    or len(backup_path_pattern) > 16384 or "\0" in backup_path_pattern):
                raise ValueError("Choose a supported backup switch and file path pattern.")
            if type(auto_save) is not bool or type(auto_save_on_exit) is not bool:
                raise ValueError("Choose whether to save vault changes automatically.")
            if type(auto_reload) is not bool:
                raise ValueError("Choose whether to reload externally changed vaults.")
            if type(minimize_on_url) is not bool:
                raise ValueError("Choose whether to minimize after opening links.")
            ssh = self.ssh if ssh is None else ssh
            ssh_socket = self.ssh_socket if ssh_socket is None else ssh_socket
            ssh_provider = self.ssh_provider if ssh_provider is None else ssh_provider
            if (type(ssh) is not bool or any(not isinstance(value, str) or len(value) > 4096
                    or any(c in value for c in ("\0", "\n", "\r")) for value in (ssh_socket, ssh_provider))
                    or (ssh_socket and not Path(ssh_socket).is_absolute())):
                raise ValueError("Choose an absolute SSH agent socket path, or leave it blank to use the session agent.")
            timeout = self.lock_minutes if lock_minutes is None else lock_minutes
            if type(timeout) is not int or not 0 <= timeout <= 1440:
                raise ValueError("Choose Never or a timeout between 1 and 1440 minutes.")
            seconds = self.lock_seconds if lock_minutes is None else timeout * 60
            seconds = seconds if lock_seconds is None else lock_seconds
            if type(seconds) is not int or not 0 <= seconds <= 86400:
                raise ValueError("Choose Never or an inactivity timeout between 1 and 86400 seconds.")
            timeout = (seconds + 59) // 60
            clipboard_seconds = self.clipboard_seconds if clipboard_seconds is None else clipboard_seconds
            if type(clipboard_seconds) is not int or not 0 <= clipboard_seconds <= 3600:
                raise ValueError("Choose Never or a clipboard timeout between 1 and 3600 seconds.")
            vault = Path(vault).expanduser().resolve() if remember and vault else None
            login = bool(login and remember and vault)
            if login and not self.launcher:
                raise ValueError("Install the packaged Keyslot application before enabling login unlock.")
            # shortcut: GLib cannot launch a percent sign in argv[0]; packaged Nix paths never contain one.
            if login and any(char in str(self.launcher) for char in ("%", "\n", "\r")):
                raise ValueError("The login launcher path cannot contain a percent sign or a newline.")
            old = self.autostart.read_text() if self.autostart.exists() else None
            if login:
                command = _desktop_argument(self.launcher)
                if self.storage:
                    for option, value in self.storage.launch_arguments:
                        command += " " + option + " " + _desktop_argument(value)
                _write(self.autostart, '[Desktop Entry]\nType=Application\nName=Keyslot\n'
                       f'Exec={command} --login --background\nIcon=keepassxc\nTerminal=false\n'
                       'OnlyShowIn=GNOME;\nX-GNOME-Autostart-enabled=true\n')
            else:
                self.autostart.unlink(missing_ok=True)
            try:
                data = {"remember": bool(remember), "login": login, "background": background, "lock_minutes": timeout, "browser": browser,
                       "browser_listing": self.browser_listing if self.storage else self.browser_listing_allowed(),
                       "ssh": ssh, "ssh_socket": ssh_socket, "ssh_provider": ssh_provider,
                       "autotype": autotype,
                       "keeshare": keeshare,
                       "secret_service": secret_service,
                       "minimize_on_url": minimize_on_url,
                       "vault": str(vault) if vault else None}
                data.update(locks)
                data.update(behavior)
                data["backup_before_save"] = backup_before_save
                data["backup_path_pattern"] = backup_path_pattern
                data.update(privacy)
                data.update(windows)
                data.update(entries)
                if seconds != timeout * 60:
                    data["lock_seconds"] = seconds
                if clipboard_seconds != 20:
                    data["clipboard_seconds"] = clipboard_seconds
                if not auto_reload:
                    data["auto_reload"] = False
                if not auto_save:
                    data["auto_save"] = False
                if not auto_save_on_exit:
                    data["auto_save_on_exit"] = False
                if self.storage:
                    self.storage.write_startup(data)
                else:
                    _write(self.path, json.dumps(data) + "\n")
            except Exception:
                if old is None:
                    self.autostart.unlink(missing_ok=True)
                else:
                    _write(self.autostart, old)
                raise
            self.remember, self.login, self.vault = bool(remember), login, vault
            self.background = background
            self.browser = browser
            self.minimize_on_url = minimize_on_url
            self.auto_reload = auto_reload
            self.auto_save, self.auto_save_on_exit = auto_save, auto_save_on_exit
            for name, value in behavior.items():
                setattr(self, name, value)
            self.save_policy_value = auto_save, auto_save_on_exit, self.auto_save_non_data
            self.backup_before_save, self.backup_path_pattern = backup_before_save, backup_path_pattern
            self.backup_policy_value = backup_before_save, backup_path_pattern
            for name, value in locks.items():
                setattr(self, name, value)
            for name, value in privacy.items():
                setattr(self, name, value)
            for name, value in windows.items():
                setattr(self, name, value)
            for name, value in entries.items():
                setattr(self, name, value)
            self.ssh, self.ssh_socket, self.ssh_provider = ssh, ssh_socket, ssh_provider
            self.autotype = autotype
            self.keeshare = keeshare
            self.secret_service = secret_service
            self.lock_minutes = timeout
            self.lock_seconds = seconds
            self.clipboard_seconds = clipboard_seconds

    def opened(self, path):
        with self.mutex:
            if self.remember:
                self.save(True, self.login, path)


class LoginKeyring:
    """Access only Keyslot items in GNOME's persistent login collection."""
    def __init__(self):
        import gi
        gi.require_version("Secret", "1")
        from gi.repository import Secret
        self.secret = Secret
        self.schema = Secret.Schema.new(APP_ID + ".Login", Secret.SchemaFlags.NONE,
            {"application": Secret.SchemaAttributeType.STRING, "vault": Secret.SchemaAttributeType.STRING})

    def _service(self, cancellable=None):
        from gi.repository import Gio, GLib
        connection = Gio.bus_get_sync(Gio.BusType.SESSION, cancellable)
        try:
            def current_owner():
                return connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner",
                    GLib.Variant("(s)", ("org.freedesktop.secrets",)), GLib.VariantType.new("(s)"),
                    Gio.DBusCallFlags.NONE, 5000, cancellable).unpack()[0]
            try:
                owner = current_owner()
            except GLib.Error as exc:
                if not exc.matches(Gio.DBusError, Gio.DBusError.NAME_HAS_NO_OWNER):
                    raise
                connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "StartServiceByName",
                    GLib.Variant("(su)", ("org.freedesktop.secrets", 0)), None, Gio.DBusCallFlags.NONE, 5000, cancellable)
                owner = current_owner()
            if owner == connection.get_unique_name():
                raise ValueError("GNOME login unlock is unavailable while Keyslot is the active password service. Unlock this vault manually.")
            # Pin every operation to this owner; a later provider switch must not receive the master credential.
            return self.secret.Service.open_sync(self.secret.Service.__gtype__, owner,
                self.secret.ServiceFlags.OPEN_SESSION | self.secret.ServiceFlags.LOAD_COLLECTIONS, cancellable)
        except GLib.Error as exc:
            raise ValueError("The GNOME login keyring is unavailable. Unlock the vault manually.") from exc

    def _collection(self, cancellable=None):
        service = self._service(cancellable)
        collections = service.get_collections() if service is not None else None
        if collections is None:
            raise ValueError("The GNOME login keyring is unavailable. Unlock the vault manually.")
        collection = next((item for item in collections
                           if item.get_object_path() == "/org/freedesktop/secrets/collection/login"), None)
        if collection is None:
            raise ValueError("The GNOME login keyring is unavailable. Unlock the vault manually.")
        if collection.get_locked():
            raise ValueError("The GNOME login keyring is locked. Unlock it in Passwords and Keys first.")
        # Collection holds only a weak service reference; retain the pinned owner for the entire operation.
        return service, collection

    def _attributes(self, path=None):
        result = {"application": APP_ID}
        if path is not None:
            result["vault"] = str(Path(path).expanduser().resolve())
        return result

    def store(self, path, credentials, cancellable=None):
        service, collection = self._collection(cancellable)
        value = self.secret.Value.new(json.dumps(credentials), -1, "text/plain")
        if not service.store_sync(self.schema, self._attributes(path), collection.get_object_path(),
                "Keyslot login unlock: " + Path(path).name, value, cancellable):
            raise ValueError("The vault credential could not be saved in the GNOME login keyring.")

    def lookup(self, path, cancellable=None):
        service, collection = self._collection(cancellable)
        items = collection.search_sync(self.schema, self._attributes(path), self.secret.SearchFlags.LOAD_SECRETS, cancellable)
        if not items or items[0].get_secret() is None:
            raise ValueError("No login credential is saved for this vault. Unlock it manually and enable login unlock in Preferences.")
        try:
            value = json.loads(items[0].get_secret().get_text())
            if (not isinstance(value, dict) or set(value) != {"password", "keyfile", "yubikey", "no_password"}
                    or any(not isinstance(value[key], str) for key in ("password", "keyfile", "yubikey"))
                    or type(value["no_password"]) is not bool):
                raise ValueError()
            return value
        except (TypeError, ValueError):
            raise ValueError("The saved vault credential is invalid. Configure login unlock again.") from None

    def clear(self, cancellable=None):
        service, collection = self._collection(cancellable)
        for item in collection.search_sync(self.schema, self._attributes(), self.secret.SearchFlags.NONE, cancellable):
            if not item.delete_sync(cancellable):
                raise ValueError("A saved Keyslot credential could not be removed from the login keyring.")
