"""Startup preferences contain paths and flags only; credentials live in libsecret."""
import json
import os
from pathlib import Path
import tempfile
import threading

from . import APP_ID


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


class Startup:
    def __init__(self, config_home=None, launcher=None):
        self.directory = Path(config_home or os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        self.path = self.directory / "keyslot" / "startup.json"
        self.autostart = self.directory / "autostart" / (APP_ID + ".desktop")
        self.launcher = launcher
        self.mutex = threading.RLock()
        self.remember = self.login = False
        self.background = True
        self.browser = False
        self.ssh = False
        self.ssh_socket = self.ssh_provider = ""
        self.lock_minutes = 5
        self.vault = None
        try:
            data = json.loads(self.path.read_text())
            self.background = data.get("background", True) is True
            self.browser = data.get("browser") is True
            self.ssh = data.get("ssh") is True
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
            self.remember = data.get("remember") is True
            value = data.get("vault")
            if self.remember and isinstance(value, str) and Path(value).is_absolute():
                self.vault = Path(value)
            self.login = self.remember and self.vault is not None and data.get("login") is True
        except (OSError, ValueError, AttributeError):
            pass

    def save(self, remember, login, vault=None, background=None, lock_minutes=None, browser=None,
             ssh=None, ssh_socket=None, ssh_provider=None):
        with self.mutex:
            background = self.background if background is None else bool(background)
            browser = self.browser if browser is None else bool(browser)
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
            vault = Path(vault).expanduser().resolve() if remember and vault else None
            login = bool(login and remember and vault)
            if login and not self.launcher:
                raise ValueError("Install the packaged Keyslot application before enabling login unlock.")
            # shortcut: GLib cannot launch a percent sign in argv[0]; packaged Nix paths never contain one.
            if login and any(char in str(self.launcher) for char in ("%", "\n", "\r")):
                raise ValueError("The login launcher path cannot contain a percent sign or a newline.")
            old = self.autostart.read_text() if self.autostart.exists() else None
            if login:
                command = str(self.launcher).replace("%", "%%")
                for char in ('\\', '"', '`', '$'):
                    command = command.replace(char, '\\' + char)
                # Desktop Entry strings unescape once before the Exec argument parser.
                command = command.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')
                _write(self.autostart, '[Desktop Entry]\nType=Application\nName=Keyslot\n'
                       f'Exec="{command}" --login\nIcon=keepassxc\nTerminal=false\n'
                       'OnlyShowIn=GNOME;\nX-GNOME-Autostart-enabled=true\n')
            else:
                self.autostart.unlink(missing_ok=True)
            try:
                _write(self.path, json.dumps({"remember": bool(remember), "login": login, "background": background, "lock_minutes": timeout, "browser": browser,
                       "ssh": ssh, "ssh_socket": ssh_socket, "ssh_provider": ssh_provider,
                       "vault": str(vault) if vault else None}) + "\n")
            except Exception:
                if old is None:
                    self.autostart.unlink(missing_ok=True)
                else:
                    _write(self.autostart, old)
                raise
            self.remember, self.login, self.vault = bool(remember), login, vault
            self.background = background
            self.browser = browser
            self.ssh, self.ssh_socket, self.ssh_provider = ssh, ssh_socket, ssh_provider
            self.lock_minutes = timeout

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

    def _collection(self, cancellable=None):
        service = self.secret.Service.get_sync(self.secret.ServiceFlags.OPEN_SESSION |
                                               self.secret.ServiceFlags.LOAD_COLLECTIONS, cancellable)
        collections = service.get_collections() if service is not None else None
        if collections is None:
            raise ValueError("The GNOME login keyring is unavailable. Unlock the vault manually.")
        collection = next((item for item in collections
                           if item.get_object_path() == "/org/freedesktop/secrets/collection/login"), None)
        if collection is None:
            raise ValueError("The GNOME login keyring is unavailable. Unlock the vault manually.")
        if collection.get_locked():
            raise ValueError("The GNOME login keyring is locked. Unlock it in Passwords and Keys first.")
        return collection

    def _attributes(self, path=None):
        result = {"application": APP_ID}
        if path is not None:
            result["vault"] = str(Path(path).expanduser().resolve())
        return result

    def store(self, path, credentials, cancellable=None):
        collection = self._collection(cancellable)
        if not self.secret.password_store_sync(self.schema, self._attributes(path), collection.get_object_path(),
                "Keyslot login unlock: " + Path(path).name, json.dumps(credentials), cancellable):
            raise ValueError("The vault credential could not be saved in the GNOME login keyring.")

    def lookup(self, path, cancellable=None):
        collection = self._collection(cancellable)
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
        collection = self._collection(cancellable)
        for item in collection.search_sync(self.schema, self._attributes(), self.secret.SearchFlags.NONE, cancellable):
            if not item.delete_sync(cancellable):
                raise ValueError("A saved Keyslot credential could not be removed from the login keyring.")
