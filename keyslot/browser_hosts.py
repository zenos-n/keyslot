"""Explicit browser registration with private backups and unchanged-file checks."""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from .backend import VaultError
from .startup import _write


HOST = "org.keepassxc.keepassxc_browser"
BROWSERS = {"firefox": "Firefox", "chrome": "Google Chrome", "chromium": "Chromium", "brave": "Brave",
            "vivaldi": "Vivaldi", "edge": "Microsoft Edge", "tor": "Tor Browser", "gnosis": "Gnosis"}
ORIGINS = ["chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/",
           "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/"]


def fingerprint(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


class NativeHosts:
    def __init__(self, proxy, home=None, config_home=None, data_home=None):
        self.proxy = str(Path(proxy).resolve(strict=True))
        if not Path(self.proxy).is_file() or not os.access(self.proxy, os.X_OK):
            raise VaultError("Install Keyslot's packaged browser proxy before configuring browsers.")
        home = Path(home or Path.home())
        config = Path(config_home or os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        data = Path(data_home or os.environ.get("XDG_DATA_HOME", home / ".local/share"))
        # ZenOS relocates Firefox's legacy home through ZenFS, matching ZenLink's native-host setup.
        mozilla = config / "mozilla" if config.is_relative_to(home / ".private") else home / ".mozilla"
        directories = {"firefox": mozilla / "native-messaging-hosts", "chrome": config / "google-chrome/NativeMessagingHosts",
            "chromium": config / "chromium/NativeMessagingHosts", "brave": config / "BraveSoftware/Brave-Browser/NativeMessagingHosts",
            "vivaldi": config / "vivaldi/NativeMessagingHosts", "edge": config / "microsoft-edge/NativeMessagingHosts",
            "tor": data / "torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser/.mozilla/native-messaging-hosts"}
        directories["gnosis"] = config / "gnosis/NativeMessagingHosts"
        self.paths = {name: directory / (HOST + ".json") for name, directory in directories.items()}
        self.state_path = config / "keyslot/browser-hosts.json"

    def _load(self):
        try:
            source, _mode = self._read(self.state_path, limit=1024 * 1024)
            if source is None:
                return {"version": 1, "browsers": {}}
            value = json.loads(source)
            if value.get("version") != 1 or not isinstance(value.get("browsers"), dict):
                raise ValueError("invalid registry")
            for name, item in value["browsers"].items():
                if name not in BROWSERS or not isinstance(item, dict) or "original" not in item or not isinstance(item.get("installed"), str):
                    raise ValueError("invalid registry")
                if len(item["installed"]) != 64 or any(c not in "0123456789abcdef" for c in item["installed"]):
                    raise ValueError("invalid fingerprint")
                original = item.get("original")
                if original is not None and (not isinstance(original, str) or len(base64.b64decode(original, validate=True)) > 65536):
                    raise ValueError("invalid backup")
                if type(item.get("mode")) is not int or not 0 <= item["mode"] <= 0o777:
                    raise ValueError("invalid mode")
            return value
        except (ValueError, AttributeError, OSError, VaultError) as exc:
            raise VaultError("Browser setup records could not be read. Existing browser settings have been preserved.") from exc

    def _read(self, path, limit=65536):
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None, 0o600
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise VaultError("This browser registration is managed outside Keyslot. Update it in your system configuration.") from exc
            raise VaultError("This browser registration could not be read. Its settings have been preserved.") from exc
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise VaultError("This browser registration is managed outside Keyslot. Update it in your system configuration.")
            source = stream.read(limit + 1)
            if len(source) > limit:
                raise VaultError("This browser registration is too large. Its settings have been preserved.")
            return source, stat.S_IMODE(info.st_mode) & 0o777

    def _path(self, browser):
        if browser not in self.paths:
            raise VaultError("Choose a supported browser.")
        return self.paths[browser]

    def manifest(self, browser):
        self._path(browser)
        value = {"name": HOST, "description": "Keyslot password manager", "type": "stdio", "path": self.proxy}
        if browser in {"firefox", "tor"}:
            value["allowed_extensions"] = ["keepassxc-browser@keepassxc.org"]
        else:
            value["allowed_origins"] = ["chrome-extension://giohadoodmdcadnkcpdmhmmdnaidnckm/"] if browser == "gnosis" else ORIGINS
        return (json.dumps(value, indent=2) + "\n").encode()

    def status(self, browser):
        data, _mode = self._read(self._path(browser))
        record = self._load()["browsers"].get(browser)
        current = fingerprint(data)
        return {"enabled": record is not None and record["installed"] == current,
                "exists": data is not None, "fingerprint": current}

    def _save(self, value):
        _write(self.state_path, json.dumps(value, indent=2) + "\n")

    def _replace(self, path, data, expected, mode=0o600):
        if fingerprint(self._read(path)[0]) != expected:
            raise VaultError("The browser connection changed. Review it again before replacing it.")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if data is None:
            path.unlink(missing_ok=True)
            return
        descriptor, temporary = tempfile.mkstemp(prefix=".keyslot-host-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if fingerprint(self._read(path)[0]) != expected:
                raise VaultError("The browser connection changed. Review it again before replacing it.")
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def enable(self, browser, expected, replace=False):
        path = self._path(browser)
        current, mode = self._read(path)
        current_hash = fingerprint(current)
        if current_hash != expected:
            raise VaultError("The browser connection changed. Review it again before replacing it.")
        state = self._load()
        previous_state = json.loads(json.dumps(state))
        record = state["browsers"].get(browser)
        owned = record is not None and record["installed"] == current_hash
        if current is not None and not owned and not replace:
            raise VaultError("Replacing this browser's current connection requires confirmation.")
        target = self.manifest(browser)
        original = record["original"] if owned else base64.b64encode(current).decode() if current is not None else None
        original_mode = record["mode"] if owned else mode
        state["browsers"][browser] = {"installed": fingerprint(target), "original": original, "mode": original_mode}
        # Secure the backup before replacing the original registration.
        self._save(state)
        try:
            self._replace(path, target, current_hash)
        except Exception:
            self._save(previous_state)
            raise

    def disable(self, browser):
        path = self._path(browser)
        state = self._load()
        record = state["browsers"].get(browser)
        if record is None:
            return
        original = base64.b64decode(record["original"], validate=True) if record["original"] is not None else None
        current, _mode = self._read(path)
        if fingerprint(current) == record["installed"]:
            self._replace(path, original, record["installed"], record["mode"])
        elif fingerprint(current) != fingerprint(original):
            raise VaultError("Another application changed this browser connection. Its settings have been preserved.")
        del state["browsers"][browser]
        self._save(state)

    def refresh(self):
        for browser in self._load()["browsers"]:
            status = self.status(browser)
            if status["enabled"]:
                self.enable(browser, expected=status["fingerprint"])
