"""Explicit KeePassXC INI profiles, decoded and updated by the pinned Qt core."""
import hashlib
import copy
import json
import os
import re
from pathlib import Path
import threading

from .backend import VaultError
from .core_backend import Vault, EngineError
from .startup import _autotype_options, _secret_service_options


STARTUP_KEYS = {
    "background": ("global", "Keyslot/RunInBackground", True),
    "browser": ("global", "Browser/Enabled", False),
    "minimize_on_url": ("global", "MinimizeOnOpenUrl", False),
    "auto_reload": ("global", "AutoReloadOnChange", True),
    "auto_save": ("global", "AutoSaveAfterEveryChange", True),
    "auto_save_on_exit": ("global", "AutoSaveOnExit", True),
    "ssh": ("global", "SSHAgent/Enabled", False),
    "ssh_socket": ("local", "SSHAgent/AuthSockOverride", ""),
    "ssh_provider": ("local", "SSHAgent/SecurityKeyProviderOverride", ""),
    "login": ("local", "Keyslot/UnlockAtLogin", False),
}
AUTOTYPE_KEYS = {"match_title": "AutoTypeEntryTitleMatch", "match_url": "AutoTypeEntryURLMatch",
    "hide_expired": "AutoTypeHideExpiredEntry", "relock": "Security/RelockAutoType",
    "delay": "AutoTypeDelay", "start_delay": "AutoTypeStartDelay"}
SECRET_KEYS = {"enabled": "Enabled", "notify": "ShowNotification", "confirm_delete": "ConfirmDeleteItem",
    "confirm_access": "ConfirmAccessItem", "unlock_before_search": "UnlockBeforeSearch"}
GENERATOR_KEYS = {"lowercase": ("LowerCase", True), "uppercase": ("UpperCase", True),
    "numbers": ("Numbers", True), "extended_ascii": ("EASCII", False),
    "every_group": ("EnsureEvery", True), "exclude_lookalike": ("ExcludeAlike", True),
    "additional": ("AdditionalChars", ""), "excluded": ("ExcludedChars", ""),
    "length": ("Length", 20), "word_count": ("WordCount", 7), "separator": ("WordSeparator", " "),
    "wordlist": ("WordList", "eff_large.wordlist")}
SYMBOL_KEYS = {"braces": "Braces", "punctuation": "Punctuation", "quotes": "Quotes",
               "dashes": "Dashes", "math": "Math", "logograms": "Logograms"}
SEARCH_KEYS = {"limit_group": ("SearchLimitGroup", False), "wait_enter": ("GUI/SearchWaitForEnter", False),
               "recursive": ("Keyslot/RecursiveGroupView", False), "search_recursive": ("Keyslot/SearchRecursive", True)}
GLOBAL = {"RememberLastDatabases": True, "OpenPreviousDatabasesOnStartup": True,
    "RememberLastKeyFiles": True,
    "NumberOfRememberedLastDatabases": 5, "Security/LockDatabaseIdle": True,
    "Security/LockDatabaseIdleSeconds": 900, "Security/ClearClipboard": True,
    "Security/ClearClipboardTimeout": 10, "Keyslot/KeeShareImport": False,
    "Keyslot/KeeShareExport": False, "PasswordGenerator/AdvancedMode": False,
    "PasswordGenerator/SpecialChars": True, "PasswordGenerator/WordCase": 0,
    "PasswordGenerator/Type": 0, "FaviconDownloadTimeout": 10,
    "Security/IconDownloadFallback": False}
LOCAL = {"LastActiveDatabase": "", "LastDatabases": [], "LastOpenedDatabases": [],
         "LastKeyFiles": {}, "LastChallengeResponse": {}, "Keyslot/LoginVault": ""}
for _role, _key, _default in STARTUP_KEYS.values():
    (GLOBAL if _role == "global" else LOCAL)[_key] = _default
for _name, _key in AUTOTYPE_KEYS.items():
    GLOBAL[_key] = {"match_title": True, "match_url": True, "hide_expired": False,
                   "relock": False, "delay": 25, "start_delay": 500}[_name]
for _name, _key in SECRET_KEYS.items():
    GLOBAL["FdoSecrets/" + _key] = _name != "enabled"
for _key, _default in GENERATOR_KEYS.values():
    GLOBAL["PasswordGenerator/" + _key] = _default
for _key in SYMBOL_KEYS.values():
    GLOBAL["PasswordGenerator/" + _key] = False
for _key, _default in SEARCH_KEYS.values():
    GLOBAL[_key] = _default


def default_paths():
    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    cache = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    return (os.environ.get("KPXC_CONFIG") or config / "keepassxc/keepassxc.ini",
            os.environ.get("KPXC_CONFIG_LOCAL") or cache / "keepassxc/keepassxc.ini")


def _local_path(name):
    if not name or len(name) > 4096 or any(c in name for c in ("\0", "\n", "\r")) or not Path(name).is_absolute():
        return None
    try:
        return Path(name).resolve()
    except (OSError, RuntimeError):
        return None


class IniProfile:
    def __init__(self, global_path, local_path):
        self.arguments = [("--config", os.path.abspath(global_path)),
                          ("--localconfig", os.path.abspath(local_path))]
        self.paths = {role: str(Path(path).resolve()) for role, (_option, path) in
                      zip(("global", "local"), self.arguments)}
        self.identity = hashlib.sha256(json.dumps(self.paths, sort_keys=True).encode()).hexdigest()
        self.directory = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "keyslot/profiles" / self.identity
        self.schemas = {}
        for role, schema in (("global", GLOBAL), ("local", LOCAL)):
            self.schemas.setdefault(self.paths[role], {}).update(schema)
        self.mutex = threading.RLock()
        self.values = {}
        self.startup = self.generator = None
        self._read()

    def _request(self, write, files):
        for role, (_option, path) in zip(("global", "local"), self.arguments):
            if str(Path(path).resolve()) != self.paths[role]:
                raise VaultError("The configuration link changed. Reopen Keyslot before saving settings.")
        client = Vault()
        try:
            return client.configuration(write, files)["files"]
        except EngineError as exc:
            recovery = exc.details.get("recovery_path") if isinstance(exc.details, dict) else None
            if recovery:
                raise VaultError(f"{exc}\nOriginal configurations were retained in {recovery}") from exc
            raise
        finally:
            client.lock()

    def _read(self):
        self.values = {item["path"]: item["values"] for item in self._request(False,
            [{"path": path, "defaults": schema} for path, schema in self.schemas.items()])}

    def _get(self, key, role="global"):
        return self.values[self.paths[role]][key]

    def restore_paths(self):
        with self.mutex:
            if not self._get("OpenPreviousDatabasesOnStartup"):
                return []
            active = self._get("LastActiveDatabase", "local")
            result = []
            # The active vault is last so it receives focus after the other windows.
            for name in [*self._get("LastOpenedDatabases", "local"), active]:
                path = _local_path(name)
                if path and path.is_file():
                    if path in result:
                        result.remove(path)
                    result.append(path)
            return result

    def write_session(self, paths, active):
        with self.mutex:
            self._read()
            if self._get("OpenPreviousDatabasesOnStartup"):
                opened = list(dict.fromkeys(str(Path(path).resolve()) for path in paths))
                selected = str(Path(active).resolve()) if active else ""
                selected = selected if selected in opened else next(iter(opened), "")
            else:
                opened, selected = [], ""
            self._write({("local", "LastOpenedDatabases"): opened, ("local", "LastActiveDatabase"): selected})

    def key_components(self, path):
        with self.mutex:
            result = {"keyfile": "", "yubikey": ""}
            if not self._get("RememberLastKeyFiles"):
                return result
            canonical = Path(path).resolve()
            def selected(key):
                choices = self._get(key, "local")
                if str(canonical) in choices:
                    return choices[str(canonical)]
                for name, value in choices.items():
                    if _local_path(name) == canonical:
                        return value
                return ""
            keyfile = selected("LastKeyFiles")
            if keyfile:
                if len(keyfile) > 4096 or any(c in keyfile for c in ("\0", "\n", "\r")):
                    raise VaultError("The remembered key-file path is invalid. Choose a key file manually.")
                result["keyfile"] = str(Path(keyfile).expanduser().absolute())
            hardware = re.fullmatch(r"([0-9]{1,10}):([12])", selected("LastChallengeResponse"))
            if hardware and int(hardware[1]) <= 4294967295:
                result["yubikey"] = hardware[2] + (":" + str(int(hardware[1])) if int(hardware[1]) else "")
            return result

    def remember_components(self, path, keyfile, hardware):
        with self.mutex:
            self._read()
            if not self._get("RememberLastKeyFiles"):
                return
            canonical = Path(path).resolve()
            match = re.fullmatch(r"([12])(?::([0-9]{1,10}))?", hardware) if hardware else None
            if hardware and (not match or int(match[2] or 0) > 4294967295):
                raise VaultError("The hardware-key selection could not be remembered.")
            updates = {}
            for key, value in (("LastKeyFiles", str(Path(keyfile).expanduser().resolve()) if keyfile else ""),
                               ("LastChallengeResponse", f"{int(match[2] or 0)}:{match[1]}" if match else "")):
                choices = dict(self._get(key, "local"))
                for name in list(choices):
                    if _local_path(name) == canonical:
                        choices.pop(name)
                if value:
                    choices[str(canonical)] = value
                updates["local", key] = choices
            self._write(updates)

    def _write(self, changes):
        grouped = {}
        for (role, key), value in changes.items():
            path = self.paths[role]
            if self.values[path][key] != value:
                grouped.setdefault(path, {})[key] = value
        if grouped:
            records = self._request(True, [{"path": path, "defaults": self.schemas[path], "values": values,
                "expected": {key: self.values[path][key] for key in values}} for path, values in grouped.items()])
            for record in records:
                self.values[record["path"]] = record["values"]

    def read_startup(self):
        with self.mutex:
            data = {field: self._get(key, role) for field, (role, key, _default) in STARTUP_KEYS.items()}
            data["remember"] = self._get("OpenPreviousDatabasesOnStartup")
            candidates = [self._get("LastActiveDatabase", "local"), *self._get("LastOpenedDatabases", "local")]
            if data["login"]:
                candidates.insert(0, self._get("Keyslot/LoginVault", "local"))
            data["vault"] = next((path for path in candidates if path and Path(path).is_absolute()), None) if data["remember"] else None
            data["login"] = data["login"] and data["remember"] and data["vault"] is not None
            seconds = self._get("Security/LockDatabaseIdleSeconds") if self._get("Security/LockDatabaseIdle") else 0
            clipboard = self._get("Security/ClearClipboardTimeout") if self._get("Security/ClearClipboard") else 0
            if not 0 <= seconds <= 86400 or not 0 <= clipboard <= 3600:
                raise VaultError("This configuration's idle or clipboard timeout exceeds Keyslot's supported range. Original settings have been preserved.")
            data.update(lock_minutes=(seconds + 59) // 60, lock_seconds=seconds, clipboard_seconds=clipboard)
            data["autotype"] = _autotype_options({name: self._get(key) for name, key in AUTOTYPE_KEYS.items()})
            data["secret_service"] = _secret_service_options({name: self._get("FdoSecrets/" + key) for name, key in SECRET_KEYS.items()})
            data["keeshare"] = {name: self._get("Keyslot/KeeShare" + name.title()) for name in ("import", "export")}
            for value in (data["vault"], data["ssh_socket"], data["ssh_provider"]):
                if value is not None and (len(value) > 4096 or any(c in value for c in ("\0", "\n", "\r"))):
                    raise VaultError("The configuration contains an invalid file path. Original settings have been preserved.")
            if data["ssh_socket"] and not Path(data["ssh_socket"]).is_absolute():
                raise VaultError("The configured SSH agent socket must be an absolute path.")
            self.startup = copy.deepcopy(data)
            return data

    def write_startup(self, data):
        with self.mutex:
            if self.startup is None:
                self.read_startup()
            changes = {}
            def put(key, value, role="global"):
                changes[role, key] = value
            for field, (role, key, _default) in STARTUP_KEYS.items():
                value = data.get(field, _default)
                if value != self.startup.get(field, _default):
                    put(key, value, role)
            put("Keyslot/LoginVault", data["vault"] if data["login"] else "", "local")
            if data["remember"] != self.startup["remember"]:
                put("RememberLastDatabases", data["remember"])
                put("OpenPreviousDatabasesOnStartup", data["remember"])
                if not data["remember"]:
                    for key, value in (("LastActiveDatabase", ""), ("LastDatabases", []), ("LastOpenedDatabases", [])):
                        put(key, value, "local")
            if data["remember"] and data["vault"] != self.startup["vault"]:
                path = data["vault"] or ""
                put("LastActiveDatabase", path, "local")
                if path and self._get("RememberLastDatabases"):
                    limit = self._get("NumberOfRememberedLastDatabases")
                    if not 0 <= limit <= 10000:
                        raise VaultError("The configured recent-database limit is invalid.")
                    recent = [path] + [item for item in self._get("LastDatabases", "local") if item != path]
                    put("LastDatabases", recent[:limit], "local")
            seconds = data.get("lock_seconds", data["lock_minutes"] * 60)
            if seconds != self.startup["lock_seconds"]:
                put("Security/LockDatabaseIdle", seconds != 0)
                if seconds:
                    put("Security/LockDatabaseIdleSeconds", seconds)
            clipboard = data.get("clipboard_seconds", 20)
            if clipboard != self.startup["clipboard_seconds"]:
                put("Security/ClearClipboard", clipboard != 0)
                if clipboard:
                    put("Security/ClearClipboardTimeout", clipboard)
            for field, mapping, prefix in (("autotype", AUTOTYPE_KEYS, ""), ("secret_service", SECRET_KEYS, "FdoSecrets/")):
                for name, key in mapping.items():
                    if data[field][name] != self.startup[field][name]:
                        put(prefix + key, data[field][name])
            for name in ("import", "export"):
                if data["keeshare"][name] != self.startup["keeshare"][name]:
                    put("Keyslot/KeeShare" + name.title(), data["keeshare"][name])
            self._write(changes)
            self.startup = copy.deepcopy(dict(data, lock_seconds=seconds, clipboard_seconds=clipboard))

    def read_search(self):
        with self.mutex:
            return {name: self._get(key) for name, (key, _default) in SEARCH_KEYS.items()}

    def read_icon_options(self):
        with self.mutex:
            timeout = self._get("FaviconDownloadTimeout")
            if not 1 <= timeout <= 300:
                raise VaultError("This profile's favicon timeout is outside the supported 1–300 second range. Its original setting was preserved.")
            return {"timeout": timeout, "fallback": self._get("Security/IconDownloadFallback")}

    def write_search(self, changes):
        with self.mutex:
            if not isinstance(changes, dict) or set(changes) - SEARCH_KEYS.keys() or any(type(value) is not bool for value in changes.values()):
                raise VaultError("Choose supported search options.")
            self._write({("global", SEARCH_KEYS[name][0]): value for name, value in changes.items()})

    def read_generator(self):
        from .generator_views import DEFAULTS, CASES, _validate
        with self.mutex:
            self._read()
            data = dict(DEFAULTS)
            for name, (key, _default) in GENERATOR_KEYS.items():
                data[name] = self._get("PasswordGenerator/" + key)
            groups = {name: self._get("PasswordGenerator/" + key) for name, key in SYMBOL_KEYS.items()}
            advanced, symbols = self._get("PasswordGenerator/AdvancedMode"), self._get("PasswordGenerator/SpecialChars")
            data.update(groups if advanced or (not symbols and any(groups.values())) else dict.fromkeys(groups, True))
            data["symbols"] = any(groups.values()) if advanced else symbols
            mode, case = self._get("PasswordGenerator/Type"), self._get("PasswordGenerator/WordCase")
            if mode not in (0, 1) or not 0 <= case < len(CASES):
                raise VaultError("The configuration contains an unsupported password generator mode.")
            data["passphrase"], data["word_case"] = mode == 1, CASES[case][0]
            if not _validate(data):
                raise VaultError("The configuration contains unsupported password generator settings.")
            self.generator = data
            return dict(data)

    def write_generator(self, data):
        from .generator_views import CASES, _validate
        with self.mutex:
            if not _validate(data):
                raise VaultError("Choose supported password generator settings.")
            previous = self.generator if self.generator is not None else self.read_generator()
            changed = {key for key in data if data[key] != previous[key]}
            changes = {("global", "PasswordGenerator/" + GENERATOR_KEYS[name][0]): data[name]
                       for name in changed & GENERATOR_KEYS.keys()}
            if "passphrase" in changed:
                changes["global", "PasswordGenerator/Type"] = int(data["passphrase"])
            if "word_case" in changed:
                changes["global", "PasswordGenerator/WordCase"] = next(i for i, (name, _label) in enumerate(CASES) if name == data["word_case"])
            if changed & ({"symbols"} | SYMBOL_KEYS.keys()):
                changes["global", "PasswordGenerator/AdvancedMode"] = data["symbols"] and not all(data[name] for name in SYMBOL_KEYS)
                changes["global", "PasswordGenerator/SpecialChars"] = data["symbols"]
                for name, key in SYMBOL_KEYS.items():
                    changes["global", "PasswordGenerator/" + key] = data[name]
            self._write(changes)
            self.generator = dict(data)
