"""Application accelerators and scoped KeePassXC shortcut overrides."""
from dataclasses import dataclass
import json
import threading

from .application import Gdk, Gtk
from .backend import VaultError
from .core_backend import Vault
from .startup import _write
from .autotype_fields import TYPES


MISSING = "__keyslot_default_shortcut__"
MODIFIERS = Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK | Gdk.ModifierType.ALT_MASK | Gdk.ModifierType.SUPER_MASK
RESERVED = {"<Control>a": "Select All Entries", "<Shift><Control>a": "Deselect All Entries",
            "Escape": "Cancel / Leave Selection", "Menu": "Entry Context Menu", "<Shift>F10": "Entry Context Menu"}
QT_NAMES = {"Esc": "Escape", "Del": "Delete", "Ins": "Insert", "Space": "space", "Backtab": "ISO_Left_Tab",
            "PgUp": "Page_Up", "PgDown": "Page_Down", "Enter": "KP_Enter", "Print": "Print",
            "VolumeUp": "AudioRaiseVolume", "VolumeDown": "AudioLowerVolume", "VolumeMute": "AudioMute",
            "MediaPlay": "AudioPlay", "MediaPause": "AudioPause", "MediaStop": "AudioStop",
            "MediaNext": "AudioNext", "MediaPrevious": "AudioPrev", "LaunchMail": "Mail"}


@dataclass(frozen=True)
class Shortcut:
    action: str
    title: str
    default: str
    qt: str = ""
    needs: str = "always"

    @property
    def key(self):
        return "Shortcuts/" + self.qt if self.qt else "Keyslot/Shortcuts/" + self.action


SPECS = [
    Shortcut("app.new-window", "New Window", ""), Shortcut("app.recover", "Recover Unsaved Changes", ""),
    Shortcut("app.lock-all", "Lock All Databases", "<Control><Shift>l", "actionLockAllDatabases"),
    Shortcut("app.quit", "Quit", "<Control>q", "actionQuit"),
    Shortcut("win.open", "Open Database", "<Control>o", "actionDatabaseOpen"),
    Shortcut("win.new", "New Database", "<Control><Shift>n", "actionDatabaseNew"),
    Shortcut("win.save", "Save Database", "<Control>s", "actionDatabaseSave", "vault"),
    Shortcut("win.save-as", "Save Database As", "<Control><Shift>s", "actionDatabaseSaveAs", "vault"),
    Shortcut("win.save-copy", "Save Encrypted Database Copy", "", "actionDatabaseSaveBackup", "vault"),
    Shortcut("win.close", "Close Window", "<Control>w", "actionDatabaseClose"),
    Shortcut("win.new-entry", "New Entry", "<Control>n", "actionEntryNew", "vault"),
    Shortcut("win.edit-entry", "Edit Entry", "<Control>e", "actionEntryEdit", "entry"),
    Shortcut("win.duplicate", "Duplicate Entry", "<Control>d", "actionEntryClone", "entry"),
    Shortcut("win.delete", "Delete Selected Entries", "Delete", "actionEntryDelete", "selection"),
    Shortcut("win.permanent-delete", "Permanently Delete Selected Entries", "<Shift>Delete", needs="selection"),
    Shortcut("win.search", "Search", "<Control>f", needs="vault"),
    Shortcut("win.lock", "Lock Database", "<Control>l", "actionLockDatabase", "lock"),
    Shortcut("win.generator", "Password Generator", "<Control>g", "actionPasswordGenerator"),
    Shortcut("win.refresh", "Reload Database", "<Control>r", needs="vault"),
    Shortcut("win.import", "Import Database", "", "actionImport"),
    Shortcut("win.merge", "Merge Database", "", "actionDatabaseMerge", "vault"),
    Shortcut("win.remote-sync", "Remote Synchronization", "", needs="vault"),
    Shortcut("win.export", "Export Unencrypted Data", "", needs="vault"),
    Shortcut("win.settings", "Database Settings", "<Control><Shift>comma", "actionDatabaseSettings", "vault"),
    Shortcut("win.change-key", "Change Unlock Key", "", "actionDatabaseSecurity", "vault"),
    Shortcut("win.reports", "Database Reports", "<Control><Shift>r", "actionReports", "vault"),
    Shortcut("win.passkeys", "Manage Passkeys", "", "actionPasskeys", "vault"),
    Shortcut("win.open-url", "Open Entry Website", "<Control><Shift>u", "actionEntryOpenUrl", "entry"),
    Shortcut("win.copy-title", "Copy Entry Title", "<Control>i", "actionEntryCopyTitle", "entry"),
    Shortcut("win.copy-username", "Copy Username", "<Control>b", "actionEntryCopyUsername", "entry"),
    Shortcut("win.copy-password", "Copy Password", "<Control>c", "actionEntryCopyPassword", "entry"),
    Shortcut("win.copy-url", "Copy Website", "<Control>u", "actionEntryCopyURL", "entry"),
    Shortcut("win.copy-notes", "Copy Notes", "", "actionEntryCopyNotes", "entry"),
    Shortcut("win.copy-totp", "Copy One-Time Password", "<Control>t", "actionEntryCopyTotp", "totp"),
    Shortcut("win.copy-password-totp", "Copy Password and One-Time Password", "<Control>y", "actionEntryCopyPasswordTotp", "totp"),
    Shortcut("win.type-entry", "Type Selected Entry", "<Control><Shift>v", "actionEntryAutoTypeSequence", "autotype-entry"),
    *[Shortcut("win.type-" + name, "Type " + title, "", qt, "autotype-" + name)
      for name, (title, _sequence, qt) in TYPES.items()],
    Shortcut("win.autotype", "Choose Auto-Type Entry", "", needs="vault"),
    Shortcut("win.preferences", "Preferences", "<Control>comma", "actionSettings"),
    Shortcut("win.shortcuts", "Keyboard Shortcuts", "<Control>question", "actionKeyboardShortcuts"),
    Shortcut("win.shortcut-settings", "Customize Keyboard Shortcuts", ""),
    Shortcut("win.about", "About Keyslot", "", "actionAbout"),
]
BY_ACTION = {spec.action: spec for spec in SPECS}
ENTRY_ACTIONS = {"edit-entry": "edit", "duplicate": "duplicate", "delete": "delete", "permanent-delete": "permanent-delete",
                 "type-entry": "type:entry", **{"type-" + name: "type:" + name for name in TYPES},
                 **{"copy-" + name: name for name in ("title", "username", "password", "url", "notes", "totp", "password-totp")}}


def normalize(value):
    if not isinstance(value, str) or len(value) > 256 or "\0" in value:
        raise VaultError("Choose a supported keyboard shortcut.")
    if not value:
        return ""
    ok, key, mods = Gtk.accelerator_parse(value)
    if not ok or int(mods) & ~int(MODIFIERS) or not Gtk.accelerator_valid(key, mods):
        raise VaultError("Choose a valid key combination.")
    if key == Gdk.KEY_ISO_Left_Tab:
        key, mods = Gdk.KEY_Tab, mods | Gdk.ModifierType.SHIFT_MASK
    return Gtk.accelerator_name(Gdk.keyval_to_lower(key), mods)


def from_qt(record):
    if record["unsupported"]:
        raise VaultError("This stored Qt key sequence is not supported here.")
    if not record["text"]:
        return ""
    name = record["key"]
    key = Gdk.unicode_to_keyval(ord(name)) if len(name) == 1 else Gdk.keyval_from_name(QT_NAMES.get(name, name))
    if record["keypad"] and key and not (Gdk.keyval_name(key) or "").startswith("KP_"):
        key = Gdk.keyval_from_name("KP_" + (Gdk.keyval_name(key) or ""))
    mods = Gdk.ModifierType(0)
    for flag, mask in (("ctrl", Gdk.ModifierType.CONTROL_MASK), ("shift", Gdk.ModifierType.SHIFT_MASK),
                       ("alt", Gdk.ModifierType.ALT_MASK), ("super", Gdk.ModifierType.SUPER_MASK)):
        if record[flag]:
            mods |= mask
    if not key:
        raise VaultError("This key is unavailable in GTK.")
    return normalize(Gtk.accelerator_name(key, mods))


def qt_text(value):
    if not value:
        return ""
    _, key, mods = Gtk.accelerator_parse(value)
    name = Gdk.keyval_name(key)
    keypad = name.startswith("KP_")
    if keypad and name != "KP_Enter":
        name = name[3:]
        key = Gdk.keyval_from_name(name)
    reverse = {gtk: qt for qt, gtk in QT_NAMES.items()}
    char = Gdk.keyval_to_unicode(key)
    name = reverse.get(name, chr(char) if char and char >= 32 else name)
    if name in ("Page_Up", "Prior"):
        name = "PgUp"
    elif name in ("Page_Down", "Next"):
        name = "PgDown"
    parts = [text for mask, text in ((Gdk.ModifierType.CONTROL_MASK, "Ctrl"), (Gdk.ModifierType.ALT_MASK, "Alt"),
             (Gdk.ModifierType.SHIFT_MASK, "Shift"), (Gdk.ModifierType.SUPER_MASK, "Meta")) if mods & mask]
    return "+".join(parts + (["Num"] if keypad else []) + [name])


def decode(values):
    client = Vault(timeout=5)
    try:
        return client.shortcut_sequences(values)
    finally:
        client.lock()


class Store:
    def __init__(self, settings):
        self.profile = settings.storage
        self.path = settings.directory / "keyslot" / "shortcuts.json"
        self.schema = {spec.key: MISSING for spec in SPECS}
        self.mutex = self.profile.mutex if self.profile else threading.RLock()

    def read(self):
        with self.mutex:
            return self._read()

    def _read(self):
        if self.profile:
            with self.profile.mutex:
                records = self.profile._request(False, [{"path": self.profile.paths["global"], "defaults": self.schema}], timeout=5)
                raw = records[0]["values"]
        else:
            data = json.loads(self.path.read_text()) if self.path.exists() else {}
            if not isinstance(data, dict):
                raise VaultError("The shortcut settings are invalid; the original file was kept.")
            raw = {spec.key: data.get(spec.action, MISSING) for spec in SPECS}
        return self.parse(raw)

    def parse(self, raw):
        values, problems = {}, {}
        shared = [spec for spec in SPECS if self.profile and spec.qt and raw[spec.key] != MISSING
                  and isinstance(raw[spec.key], str) and len(raw[spec.key]) <= 1024 and "\0" not in raw[spec.key]]
        translated = dict(zip((spec.action for spec in shared), decode([raw[spec.key] for spec in shared]))) if shared else {}
        for spec in SPECS:
            source = raw[spec.key]
            if source == MISSING:
                values[spec.action] = None
                continue
            try:
                values[spec.action] = from_qt(translated[spec.action]) if self.profile and spec.qt else normalize(source)
            except (VaultError, KeyError, TypeError):
                values[spec.action] = ""
                problems[spec.action] = "Stored shortcut is unavailable here; it is preserved until changed."
        return {"raw": raw, "values": values, "problems": problems}

    def save(self, changes, snapshot):
        with self.mutex:
            return self._save(changes, snapshot)

    def _save(self, changes, snapshot):
        updates = {}
        for action, value in changes.items():
            if action not in BY_ACTION:
                raise VaultError("This shortcut is unavailable.")
            updates[action] = None if value is None else normalize(value)
        bindings = effective(snapshot["values"] | updates)
        if any(conflicts(bindings, action, key) for action, key in bindings.items()):
            raise VaultError("Resolve conflicting shortcuts before saving.")
        shared = [action for action in updates if self.profile and BY_ACTION[action].qt and updates[action] is not None]
        encoded = decode([qt_text(updates[action]) for action in shared]) if shared else []
        for action, record in zip(shared, encoded):
            if from_qt(record) != updates[action]:
                raise VaultError("This key combination cannot be represented in KeePassXC settings.")
            updates[action] = record["text"]
        if self.profile:
            values = {BY_ACTION[action].key: value for action, value in updates.items() if value is not None}
            removed = [BY_ACTION[action].key for action, value in updates.items() if value is None]
            with self.profile.mutex:
                self.profile._request(True, [{"path": self.profile.paths["global"], "defaults": self.schema,
                    "values": values, "remove": removed, "expected": snapshot["raw"]}])
        else:
            before = self.path.read_text() if self.path.exists() else None
            data = json.loads(before) if before is not None else {}
            if not isinstance(data, dict):
                raise VaultError("The shortcut settings are invalid.")
            if any(data.get(spec.action, MISSING) != snapshot["raw"][spec.key] for spec in SPECS):
                raise VaultError("Shortcuts changed in another window. Reopen the editor before saving.")
            for action, value in updates.items():
                if data.get(action, MISSING) != snapshot["raw"][BY_ACTION[action].key]:
                    raise VaultError("A shortcut changed in another window. Reopen the editor before saving.")
                if value is None:
                    data.pop(action, None)
                else:
                    data[action] = value
            if (self.path.read_text() if self.path.exists() else None) != before:
                raise VaultError("The shortcut file changed before saving. Reopen the editor.")
            _write(self.path, json.dumps(data) + "\n")
        return self.read()


def effective(values):
    return {spec.action: normalize(spec.default if values.get(spec.action) is None else values[spec.action]) for spec in SPECS}


def conflicts(bindings, action, accelerator):
    if not accelerator:
        return []
    reserved = {Gtk.accelerator_name(Gdk.keyval_to_lower(key), mods): label
                for value, label in RESERVED.items() for ok, key, mods in [Gtk.accelerator_parse(value)] if ok}
    return ([reserved[accelerator]] if accelerator in reserved else []) + [name for name, key in bindings.items() if name != action and key == accelerator]


def editing(window):
    widget = window.get_focus()
    while widget:
        if isinstance(widget, (Gtk.Editable, Gtk.TextView)):
            return True
        widget = widget.get_parent()
    return False


class Manager:
    def __init__(self, app):
        self.app, self.store = app, Store(app.startup)
        self.bindings = effective({})
        self.inhibitors = set()

    def load(self):
        snapshot = self.store.read()
        self.apply(snapshot)
        return snapshot

    def apply(self, snapshot):
        self.bindings = effective(snapshot["values"])
        blocked = {action for action, key in self.bindings.items() if conflicts(self.bindings, action, key)}
        for action, key in list(self.bindings.items()):
            if action in blocked:
                self.bindings[action] = ""
                snapshot["problems"][action] = "Conflicting shortcut was not activated. Reassign it in Preferences."
        self.install()

    def install(self):
        for action, key in self.bindings.items():
            self.app.set_accels_for_action(action, [key] if key and not self.inhibitors else [])
        self.refresh_state()

    def refresh_state(self):
        for session in self.app.sessions:
            window = session.host_window
            if not window:
                continue
            typing = editing(window)
            modal = bool(session.dialogs or session.file_requests)
            unlocked = session.vault.unlocked and not session.busy
            entry = session.window.selected_entry
            for spec in SPECS:
                if not spec.action.startswith("win."):
                    continue
                enabled = not session.busy and not modal
                if spec.needs == "lock":
                    enabled = session.vault.unlocked or session.busy
                elif spec.needs != "always":
                    enabled = enabled and unlocked
                if spec.needs in ("entry", "totp") or spec.needs.startswith("autotype-"):
                    enabled = enabled and not typing and entry is not None and entry.addressable and not entry.recycled
                    if spec.needs == "totp":
                        enabled = enabled and entry.totp
                    elif spec.needs.startswith("autotype-"):
                        enabled = enabled and session.type_fields.available(spec.needs.removeprefix("autotype-"), entry=entry)
                elif spec.needs == "selection":
                    selected = session.window.selected_entries()
                    enabled = enabled and not typing and bool(selected) and all(item.addressable for item in selected)
                if action := window.lookup_action(spec.action[4:]):
                    action.set_enabled(bool(enabled))


def invoke_entry(session, operation):
    if session.busy or session.dialogs or session.file_requests or editing(session.host_window) or not session.vault.unlocked:
        return
    if operation in ("delete", "permanent-delete"):
        session.delete_entries(session.window.selected_entries(), permanent=operation == "permanent-delete")
        return
    entry = session.window.selected_entry
    if not entry or not entry.addressable or entry.recycled:
        return
    if operation.startswith("type:"):
        name = operation.removeprefix("type:")
        if session.type_fields.available(name, entry=entry):
            from .autotype_views import choose
            choose(session, entry, field=None if name == "entry" else name)
    elif operation == "edit":
        session.edit_entry(entry)
    elif operation == "duplicate":
        from .entry_actions import choose
        choose(session, [entry], "duplicate")
    elif operation in ("totp", "password-totp"):
        session.totp.copy(entry, combined=operation == "password-totp")
    else:
        name = {"title": "Title", "username": "UserName", "password": "Password", "url": "URL", "notes": "Notes"}[operation]
        session.run_job(lambda: session.vault.attribute(entry, name), session.copy_entry)
