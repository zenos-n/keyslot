"""Fixed field actions and secret-free, stale-guarded availability metadata."""
import weakref
from gi.repository import GLib

TYPES = {
    "username": ("Username", "{USERNAME}", "actionEntryAutoTypeUsername"),
    "username-enter": ("Username, Then Enter", "{USERNAME}{ENTER}", "actionEntryAutoTypeUsernameEnter"),
    "password": ("Password", "{PASSWORD}", "actionEntryAutoTypePassword"),
    "password-enter": ("Password, Then Enter", "{PASSWORD}{ENTER}", "actionEntryAutoTypePasswordEnter"),
    "totp": ("One-Time Password", "{TOTP}", "actionEntryAutoTypeTOTP"),
    "url": ("Website", "{URL}", "actionEntryAutoTypeURL"),
    "url-enter": ("Website, Then Enter", "{URL}{ENTER}", "actionEntryAutoTypeURLEnter"),
}
COPY_FIELDS = {"username": "UserName", "password": "Password", "totp": "TOTP", "url": "URL"}
SELECTOR_KEYS = {"username": "<Control>1", "password": "<Control>2",
                 "totp": "<Control>3", "url": "<Control>4"}


class FieldInfo:
    def __init__(self, changed):
        self.changed = changed
        self.serial = 0
        self.context = self.info = None
        self.pending = self.closed = False
        self.retry = 0
        self.error = ""

    def clear(self):
        self.serial += 1
        self.context = self.info = None
        self.pending = False
        self.error = ""
        if self.retry:
            GLib.source_remove(self.retry)
            self.retry = 0
        self.changed()

    def close(self):
        self.closed = True
        self.clear()

    def current(self):
        if self.closed or self.context is None:
            return False
        reference, epoch, identity, generation, snapshot, _uuid = self.context
        owner = reference()
        return bool(owner and not owner.jobs.closed and owner.vault.unlocked
                    and owner.epoch == epoch and owner.vault.identity is identity
                    and owner.vault.generation == generation and owner.vault.snapshot is snapshot())

    def available(self, name, *, typing=True, entry=None):
        if not self.current() or self.info is None or (typing and not self.info["eligible"]):
            return False
        if entry is not None and self.context[-1] != entry.uuid:
            return False
        return name == "entry" or self.info.get(name.removesuffix("-enter"), False)

    def select(self, owner, entry):
        if self.closed:
            return
        if (self.current() and self.context[0]() is owner and self.context[-1] == entry.uuid
                and (self.info is not None or self.pending)):
            return
        self.clear()
        if owner.jobs.closed or not owner.vault.unlocked or entry.recycled or not entry.addressable:
            return
        self.context = (weakref.ref(owner), owner.epoch, owner.vault.identity, owner.vault.generation,
                        weakref.ref(owner.vault.snapshot), entry.uuid)
        serial = self.serial
        def completed(info):
            if serial == self.serial and self.current():
                self.pending = False
                self.info = info
                self.changed()
        def failed(_message):
            if serial == self.serial and self.current():
                self.pending = False
                self.error = "Auto-Type options could not be loaded. Select the entry again to retry."
                self.changed()
        def request():
            self.retry = 0
            if serial != self.serial or not self.current():
                return GLib.SOURCE_REMOVE
            self.pending = True
            if not owner.jobs.run(lambda: owner.vault.autotype_fields(entry), completed, failed, interactive=False):
                self.pending = False
                self.retry = GLib.timeout_add(200, request)
            return GLib.SOURCE_REMOVE
        request()
