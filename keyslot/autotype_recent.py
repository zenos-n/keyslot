"""Short-lived Auto-Type selection metadata, never a reusable typing approval."""
import hashlib
import time
import weakref

from gi.repository import GLib


class RecentChoice:
    def __init__(self, app):
        self.app = app
        self.record = None
        self.timer = 0

    @staticmethod
    def digest(sequence):
        return hashlib.sha256(sequence.encode("utf-8")).digest()

    def clear(self, owner=None):
        if owner is not None and self.record and self.record["owner"]() is not owner:
            return
        self.record = None
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0

    def current(self):
        record = self.record
        if not record:
            return None
        owner = record["owner"]()
        seconds = self.app.startup.autotype["retype_seconds"]
        if (not seconds or time.monotonic() - record["time"] >= seconds
                or owner is None or owner.jobs.closed or not owner.vault.unlocked
                or owner.epoch != record["epoch"] or owner.vault.identity is not record["identity"]
                or owner.vault.generation != record["generation"]
                or owner.vault.snapshot is not record["snapshot"]()):
            self.clear()
            return None
        return record

    def remember(self, owner, uuid, sequence_digest, snapshot):
        self.clear()
        seconds = self.app.startup.autotype["retype_seconds"]
        if (not seconds or owner.jobs.closed or not owner.vault.unlocked
                or owner.vault.snapshot is not snapshot):
            return
        self.record = {"owner": weakref.ref(owner), "snapshot": weakref.ref(snapshot),
                       "identity": owner.vault.identity, "epoch": owner.epoch,
                       "generation": owner.vault.generation, "uuid": uuid,
                       "digest": sequence_digest, "time": time.monotonic()}
        def expired():
            self.timer = 0
            self.record = None
            return GLib.SOURCE_REMOVE
        self.timer = GLib.timeout_add(seconds * 1000, expired)

    def matches(self, owner, entry, sequence, default_digest=None):
        record = self.current()
        return bool(record and record["owner"]() is owner and record["uuid"] == entry.uuid
                    and record["digest"] == (self.digest(sequence) if sequence else default_digest))
