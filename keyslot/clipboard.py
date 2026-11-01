"""Track process-local clipboard providers without reading another application's data."""
from dataclasses import dataclass
import math
import time
import weakref
from gi.repository import Gdk, GLib


@dataclass
class Owned:
    provider: object
    owner: object
    started: float
    deadline: float = 0
    explicit: bool = False
    timer: int = 0


class Clipboards:
    def __init__(self, app):
        self.app = app
        self.records = {}
        self.signals = {}
        self.closed = False

    def watch(self, display):
        if self.closed:
            return
        for clipboard in (display.get_clipboard(), display.get_primary_clipboard()):
            if clipboard is not None and clipboard not in self.signals:
                self.signals[clipboard] = clipboard.connect("changed", self._changed)
                self._changed(clipboard)

    def _owner(self):
        window = self.app.get_active_window()
        while window:
            session = getattr(window, "session", None)
            if session and not session.jobs.closed:
                return session
            window = window.get_transient_for()
        session = self.app.active_session
        return session if session and not session.jobs.closed else None

    def _drop(self, clipboard):
        old = self.records.pop(clipboard, None)
        if old and old.timer:
            GLib.source_remove(old.timer)

    def _remember(self, clipboard, provider, owner, explicit=False):
        self._drop(clipboard)
        record = Owned(provider, weakref.ref(owner) if owner else lambda: None,
                       time.monotonic(), explicit=explicit)
        self.records[clipboard] = record
        self._schedule(clipboard, record)

    def _schedule(self, clipboard, record):
        if record.timer:
            GLib.source_remove(record.timer)
            record.timer = 0
        seconds = self.app.startup.clipboard_seconds
        record.deadline = record.started + seconds if seconds else 0
        if seconds:
            remaining = record.deadline - time.monotonic()
            if remaining <= 0:
                self._clear_one(clipboard)
                return
            def expire():
                record.timer = 0
                if self.records.get(clipboard) is record:
                    self._clear_one(clipboard)
                return GLib.SOURCE_REMOVE
            record.timer = GLib.timeout_add(max(1, math.ceil(remaining * 1000)), expire)

    def refresh(self):
        if self.closed:
            return
        for clipboard, record in list(self.records.items()):
            if clipboard.get_content() == record.provider:
                self._schedule(clipboard, record)
            else:
                self._drop(clipboard)

    def _changed(self, clipboard):
        if self.closed:
            return
        provider = clipboard.get_content()
        if provider is None:
            self._drop(clipboard)
            return
        old = self.records.get(clipboard)
        if old and old.provider == provider and old.explicit:
            return
        # GTK selections can change their contents while keeping the same provider object.
        owner = old.owner() if old and old.provider == provider else self._owner()
        self._remember(clipboard, provider, owner)

    def copy(self, session, value):
        if self.closed:
            return False
        display = session.host_window.get_display()
        self.watch(display)
        regular = display.get_clipboard()
        copied = False
        for clipboard in dict.fromkeys((regular, display.get_primary_clipboard())):
            if clipboard is None:
                continue
            provider = Gdk.ContentProvider.new_union([
                Gdk.ContentProvider.new_for_value(value),
                Gdk.ContentProvider.new_for_bytes("x-kde-passwordManagerHint", GLib.Bytes.new(b"secret")),
            ])
            # Replace directly: clearing first can lose the subsequent claim on X11.
            if clipboard.set_content(provider) and clipboard.get_content() == provider:
                self._remember(clipboard, provider, session, True)
                if clipboard == regular:
                    copied = True
        return copied

    def _clear_one(self, clipboard):
        record = self.records.get(clipboard)
        if record is None:
            return
        self._drop(clipboard)
        if clipboard.get_content() == record.provider:
            clipboard.set_content(None)

    def clear(self, session=None):
        for clipboard, record in list(self.records.items()):
            owner = record.owner()
            if session is None or owner is None or owner is session:
                self._clear_one(clipboard)

    def remaining(self):
        now = time.monotonic()
        return max((record.deadline - now for clipboard, record in self.records.items()
                    if record.deadline and clipboard.get_content() == record.provider), default=0)

    def close(self):
        self.closed = True
        for clipboard, signal in self.signals.items():
            clipboard.disconnect(signal)
        self.signals.clear()
        self.clear()
