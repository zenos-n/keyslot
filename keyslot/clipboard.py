"""Track process-local clipboard providers without reading another application's data."""
from dataclasses import dataclass
import math
import os
import threading
import time
import weakref
from gi.repository import Gdk, GLib
from .backend import VaultError


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
        self.regular = set()
        self.closed = False
        self.portal_mutex = threading.RLock()
        self.portals = set()
        self.serial = self.changed_serial = 0
        self.pending = None

    def watch_portal(self, portal):
        with self.portal_mutex:
            self.portals.add(portal)

    def unwatch_portal(self, portal):
        with self.portal_mutex:
            self.portals.discard(portal)

    def _portals(self):
        with self.portal_mutex:
            return list(self.portals)

    def _finish_request(self, request):
        if self.pending is request:
            self.pending = None
        for widget, signal in request["signals"]:
            widget.disconnect(signal)
        request["signals"].clear()

    def _cancel_pending(self, owner=None):
        request = self.pending
        if request and (owner is None or request["owner"]() is owner):
            request["cancelled"] = True
            self._finish_request(request)

    def watch(self, display):
        if self.closed:
            return
        self.regular.add(display.get_clipboard())
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
        for portal in self._portals():
            portal.refresh()

    def _changed(self, clipboard):
        if self.closed:
            return
        if clipboard in self.regular:
            self.changed_serial += 1
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

    def copy(self, session, value, done=None, valid=None):
        def report(success):
            if done:
                done(success)
            return success
        if self.closed or not isinstance(value, str):
            return report(False)
        self._cancel_pending()
        self.serial += 1
        self.watch(session.host_window.get_display())
        if not self.app.startup.autotype["portal_clipboard"] or os.environ.get("XDG_SESSION_TYPE") != "wayland":
            return report(self._copy_gtk(session, value))
        try:
            permission = self.app.portal_permissions.capture()
        except VaultError:
            return report(False)
        connection_epoch = self.app.portal_connections.epoch
        reference = weakref.ref(session)
        epoch, generation, identity = session.epoch, session.vault.generation, session.vault.identity
        snapshot = session.vault.snapshot
        snapshot = weakref.ref(snapshot) if snapshot is not None else lambda: None
        config = self.app.startup
        request = dict(owner=reference, serial=self.serial, changed=self.changed_serial,
                       cancelled=False, claiming=False, signals=[])
        self.pending = request
        def current():
            if self.app.quitting:
                request["cancelled"] = True
            owner = reference()
            return bool(not self.closed and not request["cancelled"] and request["serial"] == self.serial
                and (request["claiming"] or request["changed"] == self.changed_serial)
                and config is self.app.startup and config.autotype["portal_clipboard"]
                and connection_epoch == self.app.portal_connections.epoch
                and self.app.portal_permissions.valid(permission)
                and owner is not None and not owner.jobs.closed and owner.epoch == epoch
                and owner.vault.generation == generation and owner.vault.identity is identity
                and owner.vault.snapshot is snapshot() and (valid is None or valid()))
        def hidden(window, _property):
            if not window.get_visible():
                request["cancelled"] = True
        window = session.host_window
        request["signals"].append((window, window.connect("notify::visible", hidden)))
        def before_claim():
            if not current():
                return False
            request["claiming"] = True
            return True
        def perform():
            keyboard, success = None, False
            try:
                from .portal_clipboard import available
                if not current() or not available() or not current():
                    return None
                keyboard = self.app.portal_connections.take(current)
                portal = keyboard.clipboard
                record = portal.claim(session, value, current, before_claim) if portal else None
                success = record is not None
                return (portal, record) if success else None
            except (GLib.Error, VaultError, OSError, ValueError):
                return None
            finally:
                self.app.portal_connections.finish(keyboard, success)
        def completed(result):
            success = False
            if result:
                portal, record = result
                if current():
                    success = portal.publish(record)
                if not success:
                    portal.clear(record)
            elif current() and not request["claiming"]:
                # Fallback cannot reclaim the selection after a portal claim/loss.
                request["claiming"] = True
                success = self._copy_gtk(session, value)
            self._finish_request(request)
            report(success)
        def failed(_message):
            request["cancelled"] = True
            self._finish_request(request)
            report(False)
        if not session.run_job(perform, completed, failed):
            request["cancelled"] = True
            self._finish_request(request)
            return report(False)
        return True

    def _copy_gtk(self, session, value):
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
        self._cancel_pending(session)
        for clipboard, record in list(self.records.items()):
            owner = record.owner()
            if session is None or owner is None or owner is session:
                self._clear_one(clipboard)
        for portal in self._portals():
            portal.clear(owner=session)

    def remaining(self):
        now = time.monotonic()
        gtk = max((record.deadline - now for clipboard, record in self.records.items()
                   if record.deadline and clipboard.get_content() == record.provider), default=0)
        return max(gtk, max((portal.remaining() for portal in self._portals()), default=0))

    def close(self):
        self.closed = True
        for clipboard, signal in self.signals.items():
            clipboard.disconnect(signal)
        self.signals.clear()
        self.regular.clear()
        self.clear()
