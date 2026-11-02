"""Owned text selection on a RemoteDesktop session; never reads the clipboard."""
from dataclasses import dataclass
import os
import select
import threading
import time
import weakref

from gi.repository import Gio, GLib
from .backend import VaultError

INTERFACE = "org.freedesktop.portal.Clipboard"
PATH = "/org/freedesktop/portal/desktop"
FORMATS = ("text/plain;charset=utf-8", "text/plain", "x-kde-passwordManagerHint")
MAX_BYTES = 16 * 1024 * 1024


def available():
    try:
        connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        version = connection.call_sync("org.freedesktop.portal.Desktop", PATH,
            "org.freedesktop.DBus.Properties", "Get", GLib.Variant("(ss)", (INTERFACE, "version")),
            GLib.VariantType.new("(v)"), Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
        return type(version) is int and version >= 1
    except GLib.Error:
        return False


@dataclass
class Selection:
    data: bytearray
    owner: object
    epoch: int
    permission: object
    connection_epoch: int
    pending_valid: object
    pending_until: float
    owned: bool = False
    published: bool = False
    cancelled: bool = False
    started: float = 0
    deadline: float = 0
    timer: object = None
    stamp: object = None


class PortalClipboard:
    def __init__(self, keyboard, application):
        self.keyboard = keyboard
        self.app = application
        self.connection, self.owner, self.session = keyboard.connection, keyboard.owner, keyboard.session
        self.mutex = threading.RLock()
        self.selection = None
        self.enabled = self.closed = False
        self.requested = False
        self.signals = []
        self.inflight = set()
        self.slots = threading.BoundedSemaphore(8)
        self.app.clipboards.watch_portal(self)

    def _call(self, method, parameters, timeout=3000):
        return self.connection.call_sync(self.owner, PATH, INTERFACE, method, parameters,
            None, Gio.DBusCallFlags.NO_AUTO_START, timeout, None)

    def request(self):
        try:
            version = self.connection.call_sync(self.owner, PATH, "org.freedesktop.DBus.Properties", "Get",
                GLib.Variant("(ss)", (INTERFACE, "version")), GLib.VariantType.new("(v)"),
                Gio.DBusCallFlags.NO_AUTO_START, 3000, None).unpack()[0]
            if type(version) is not int or version < 1 or self.closed:
                return False
            self.signals = [self.connection.signal_subscribe(self.owner, INTERFACE, name, PATH, None,
                Gio.DBusSignalFlags.NONE, callback) for name, callback in
                (("SelectionTransfer", self._transfer), ("SelectionOwnerChanged", self._owner_changed))]
            self._call("RequestClipboard", GLib.Variant("(oa{sv})", (self.session, {})))
            self.requested = True
            return True
        except GLib.Error:
            return False

    def _live(self, record, owned=True):
        owner = record.owner()
        now = time.monotonic()
        return bool(self.selection is record and not record.cancelled and not self.closed and self.enabled
            and not self.app.clipboards.closed and self.app.startup.autotype["portal_clipboard"]
            and not self.keyboard.closed and not self.keyboard.disposed
            and owner is not None and not owner.jobs.closed and owner.epoch == record.epoch
            and record.connection_epoch == self.app.portal_connections.epoch
            and self.app.portal_permissions.valid(record.permission)
            and (not owned or record.owned)
            and ((record.published and (not record.deadline or now < record.deadline))
                 or (not record.published and now < record.pending_until and record.pending_valid())))

    def holds_selection(self):
        with self.mutex:
            return self.selection is not None and self._live(self.selection)

    def _schedule(self, record):
        if record.timer:
            record.timer.cancel()
        record.timer = None
        record.stamp = object()
        deadline = record.deadline if record.published else record.pending_until
        if deadline:
            record.timer = threading.Timer(max(0.001, deadline - time.monotonic()), self._expire,
                                            (record, record.stamp))
            record.timer.daemon = True
            try:
                record.timer.start()
            except RuntimeError:
                return False
        return True

    def _expire(self, record, stamp):
        self.clear(record, stamp=stamp)

    def _drop(self, record, notify=True):
        with self.mutex:
            if self.selection is not record:
                return False
            self.selection = None
            record.cancelled = True
            record.pending_valid = lambda: False
            if record.timer:
                record.timer.cancel()
                record.timer = None
            record.stamp = None
            record.data[:] = b"\0" * len(record.data)
            record.data = bytearray()
        if notify:
            self.app.portal_connections.clipboard_released(self.keyboard)
        return True

    def claim(self, session, value, valid, before_claim):
        if not self.enabled or self.closed or len(value) > MAX_BYTES:
            return None
        data = bytearray(value.encode("utf-8"))
        if len(data) > MAX_BYTES:
            data[:] = b"\0" * len(data)
            return None
        if not valid() or not before_claim():
            data[:] = b"\0" * len(data)
            raise VaultError("The clipboard request was cancelled.")
        record = Selection(data, weakref.ref(session), session.epoch, self.keyboard.ticket,
                           self.keyboard.pool_epoch, valid, time.monotonic() + 5)
        with self.mutex:
            old = self.selection
        if old:
            self._drop(old)
        with self.mutex:
            self.selection = record
            scheduled = self._schedule(record)
        try:
            if not scheduled:
                raise VaultError("The clipboard timeout could not be started.")
            self.keyboard._check()
            self._call("SetSelection", GLib.Variant("(oa{sv})", (self.session,
                {"mime_types": GLib.Variant("as", FORMATS)})))
            with self.mutex:
                if self._live(record, owned=False):
                    record.owned = True
                if not self._live(record):
                    raise VaultError("The desktop did not retain clipboard ownership.")
            return record
        except Exception:
            self.clear(record)
            raise

    def publish(self, record):
        with self.mutex:
            if not self._live(record):
                return False
            record.published = True
            record.pending_valid = lambda: False
            record.started = time.monotonic()
            seconds = self.app.startup.clipboard_seconds
            record.deadline = record.started + seconds if seconds else 0
            scheduled = self._schedule(record)
        if not scheduled:
            self.clear(record)
        return scheduled

    def refresh(self):
        with self.mutex:
            record = self.selection
            if record is None or not record.published:
                return
            seconds = self.app.startup.clipboard_seconds
            record.deadline = record.started + seconds if seconds else 0
            scheduled = self._live(record) and self._schedule(record)
        if not scheduled:
            self.clear(record)

    def remaining(self):
        with self.mutex:
            record = self.selection
            return max(0, record.deadline - time.monotonic()) if record and record.published and self._live(record) and record.deadline else 0

    def clear(self, record=None, owner=None, stamp=None):
        with self.mutex:
            record = self.selection if record is None else record
            if (record is None or self.selection is not record
                    or (owner is not None and record.owner() is not owner)
                    or (stamp is not None and record.stamp is not stamp)):
                return
            self.keyboard.closed = True
            dropped = self._drop(record, notify=False)
        if dropped:
            # Closing only our session cannot claim/erase a newer foreign selection.
            self.app.portal_connections.invalidate(self.keyboard)

    def _owner_changed(self, _connection, _sender, _path, _interface, _signal, parameters):
        session, options = parameters.unpack()
        if session != self.session or type(options.get("session_is_owner")) is not bool:
            return
        with self.mutex:
            record = self.selection
            if record is None:
                return
            if options["session_is_owner"]:
                record.owned = True
                return
            lost = record.owned
        if lost:
            self._drop(record)

    def _done(self, serial, success):
        try:
            self.connection.call(self.owner, PATH, INTERFACE, "SelectionWriteDone",
                GLib.Variant("(oub)", (self.session, serial, success)), None,
                Gio.DBusCallFlags.NO_AUTO_START, 3000, None, None)
        except GLib.Error:
            pass

    def _transfer(self, _connection, _sender, _path, _interface, _signal, parameters):
        session, mime, serial = parameters.unpack()
        if session != self.session:
            return
        with self.mutex:
            if serial in self.inflight:
                return
            record = self.selection
            accepted = (record is not None and mime in FORMATS and self._live(record, owned=False)
                        and self.slots.acquire(blocking=False))
            if accepted:
                # A transfer from the bound portal is itself an ownership acknowledgement.
                record.owned = True
                self.inflight.add(serial)
        if not accepted:
            self._done(serial, False)
            return
        try:
            threading.Thread(target=self._serve, args=(record, mime, serial),
                             name="portal-clipboard", daemon=True).start()
        except RuntimeError:
            with self.mutex:
                self.inflight.discard(serial)
                self.slots.release()
            self._done(serial, False)

    def _serve(self, record, mime, serial):
        fd, data, success = None, None, False
        try:
            with self.mutex:
                if not self._live(record):
                    return
            if not self.keyboard.same_owner():
                self.clear(record)
                return
            reply, descriptors = self.connection.call_with_unix_fd_list_sync(self.owner, PATH, INTERFACE,
                "SelectionWrite", GLib.Variant("(ou)", (self.session, serial)), GLib.VariantType.new("(h)"),
                Gio.DBusCallFlags.NO_AUTO_START, 3000, None, None)
            index = reply.unpack()[0]
            if descriptors is None or type(index) is not int or not 0 <= index < descriptors.get_length():
                return
            fd = descriptors.get(index)
            descriptors = None
            os.set_blocking(fd, False)
            with self.mutex:
                if not self._live(record):
                    return
                data = memoryview(b"secret") if mime == FORMATS[2] else memoryview(record.data)
            position, deadline = 0, time.monotonic() + 5
            while position < len(data):
                with self.mutex:
                    if not self._live(record) or time.monotonic() >= deadline:
                        return
                if not select.select([], [fd], [], 0.05)[1]:
                    continue
                with self.mutex:
                    if not self._live(record) or time.monotonic() >= deadline:
                        return
                    try:
                        count = os.write(fd, data[position:position + 65536])
                    except BlockingIOError:
                        continue
                if count <= 0:
                    return
                position += count
            with self.mutex:
                success = self._live(record)
        except (GLib.Error, OSError, ValueError):
            pass
        finally:
            if data is not None:
                data.release()
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._done(serial, success)
            with self.mutex:
                self.inflight.discard(serial)
                self.slots.release()

    def close(self):
        with self.mutex:
            if self.closed:
                return
            self.closed = True
            record = self.selection
        if record:
            self._drop(record)
        for signal in self.signals:
            self.connection.signal_unsubscribe(signal)
        self.signals.clear()
        self.app.clipboards.unwatch_portal(self)
