"""One application keyboard transport; every use gets a fresh invocation lease."""
import threading
import time

from .autotype import PortalKeyboard
from .backend import VaultError


class PortalConnections:
    def __init__(self, application):
        self.application = application
        self.mutex = threading.RLock()
        self.epoch = 0
        self.active = self.idle = self.timer = None
        self.idle_until = 0
        self.idle_stamp = None
        self.closed = False

    def _cancel_timer(self):
        self.idle_stamp = None
        if self.timer:
            self.timer.cancel()
            self.timer = None

    @staticmethod
    def _discard(keyboard):
        if keyboard:
            try:
                threading.Thread(target=keyboard.close, name="keyslot-portal-close", daemon=True).start()
            except RuntimeError:
                keyboard.close()

    def invalidate(self, keyboard=None):
        with self.mutex:
            if keyboard is None or keyboard is self.idle or keyboard is self.active:
                self.epoch += 1
                idle, self.idle = self.idle, None
                self.idle_until = 0
                self._cancel_timer()
                # Active workers keep their reservation until modifier cleanup finishes.
                keyboard = idle
        self._discard(keyboard)

    def _retain(self, keyboard):
        self._cancel_timer()
        config = self.application.startup
        held = keyboard.clipboard is not None and keyboard.clipboard.holds_selection()
        timeout = None if held or config.autotype["portal_connection"] else config.autotype["retype_seconds"]
        if timeout == 0:
            return False
        self.idle = keyboard
        self.idle_stamp = object()
        self.idle_until = float("inf") if timeout is None else time.monotonic() + timeout
        if timeout is not None:
            self.timer = threading.Timer(timeout, self._expire, (keyboard, self.idle_stamp))
            self.timer.daemon = True
            try:
                self.timer.start()
            except RuntimeError:
                self.idle = self.timer = self.idle_stamp = None
                self.idle_until = 0
                return False
        return True

    def clipboard_released(self, keyboard):
        with self.mutex:
            if self.idle is not keyboard or (keyboard.clipboard and keyboard.clipboard.holds_selection()):
                return
            if not self.closed and not keyboard.closed and not keyboard.disposed and self._retain(keyboard):
                return
            self.idle = None
            self.idle_until = 0
            self._cancel_timer()
        self._discard(keyboard)

    def take(self, valid):
        permissions = self.application.portal_permissions
        ticket = permissions.capture()
        stale = None
        with self.mutex:
            if self.closed:
                raise VaultError("The keyboard connection is closed.")
            if self.active is not None:
                raise VaultError("The previous keyboard operation is still finishing. Try again.")
            self._cancel_timer()
            keyboard, self.idle = self.idle, None
            if keyboard and (keyboard.closed or keyboard.disposed or time.monotonic() >= self.idle_until
                             or keyboard.ticket != ticket):
                stale, keyboard = keyboard, None
            self.idle_until = 0
            reused = keyboard is not None
            try:
                keyboard = keyboard or PortalKeyboard(lambda: False, permissions)
            except Exception:
                self._discard(stale)
                raise
            self.active = keyboard
            epoch = self.epoch
            def lease():
                return (not self.closed and epoch == self.epoch and self.active is keyboard
                        and permissions.valid(ticket) and valid())
            keyboard.valid = lease
            keyboard.pool_epoch = epoch
        self._discard(stale)
        try:
            if reused and not keyboard.same_owner():
                keyboard.close()
                with self.mutex:
                    if not lease():
                        raise VaultError("The keyboard operation was cancelled.")
                    replacement = PortalKeyboard(lambda: False, permissions)
                    keyboard = replacement
                    self.active = keyboard
                    keyboard.valid = lease
                    keyboard.pool_epoch = epoch
                reused = False
            if not reused:
                keyboard.open(ticket)
            keyboard._check()
            return keyboard
        except Exception:
            self.finish(keyboard, False)
            raise

    def finish(self, keyboard, success):
        if keyboard is None:
            return
        with self.mutex:
            if self.active is not keyboard:
                return
            keep = (success and keyboard.valid() and not keyboard.closed and not keyboard.disposed
                    and keyboard.pool_epoch == self.epoch and not self.closed)
            # Idle transports must retain no flow, vault, destination or entry closure.
            keyboard.valid = lambda: False
            if keep and self._retain(keyboard):
                self.active = None
                return
        try:
            keyboard.close()
        finally:
            with self.mutex:
                if self.active is keyboard:
                    self.active = None

    def _expire(self, keyboard, stamp):
        with self.mutex:
            if self.idle is not keyboard or stamp is not self.idle_stamp:
                return
            self.idle = self.timer = None
            self.idle_until = 0
            self.idle_stamp = None
        keyboard.close()

    def close(self):
        with self.mutex:
            self.closed = True
        self.invalidate()
