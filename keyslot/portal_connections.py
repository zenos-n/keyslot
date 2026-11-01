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
        self.closed = False

    def _cancel_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    @staticmethod
    def _discard(keyboard):
        if keyboard:
            threading.Thread(target=keyboard.close, name="keyslot-portal-close", daemon=True).start()

    def invalidate(self):
        with self.mutex:
            self.epoch += 1
            keyboard, self.idle = self.idle, None
            self.idle_until = 0
            self._cancel_timer()
            # Active workers keep their reservation until modifier cleanup finishes.
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
            config = self.application.startup
            keep = (success and keyboard.valid() and not keyboard.closed and not keyboard.disposed
                    and keyboard.pool_epoch == self.epoch and not self.closed)
            timeout = None if config.autotype["portal_connection"] else config.autotype["retype_seconds"]
            # Idle transports must retain no flow, vault, destination or entry closure.
            keyboard.valid = lambda: False
            if keep and (timeout is None or timeout > 0):
                self.active = None
                self.idle = keyboard
                self.idle_until = float("inf") if timeout is None else time.monotonic() + timeout
                if timeout is not None:
                    self.timer = threading.Timer(timeout, self._expire, (keyboard, self.epoch))
                    self.timer.daemon = True
                    self.timer.start()
                return
        try:
            keyboard.close()
        finally:
            with self.mutex:
                if self.active is keyboard:
                    self.active = None

    def _expire(self, keyboard, epoch):
        with self.mutex:
            if self.idle is not keyboard or epoch != self.epoch:
                return
            self.idle = self.timer = None
            self.idle_until = 0
        keyboard.close()

    def close(self):
        with self.mutex:
            self.closed = True
        self.invalidate()
