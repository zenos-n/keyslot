"""One destination-bound unlock request; never a credential or typing approval."""
import os
import weakref
from pathlib import Path
from gi.repository import GLib
from . import autotype
from .application import clear_dialog_fields


class UnlockRequest:
    def __init__(self, session, allow_automatic):
        self.app = session.application
        self.owner = weakref.ref(session)
        self.path = Path(session.path).resolve()
        self.epoch = session.epoch
        self.allow_automatic = allow_automatic
        self.dialog = self.target = self.result = None
        self.closing = weakref.WeakSet()
        self.resetting = self.switching = self.cancelled = False
        self.watch = self.timer = 0
        self.deadline = GLib.timeout_add(180000, self.expired)
        self.app.autotype_unlock = self

    def valid(self):
        session = self.owner()
        monitor = self.app.desktop_lock
        try:
            return bool(not self.cancelled and self.app.autotype_unlock is self and not self.app.quitting
                and session and not session.jobs.closed and session in self.app.sessions
                and self.app.active_session is session and session.epoch == self.epoch
                and session.path and Path(session.path).resolve() == self.path
                and not (monitor and monitor.blocked))
        except OSError:
            return False

    def cancel(self, *, lock=True):
        if self.cancelled:
            return
        self.cancelled = True
        if self.app.autotype_unlock is self:
            self.app.autotype_unlock = None
        session = self.owner()
        if self.watch and session:
            session.host_window.disconnect(self.watch)
        self.watch = 0
        for name in ("timer", "deadline"):
            if handle := getattr(self, name):
                GLib.source_remove(handle)
                setattr(self, name, 0)
        dialogs = list(self.closing)
        if self.dialog:
            dialogs.append(self.dialog)
        self.dialog = self.target = self.result = None
        for dialog in dialogs:
            clear_dialog_fields(dialog)
            dialog.force_close()
        self.closing.clear()
        if lock and session and not session.jobs.closed:
            session.lock()

    def cancel_for(self, session, *, locking=False):
        if self.owner() is session and not self.resetting and not self.switching:
            self.cancel(lock=not locking)

    def expired(self):
        self.deadline = 0
        session = self.owner()
        self.cancel()
        if session and session.active:
            session.toast("Auto-Type unlock request expired. Invoke Auto-Type again.")
        return GLib.SOURCE_REMOVE

    def reset(self):
        if not self.valid():
            self.cancel()
            return False
        session = self.owner()
        if session.vault.unlocked:
            self.cancel()
            return False
        self.resetting = True
        try:
            session.lock()
            self.epoch = session.epoch
        finally:
            self.resetting = False
        return self.valid()

    def present(self, dialog):
        if not self.valid():
            clear_dialog_fields(dialog)
            self.cancel()
            return False
        self.dialog = dialog
        dialog.set_title("Unlock for Auto-Type")
        dialog.connect("closed", lambda *_: self.cancel() if self.dialog is dialog else None)
        self.owner().present_unlock_prompt(dialog)
        return not self.cancelled

    def owns(self, dialog):
        return self.valid() and self.dialog is dialog

    def release(self, dialog):
        if self.dialog is dialog:
            self.dialog = None
            self.closing.add(dialog)

    def open(self, target=None):
        if not self.valid():
            self.cancel()
            return
        self.target = target
        session = self.owner()
        session.pending_unlock = None
        session.dismiss_unlock_prompt()
        self.switching = True
        try:
            self.app.select_session(session, activate=False)
        finally:
            self.switching = False
        self.watch = session.host_window.connect("notify::visible", lambda window, _prop:
            self.cancel() if not window.get_visible() else None)
        session._unlock_dialog(self.path, resume=self)

    def finished(self, snapshot):
        session = self.owner()
        if (not self.valid() or not session.vault.unlocked or session.vault.snapshot is not snapshot
                or session.vault.path != self.path):
            self.cancel()
            return
        self.result = (session.vault.identity, session.vault.generation, weakref.ref(snapshot))
        self.timer = GLib.timeout_add(50, self.resume)

    def resume(self):
        session = self.owner()
        if not self.valid() or not self.result:
            self.timer = 0
            self.cancel()
            return GLib.SOURCE_REMOVE
        identity, generation, snapshot = self.result
        if (not session.vault.unlocked or session.vault.identity is not identity
                or session.vault.generation != generation or session.vault.snapshot is not snapshot()):
            self.timer = 0
            self.cancel()
            return GLib.SOURCE_REMOVE
        if session.busy or session.dialogs or session.file_requests:
            return GLib.SOURCE_CONTINUE
        self.timer = 0
        target = self.target
        automatic = self.allow_automatic
        self.cancel(lock=False)
        from .autotype_views import choose
        choose(session, target=target, allow_automatic=automatic, temporary=True)
        return GLib.SOURCE_REMOVE


def request(session, *, allow_automatic=True, global_shortcut=False):
    app = session.application
    if global_shortcut and any(item.host_window.is_active() for item in app.sessions):
        return
    if app.autotype_unlock or app.autotype_flow:
        session.toast("Auto-Type is already in progress")
        return
    if (not session.path or session.busy or session.vault.finishing or session.file_requests
            or any(dialog is not session.unlock_prompt for dialog in session.dialogs)):
        app.select_session(session)
        session.toast("Open a vault and finish the current operation before using Auto-Type")
        return
    if app.desktop_lock and app.desktop_lock.blocked:
        return
    if app.active_session is None:
        app.active_session, app.window = session, session.host_window
    try:
        pending = UnlockRequest(session, allow_automatic)
    except OSError:
        session.error("The vault path is no longer available. Open it again before using Auto-Type.")
        return
    if os.environ.get("XDG_SESSION_TYPE") == "wayland":
        def failed(message):
            pending.cancel()
            app.select_session(session, activate=False)
            session.error(message)
        if not session.run_job(autotype.capture_target, pending.open, failed):
            pending.cancel()
    else:
        # X11 keeps its explicit native destination chooser after the unlock.
        pending.open()
