"""One cancellable Auto-Type invocation, from capture through approved execution."""
import threading
import weakref

from .backend import VaultError


class Flow:
    def __init__(self, source, allow_automatic, *, temporary=False):
        self.app = source.application
        self.allow_automatic = allow_automatic
        self.source = self.capture(source)
        self.temporary = self.source if temporary else None
        self.owner = self.source
        self.active = self.app.active_session
        self.cancelled = threading.Event()
        self.dialog = None
        self.closing = weakref.WeakSet()
        self.typing = self.switching = False
        self.watches = []
        self.watch(source)

    @staticmethod
    def capture(session):
        return (weakref.ref(session), session.epoch, session.vault.identity,
                session.vault.generation, weakref.ref(session.vault.snapshot))

    def watch(self, session):
        window = session.host_window
        if any(watched is window for watched, _handler in self.watches):
            return
        handler = window.connect("notify::visible", lambda window, _prop:
            self.cancel(lock=True) if not window.get_visible() else None)
        self.watches.append((window, handler))

    def valid(self):
        if (self.cancelled.is_set() or self.app.quitting or self.app.autotype_flow is not self
                or self.app.active_session is not self.active):
            return False
        for reference, epoch, identity, generation, snapshot in (self.source, self.owner):
            session = reference()
            if (session is None or session.jobs.closed or not session.vault.unlocked
                    or session.epoch != epoch or session.vault.identity is not identity
                    or session.vault.generation != generation or session.vault.snapshot is not snapshot()
                    or session.file_requests):
                return False
            if any(dialog is not self.dialog and dialog not in self.closing for dialog in tuple(session.dialogs)):
                return False
        return True

    def relock_owner(self):
        if not self.temporary or not self.app.startup.autotype["relock"]:
            return None
        reference, epoch, identity, generation, snapshot = self.temporary
        session = reference()
        if (session and not session.jobs.closed and session.vault.unlocked and session.epoch == epoch
                and session.vault.identity is identity and session.vault.generation == generation
                and session.vault.snapshot is snapshot()):
            return session
        return None

    def cancel(self, *, lock=False):
        if self.cancelled.is_set():
            return
        self.cancelled.set()
        if self.app.autotype_flow is self:
            self.app.autotype_flow = None
        for window, handler in self.watches:
            window.disconnect(handler)
        self.watches.clear()
        dialog, self.dialog = self.dialog, None
        if dialog:
            from .application import clear_dialog_fields
            clear_dialog_fields(dialog)
            dialog.force_close()
        owner = self.owner[0]()
        temporary = self.relock_owner()
        if lock and self.typing and owner and not owner.jobs.closed:
            owner.lock()
        if temporary and (temporary is not owner or not (lock and self.typing)):
            temporary.lock()
        self.temporary = None

    def cancel_for(self, session, *, locking=False):
        if self.switching:
            return
        if session in (self.source[0](), self.owner[0]()):
            self.cancel(lock=not locking or self.owner[0]() is not session)

    def select(self, session):
        self.switching = True
        try:
            self.app.select_session(session)
            self.active = session
        finally:
            self.switching = False

    def track(self, dialog):
        self.dialog = dialog
        dialog.connect("closed", lambda *_: self.cancel() if self.dialog is dialog else None)

    def present(self, session, dialog):
        if self.valid():
            self.select(session)
        if not self.valid():
            from .application import clear_dialog_fields
            clear_dialog_fields(dialog)
            self.cancel()
            return False
        self.track(dialog)
        if not session.present_dialog(dialog):
            self.release(dialog)
            self.cancel()
            return False
        return True

    def release(self, dialog):
        if self.dialog is dialog:
            self.dialog = None
            self.closing.add(dialog)

    def failed(self, session, message):
        if self.cancelled.is_set():
            return
        self.cancel()
        session.error(message)

    def run(self, session, operation, done):
        if not self.valid():
            self.cancel()
            return False
        def perform():
            if not self.valid():
                raise VaultError("Auto-Type was cancelled.")
            return operation()
        def completed(value):
            if self.valid():
                done(value)
            else:
                self.cancel()
        if not session.run_job(perform, completed, lambda message: self.failed(session, message)):
            self.cancel()
            return False
        return True
