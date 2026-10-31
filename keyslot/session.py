"""One cancellable worker queue per database, independent of the visible tab."""
from concurrent.futures import ThreadPoolExecutor

from .backend import VaultError


class SessionJobs:
    def __init__(self, vault, dispatch, changed, clear, error):
        self.vault = vault
        self.dispatch = dispatch
        self.changed = changed
        self.clear = clear
        self.error = error
        self.epoch = 0
        self.busy = False
        self.interactive = True
        self._active = {}
        self.closed = False
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vault")

    def run(self, operation, done=None, failed=None, *, interactive=True):
        # Queue bounded browser polling behind saves, reserving one foreground action.
        if (self.closed or (interactive and self.busy and self.interactive)
                or (not interactive and sum(not value for value in self._active.values()) >= 8)):
            return False
        token = object()
        self._active[token] = interactive
        self._activity()
        epoch = self.epoch
        generation = self.vault.generation
        self.changed()

        def perform():
            if self.closed or epoch != self.epoch:
                raise VaultError("The operation was cancelled.")
            with self.vault.operation(generation):
                return operation()

        future = self.executor.submit(perform)

        def complete():
            if self.closed or epoch != self.epoch:
                return False
            self._active.pop(token, None)
            self._activity()
            self.changed()
            try:
                result = future.result()
                if done:
                    done(result)
            except (VaultError, OSError, ValueError) as exc:
                if not self.vault.unlocked:
                    self.lock()
                    self.error(str(exc))
                elif failed:
                    failed(str(exc))
                else:
                    self.error(str(exc))
            except Exception:
                self.lock()
                self.error("An unexpected error occurred. Lock and reopen this database before continuing.")
            return False

        future.add_done_callback(lambda _future: self.dispatch(complete))
        return True

    def _activity(self):
        self.busy = bool(self._active)
        self.interactive = any(self._active.values()) if self._active else True

    def lock(self):
        if self.closed:
            return
        self.epoch += 1
        self.vault.cancel()
        self._active.clear()
        self._activity()
        self.clear()
        self.changed()
        self.executor.submit(self.vault.finish_lock)

    def close(self):
        if self.closed:
            return
        self.lock()
        self.closed = True
        self.vault.lock()
        self.executor.shutdown(wait=True, cancel_futures=True)
