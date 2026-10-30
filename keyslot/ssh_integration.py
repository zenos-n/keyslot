"""Application lifecycle for the native SSH relay and saved KeeAgent policies."""
from concurrent.futures import ThreadPoolExecutor
import threading

from .backend import VaultError
from .ssh_agent import SSHAgentManager


class SSHIntegration:
    def __init__(self, application, dispatch, factory=SSHAgentManager):
        self.app, self.dispatch, self.factory = application, dispatch, factory
        self.manager = None
        self.error = ""
        self.starting = self.closed = False
        self._generation = 0
        self._mutex = threading.Lock()
        self._states = {}
        self._checking = False
        self._cleanup_failed = False
        self._warned = set()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ssh-control")

    @property
    def ready(self):
        return self.manager is not None and self.manager.process is not None and self.manager.process.poll() is None

    def start(self):
        if self.closed or self.starting or self.ready:
            return
        self.starting, self.error = True, ""
        generation = self._generation
        def launch():
            try:
                manager = self.factory()
            except (OSError, ValueError, VaultError) as exc:
                self.dispatch(lambda message=str(exc): self._started(generation, message))
                return
            with self._mutex:
                keep = not self.closed and generation == self._generation
                if keep:
                    self.manager = manager
            if not keep:
                manager.close()
            else:
                self.dispatch(lambda: self._started(generation, ""))
        self.executor.submit(launch)

    def _started(self, generation, error):
        if not self.closed and generation == self._generation:
            self.starting = False
            self.error = error
            if error:
                self._warning("SSH integration could not start. " + error)
            self.state_changed()
        return False

    def stop(self):
        with self._mutex:
            self._generation += 1
            self.starting = False
            manager, self.manager = self.manager, None
        self._states.clear()
        if manager:
            def retire():
                try:
                    manager.close()
                    failed = not manager.cleanup_ok
                except (OSError, ValueError, VaultError):
                    failed = True
                if failed:
                    self._cleanup_failed = True
                    self.dispatch(lambda: self._warning("SSH key cleanup was not confirmed. Review and remove remaining keys in your SSH agent."))
            self.executor.submit(retire)

    def restart(self):
        self.stop()
        self.start()

    def _warning(self, message, session=None):
        self.error = message
        if self.closed or message in self._warned:
            return False
        self._warned.add(message)
        session = session or self.app.active_session
        if session and not session.jobs.closed:
            session.error(message)
        return False

    def _valid(self, session, state):
        return (not self.closed and self.ready and self._states.get(session) is state
                and session in self.app.sessions and session.vault.unlocked
                and not session.jobs.closed and state["key"] == self._key(session))

    def _key(self, session):
        settings = self.app.startup
        return session.epoch, session.vault.identity, settings.ssh_socket, settings.ssh_provider, self.manager

    def state_changed(self):
        if self.closed:
            return
        for session in list(self._states):
            if session not in self.app.sessions or not session.vault.unlocked or session.jobs.closed:
                self._states.pop(session, None)
        if not self.app.startup.ssh or not self.ready:
            for session in self.app.sessions:
                if (session.vault.unlocked and not session.jobs.closed and not session.jobs.busy
                        and getattr(session.vault, "ssh_manager", None) is not None):
                    session.jobs.run(lambda session=session: session.vault.ssh_configure(None),
                                     failed=lambda message: self._warning(message), interactive=False)
            return
        for session in list(self.app.sessions):
            if not session.vault.unlocked or session.jobs.closed:
                continue
            state = self._states.get(session)
            if state is None or state["key"] != self._key(session):
                state = {"key": self._key(session), "configured": False, "busy": False,
                         "queue": [], "errors": [], "done": False}
                self._states[session] = state
            if state["busy"] or state["done"] or session.jobs.busy:
                continue
            state["busy"] = True
            manager = self.manager
            socket, provider = self.app.startup.ssh_socket, self.app.startup.ssh_provider
            configuring = not state["configured"]
            identifier = state["queue"][0] if not configuring and state["queue"] else None
            title = next((entry.title for entry in session.vault.snapshot.entries if entry.uuid == identifier), "SSH Key")
            if not configuring and identifier is None:
                state["busy"], state["done"] = False, True
                if state["errors"]:
                    self._warning("Some SSH keys could not be loaded. " + " ".join(state["errors"][:3]), session)
                continue
            def operation(session=session, state=state, configuring=configuring, identifier=identifier,
                          manager=manager, socket=socket, provider=provider):
                if not self._valid(session, state):
                    raise VaultError("SSH integration changed before the operation started.")
                if configuring:
                    session.vault.ssh_configure(manager, socket, provider)
                    return [entry.uuid for entry in session.vault.snapshot.entries
                            if not entry.recycled and "KeeAgent.settings" in entry.attachments]
                entry = next((entry for entry in session.vault.snapshot.entries if entry.uuid == identifier), None)
                if entry is None or entry.recycled:
                    return
                settings = session.vault.ssh_settings(entry)
                if settings["enabled"] and settings["auto_add"] and settings["configured"]:
                    review = session.vault.ssh_prepare(entry)
                    if not self._valid(session, state):
                        raise VaultError("SSH integration changed before the key was added.")
                    session.vault.ssh_add(review["token"], approved=True)
            def done(result, session=session, state=state, configuring=configuring):
                if not self._valid(session, state):
                    return
                if configuring:
                    state["configured"], state["queue"] = True, result
                else:
                    state["queue"].pop(0)
                state["busy"] = False
                self.dispatch(self.state_changed)
            def failed(message, session=session, state=state, configuring=configuring, title=title):
                if not self._valid(session, state):
                    return
                state["busy"] = False
                if configuring:
                    state["done"] = True
                    self._warning("SSH integration could not connect to this vault. " + message, session)
                else:
                    state["queue"].pop(0)
                    if len(state["errors"]) < 3:
                        state["errors"].append(title + ": " + message)
                    self.dispatch(self.state_changed)
            if not session.jobs.run(operation, done, failed, interactive=False):
                state["busy"] = False

    def check(self, retry=False):
        self.state_changed()
        if self.closed or self._checking or not self.manager:
            return
        if not self.ready:
            self._warning("The SSH relay stopped unexpectedly. Key removal was not confirmed; review your SSH agent.")
            return
        self._checking = True
        manager, generation = self.manager, self._generation
        def check():
            try:
                result = manager.retry_cleanup() if retry else manager.status()
                error = "" if result["cleanup_ok"] else "SSH key cleanup failed. Review your agent and use Retry Cleanup in Preferences."
            except (OSError, ValueError, VaultError) as exc:
                error = str(exc)
            self.dispatch(lambda: completed(error))
        def completed(error):
            self._checking = False
            if not self.closed and generation == self._generation:
                if error:
                    self._warning(error)
                elif retry:
                    self.error = ""
                    self._warned.clear()
            return False
        self.executor.submit(check)

    def close(self):
        if self.closed:
            return not self._cleanup_failed
        self.closed = True
        self.stop()
        # Stop the relay before vault workers unregister; a starting relay retires itself.
        self.executor.shutdown(wait=True, cancel_futures=False)
        return not self._cleanup_failed
