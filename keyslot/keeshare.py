"""Poll configured KeeShare files while an unlocked helper is available."""
import time


class KeeShareIntegration:
    def __init__(self, app):
        self.app = app
        self.states = {}
        self.closed = False

    def close(self):
        self.closed = True
        self.states.clear()

    def state_changed(self):
        if self.closed:
            return
        settings = self.app.startup
        options = dict(settings.keeshare)
        self.states = {session: state for session, state in self.states.items()
                       if session in self.app.sessions and session.vault.unlocked and not session.jobs.closed}
        if not any(options.values()):
            self.states.clear()
            return
        for session in list(self.app.sessions):
            if not session.vault.unlocked or session.jobs.closed:
                continue
            key = session.epoch, session.vault.identity, tuple(options.items())
            state = self.states.get(session)
            if not state or state["key"] != key:
                state = {"key": key, "next": 0, "warning": None}
                self.states[session] = state
            if session.jobs.busy or state["next"] > time.monotonic():
                continue
            state["next"] = time.monotonic() + 30
            def perform(session=session, options=options):
                session.vault.keeshare_configure(settings.directory, options)
                return session.vault.keeshare_sync()
            def completed(result, session=session, state=state):
                if self.states.get(session) is not state or self.closed:
                    return
                if result["imports"]:
                    session.window.show_vault(session.vault.snapshot)
                warning = "\n".join(dict.fromkeys(result["warnings"]))
                if warning and warning != state["warning"]:
                    session.error("KeeShare synchronization needs attention.\n\n" + warning)
                state["warning"] = warning
            def failed(message, session=session, state=state):
                if self.states.get(session) is state and not self.closed and message != state["warning"]:
                    state["warning"] = message
                    session.error("KeeShare synchronization stopped.\n\n" + message)
            session.jobs.run(perform, completed, failed, interactive=False)
