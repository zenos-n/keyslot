"""Single-use portal permission rotation; independent of vault and focus approval."""
import threading

from .backend import VaultError
from .core_backend import Vault

RESTORE_KEY = "AutoTypeDesktopPortalRestoreToken"


def _token(value):
    if not isinstance(value, str) or any(char in value for char in ("\0", "\n", "\r")):
        return False
    try:
        return len(value.encode("utf-8")) <= 16384
    except UnicodeError:
        return False


def _exchange(config, replacement=None):
    """Consume before reuse, or store only into the empty slot we consumed."""
    with config.mutex:
        storage = config.storage
        path = storage.paths["local"] if storage else str(config.path.parent / "portal-permission.ini")
        record = {"path": path, "defaults": {RESTORE_KEY: ""}}
        client = None
        def request(write, records):
            nonlocal client
            if storage:
                with storage.mutex:
                    return storage._request(write, records)
            if client is None:
                client = Vault()
            return client.configuration(write, records)["files"]
        try:
            if replacement is None:
                previous = request(False, [record])[0]["values"][RESTORE_KEY]
                if previous:
                    request(True, [dict(record, values={RESTORE_KEY: ""}, expected={RESTORE_KEY: previous})])
                return previous if _token(previous) else ""
            if replacement:
                request(True, [dict(record, values={RESTORE_KEY: replacement}, expected={RESTORE_KEY: ""})])
        finally:
            if client:
                client.lock()


class PortalPermissions:
    def __init__(self, application):
        self.application = application
        self.mutex = threading.RLock()
        self.config = None
        self.mode = None
        self.epoch = 0
        self.token = ""
        self.cleaned = None
        self.closed = False

    def _bind(self):
        config = self.application.startup
        mode = config.autotype["portal_mode"]
        if self.config is not config or self.mode != mode:
            self.config = config
            self.mode = mode
            self.invalidate()
            self.cleaned = None
        return config

    def invalidate(self):
        # Immediate invalidation also stops a worker currently saving a token.
        self.epoch += 1
        self.token = ""

    def valid(self, ticket):
        epoch, config, mode = ticket
        return (not self.closed and epoch == self.epoch and config is self.application.startup
                and config.autotype["portal_mode"] == mode)

    def begin(self, supported=True):
        with self.mutex:
            config = self._bind()
            mode = config.autotype["portal_mode"]
            ticket = (self.epoch, config, mode)
            if not self.valid(ticket):
                raise VaultError("Keyboard permission was cancelled.")
            if not supported:
                return ticket, ""
            if mode == 2:
                token = _exchange(config)
            else:
                if self.cleaned != (config, mode):
                    _exchange(config)
                    self.cleaned = (config, mode)
                token = self.token if mode == 1 else ""
                self.token = ""
            if not self.valid(ticket):
                raise VaultError("Keyboard permission was cancelled.")
            return ticket, token

    def granted(self, ticket, token):
        with self.mutex:
            if not self.valid(ticket):
                raise VaultError("Keyboard permission was cancelled.")
            if not _token(token):
                raise VaultError("The keyboard portal returned invalid permission information.")
            _epoch, config, mode = ticket
            if mode == 2:
                _exchange(config, token)
            elif mode == 1:
                self.token = token
            if not self.valid(ticket):
                self.token = ""
                raise VaultError("Keyboard permission was cancelled.")

    def forget(self, expected_config=None):
        self.invalidate()
        with self.mutex:
            config = self._bind()
            if expected_config is not None and expected_config is not config:
                raise VaultError("The configuration changed. Open Preferences again.")
            _exchange(config)
            self.cleaned = None

    def close(self):
        self.closed = True
        self.invalidate()
