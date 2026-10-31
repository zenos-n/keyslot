"""Private native Secret Service sessions; DH/AES keys never enter Python."""
import base64
from .core_backend import Vault, EngineError
from .backend import VaultError


class SecretCipher:
    def __init__(self):
        self.vault = Vault()
        self.closed = False

    def open(self, peer, algorithm, value):
        with self.vault._mutex:
            if self.closed:
                raise VaultError("Secret Service is stopped.")
            if self.vault._process is None:
                self.vault._start()
            result = self.vault._rpc("secret.session.open", peer=peer, algorithm=algorithm, input=value)
            return result | {"identity": self.vault.identity}

    def call(self, operation, peer, session, identity, **values):
        with self.vault._mutex:
            if self.closed or self.vault._process is None or self.vault.identity is not identity:
                raise EngineError("no_session", "The Secret Service session ended. Open a new session.")
            return self.vault._rpc("secret.session." + operation, peer=peer, session=session, **values)

    def drop_peer(self, peer):
        with self.vault._mutex:
            if not self.closed and self.vault._process is not None:
                self.vault._rpc("secret.session.drop-peer", peer=peer)

    def cancel(self):
        self.closed = True
        self.vault.cancel()

    def close(self):
        self.cancel()
        self.vault.finish_lock()


def encoded(value):
    return base64.b64encode(bytes(value)).decode("ascii")


def decoded(value):
    return base64.b64decode(value, validate=True)
