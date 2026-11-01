"""Public process control for the native Polkit broker; credentials bypass Python."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import threading
import time
from .backend import VaultError


class SystemAuthManager:
    def __init__(self):
        engine = shutil.which(os.environ.get("KEYSLOT_ENGINE", "keyslot-engine"))
        executable = Path(engine).parent / "keyslot-auth-broker" if engine else None
        if not executable or not executable.is_file():
            raise VaultError("Install Keyslot's native system-authentication broker.")
        self._mutex = threading.RLock()
        self._buffer = b""
        self._sequence = 0
        self.directory = tempfile.TemporaryDirectory(prefix="keyslot-auth-")
        self.path = Path(self.directory.name) / "broker"
        self.process = None
        try:
            self.process = subprocess.Popen([str(executable), str(self.path), str(os.getpid())],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0, close_fds=True,
                start_new_session=True)
            response = self._read()
            if response.get("event") != "ready" or response.get("protocol") != 1:
                raise VaultError("The system-authentication broker returned invalid startup data.")
            if response.get("available") is not True:
                raise VaultError(response.get("message") or "System authentication is unavailable.")
        except Exception:
            self.close()
            raise

    def _read(self):
        deadline = time.monotonic() + 8
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise VaultError("The system-authentication broker did not respond.")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise VaultError("The system-authentication broker stopped.")
            self._buffer += chunk
            if len(self._buffer) > 65536:
                raise VaultError("The system-authentication broker returned oversized control data.")
        frame, self._buffer = self._buffer.split(b"\n", 1)
        try:
            value = json.loads(frame)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeDecodeError) as exc:
            raise VaultError("The system-authentication broker returned invalid control data.") from exc

    def request(self, method, **options):
        with self._mutex:
            if self.process is None or self.process.poll() is not None:
                raise VaultError("System authentication stopped. Set it up again with the master password.")
            self._sequence += 1
            identifier = self._sequence
            frame = (json.dumps({"id": identifier, "method": method, **options}) + "\n").encode()
            try:
                while frame:
                    count = os.write(self.process.stdin.fileno(), frame)
                    if count <= 0:
                        raise OSError("closed control pipe")
                    frame = frame[count:]
                response = self._read()
                if response.get("id") != identifier or response.get("ok") is not True:
                    raise VaultError("The native broker rejected a process-control request.")
                return response
            except OSError as exc:
                raise VaultError("Communication with system authentication stopped.") from exc

    def register(self, pid):
        return self.request("register", pid=pid)

    def unregister(self, pid):
        return self.request("unregister", pid=pid)

    def commit(self, token):
        return self.request("commit", token=token)

    def forget(self, token):
        return self.request("forget", token=token)

    def close(self):
        with self._mutex:
            process, self.process = self.process, None
            try:
                if process:
                    process.stdin.close()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
                    process.stdout.close()
            finally:
                self.directory.cleanup()
