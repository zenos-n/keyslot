"""Public process control for the native SSH relay; private key traffic bypasses Python."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque

from .backend import VaultError


class SSHAgentManager:
    def __init__(self, executable=None, timeout=12):
        candidate = executable or os.environ.get("KEYSLOT_SSH_AGENT")
        if not candidate and os.environ.get("KEYSLOT_ENGINE"):
            candidate = str(Path(os.environ["KEYSLOT_ENGINE"]).parent / "keyslot-ssh-agent")
        self.executable = shutil.which(str(candidate or "keyslot-ssh-agent"))
        if not self.executable:
            raise VaultError("Install Keyslot's native SSH agent helper.")
        self.timeout = timeout
        self._mutex = threading.RLock()
        self._buffer = b""
        self._sequence = 0
        self.events = deque(maxlen=64)
        self.cleanup_ok = True
        self._stopped = False
        self.directory = tempfile.TemporaryDirectory(prefix="ksssh-", dir="/tmp")
        self.path = Path(self.directory.name) / "relay"
        self.process = None
        try:
            self.process = subprocess.Popen([self.executable, str(self.path)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, start_new_session=True)
            ready = self._read()
            if ready != {"event": "ready", "protocol": 1, "socket": str(self.path)}:
                raise VaultError("The native SSH relay could not start.")
        except Exception:
            # No helper PID/key is authorized before the ready handshake succeeds.
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.close()
            raise

    def _read(self, deadline=None):
        deadline = deadline or time.monotonic() + self.timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise VaultError("The native SSH relay did not respond in time.")
            data = os.read(self.process.stdout.fileno(), 8192)
            if not data:
                raise VaultError("The native SSH relay stopped unexpectedly.")
            self._buffer += data
            if len(self._buffer) > 65536:
                raise VaultError("The native SSH relay returned invalid control data.")
        frame, self._buffer = self._buffer.split(b"\n", 1)
        try:
            value = json.loads(frame)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeDecodeError) as exc:
            raise VaultError("The native SSH relay returned invalid control data.") from exc

    def _request(self, method, **options):
        with self._mutex:
            if self.process is None or self.process.poll() is not None:
                raise VaultError("The native SSH relay is not running.")
            self._sequence += 1
            identifier = self._sequence
            data = (json.dumps({"id": identifier, "method": method, **options}) + "\n").encode()
            try:
                while data:
                    data = data[os.write(self.process.stdin.fileno(), data):]
                deadline = time.monotonic() + self.timeout
                while True:
                    value = self._read(deadline)
                    if "event" in value:
                        self.events.append(value)
                        if value["event"] == "cleanup-failed":
                            self.cleanup_ok = False
                        if value["event"] == "stopped":
                            self._stopped = True
                        continue
                    if value.get("id") != identifier or value.get("ok") is not True:
                        raise VaultError("The SSH relay rejected a process-control request.")
                    self.cleanup_ok = value.get("cleanup_ok") is True
                    return value
            except OSError as exc:
                raise VaultError("Communication with the native SSH relay failed.") from exc

    def register(self, pid):
        return self._request("register", pid=pid)

    def unregister(self, pid):
        return self._request("unregister", pid=pid)

    def status(self):
        return self._request("status")

    def retry_cleanup(self):
        return self._request("cleanup")

    def close(self):
        with self._mutex:
            process, self.process = self.process, None
            try:
                if process:
                    process.stdin.close()
                    try:
                        process.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired:
                        # Keep the native public-key owner alive to finish cleanup after the UI exits.
                        self.events.append({"event": "cleanup-pending"})
                        self.cleanup_ok = False
                    while select.select([process.stdout], [], [], 0)[0]:
                        data = os.read(process.stdout.fileno(), 8192)
                        if not data:
                            break
                        self._buffer += data
                        if len(self._buffer) > 65536:
                            self.cleanup_ok = False
                            break
                    for frame in self._buffer.splitlines():
                        try:
                            event = json.loads(frame)
                            if not isinstance(event, dict):
                                self.cleanup_ok = False
                                continue
                            if "event" in event:
                                self.events.append(event)
                                if event["event"] == "stopped":
                                    self._stopped = True
                                if "cleanup_ok" in event:
                                    self.cleanup_ok = event["cleanup_ok"] is True
                        except (ValueError, UnicodeDecodeError):
                            self.cleanup_ok = False
                    if process.poll() != 0 or not self._stopped:
                        self.cleanup_ok = False
                    process.stdout.close()
            finally:
                self.directory.cleanup()
