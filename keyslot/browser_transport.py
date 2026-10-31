"""Nonblocking private pipes to the native encrypted browser transport."""
import json
import os
from pathlib import Path
import subprocess

from gi.repository import GLib


LIMIT = 1024 * 1024


class BrowserPipe:
    def __init__(self, executable, event, failed, environment=None):
        self.event, self.failed = event, failed
        self.closed = False
        self.input, self.output = bytearray(), bytearray()
        self.read_source = self.write_source = self.check_source = 0
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, env=environment)
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.read_source = GLib.io_add_watch(self.process.stdout.fileno(), GLib.PRIORITY_DEFAULT,
            GLib.IOCondition.IN | GLib.IOCondition.HUP | GLib.IOCondition.ERR, self._read)
        self.check_source = GLib.timeout_add(250, self._check)

    def send(self, value):
        if self.closed:
            return False
        try:
            frame = (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode()
            if len(frame) > LIMIT or len(self.output) + len(frame) > 4 * LIMIT:
                raise ValueError("frame limit")
            self.output.extend(frame)
            if not self.write_source:
                self.write_source = GLib.io_add_watch(self.process.stdin.fileno(), GLib.PRIORITY_DEFAULT,
                    GLib.IOCondition.OUT | GLib.IOCondition.HUP | GLib.IOCondition.ERR, self._write)
            return True
        except (OSError, ValueError, TypeError):
            self._fail()
            return False

    def _read(self, _channel, _condition):
        try:
            # Bound work per GTK dispatch so browser traffic cannot starve input/rendering.
            for _ in range(4):
                if self.closed:
                    return False
                try:
                    data = os.read(self.process.stdout.fileno(), 65536)
                except BlockingIOError:
                    return True
                if not data:
                    self.read_source = 0
                    self._fail()
                    return False
                self.input.extend(data)
                while b"\n" in self.input:
                    end = self.input.index(b"\n")
                    if end > LIMIT:
                        raise ValueError("frame limit")
                    value = json.loads(self.input[:end])
                    del self.input[:end + 1]
                    if not isinstance(value, dict):
                        raise ValueError("invalid event")
                    self.event(value)
                    if self.closed:
                        return False
                if len(self.input) > LIMIT:
                    raise ValueError("frame limit")
            return True
        except Exception:
            self.read_source = 0
            self._fail()
        return False

    def _write(self, _channel, _condition):
        try:
            while self.output:
                try:
                    count = os.write(self.process.stdin.fileno(), self.output[:65536])
                except BlockingIOError:
                    return True
                if count <= 0:
                    raise OSError("closed pipe")
                del self.output[:count]
            self.write_source = 0
            return False
        except OSError:
            self.write_source = 0
            self._fail()
            return False

    def _check(self):
        if self.process.poll() is not None:
            self.check_source = 0
            self._fail()
            return False
        return not self.closed

    def _fail(self):
        if self.closed:
            return
        self.close()
        self.failed("Browser integration stopped. Check whether another Keyslot instance is using the browser connection.")

    def close(self):
        if self.closed:
            return
        self.closed = True
        for name in ("read_source", "write_source", "check_source"):
            identifier = getattr(self, name)
            setattr(self, name, 0)
            if identifier:
                GLib.source_remove(identifier)
        # EOF makes the native QObject destructor remove its own socket. Never unlink a peer's endpoint.
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()
        self.input.clear()
        self.output.clear()


class BrowserIntegration:
    def __init__(self, application, ui, executable=None, environment=None):
        from .browser_requests import BrowserRequests
        self.ui, self.ready = ui, False
        self.requests = BrowserRequests(application, ui, lambda value: self.pipe.send(value))
        executable = executable or Path(os.environ["KEYSLOT_ENGINE"]).parent / "keyslot-browser"
        self.pipe = BrowserPipe(executable, self._event, self._failed, environment)

    def _event(self, event):
        if event.get("event") == "ready":
            if event.get("protocol") != 1:
                self.pipe._fail()
                return
            self.ready = True
        self.requests.receive(event)

    def _failed(self, message):
        self.ready = False
        self.requests.close()
        self.ui.failure(message)

    def state_changed(self):
        self.requests.state_changed()

    def close(self):
        self.ready = False
        self.requests.close()
        self.pipe.close()
