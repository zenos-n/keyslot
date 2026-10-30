"""Owned sandboxed Chromium process controlled through its private CDP pipe."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
from collections import deque


class Browser:
    def __init__(self, executable, profile, log, arguments=(), environment=None):
        to_browser, input_write = os.pipe()
        output_read, from_browser = os.pipe()
        self.input, self.output = input_write, output_read
        self.buffer, self.sequence, self.replies, self.events = b"", 0, {}, deque(maxlen=200)
        # Remap in a fresh single-threaded Python child, never preexec_fn inside the GTK process.
        remap = """import os,sys
original = [int(sys.argv[1]), int(sys.argv[2])]
r, w = os.dup(original[0]), os.dup(original[1])
os.dup2(r, 3)
os.dup2(w, 4)
os.set_inheritable(3, True)
os.set_inheritable(4, True)
for fd in set(original + [r, w]) - {3, 4}:
    os.close(fd)
os.execv(sys.argv[3], sys.argv[3:])
"""
        args = [str(Path(executable).resolve()), "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
                "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                "--disable-component-update", "--password-store=basic", "--gtk-version=3",
                "--user-data-dir=" + str(profile), *arguments, "about:blank"]
        env = dict(os.environ if environment is None else environment)
        for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "GI_TYPELIB_PATH", "GTK_PATH", "GIO_EXTRA_MODULES", "WAYLAND_DISPLAY"):
            env.pop(name, None)
        self.log = Path(log)
        try:
            with self.log.open("w") as output:
                self.process = subprocess.Popen([sys.executable, "-c", remap, str(to_browser), str(from_browser), *args],
                    pass_fds=(to_browser, from_browser), env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=output, start_new_session=True)
        except Exception:
            os.close(input_write)
            os.close(output_read)
            raise
        finally:
            os.close(to_browser)
            os.close(from_browser)

    def receive(self, timeout=15):
        deadline = time.monotonic() + timeout
        while b"\0" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.output], [], [], remaining)[0]:
                raise TimeoutError("The owned browser did not answer its private CDP pipe")
            data = os.read(self.output, 65536)
            if not data:
                raise EOFError("The owned browser closed its private CDP pipe")
            self.buffer += data
            if len(self.buffer) > 8 * 1024 * 1024:
                raise ValueError("The browser response exceeded the fixture limit")
        frame, self.buffer = self.buffer.split(b"\0", 1)
        message = json.loads(frame)
        if "id" in message:
            self.replies[message["id"]] = message
        else:
            self.events.append(message)
        return message

    def call(self, method, params=None, session=None, timeout=20):
        self.sequence += 1
        identifier = self.sequence
        value = {"id": identifier, "method": method, "params": params or {}}
        if session:
            value["sessionId"] = session
        data = json.dumps(value).encode() + b"\0"
        while data:
            data = data[os.write(self.input, data):]
        deadline = time.monotonic() + timeout
        while identifier not in self.replies:
            self.receive(max(0, deadline - time.monotonic()))
        message = self.replies.pop(identifier)
        if "error" in message:
            raise RuntimeError("Browser protocol error: " + json.dumps(message["error"]))
        return message.get("result", {})

    def evaluate(self, session, expression):
        result = self.call("Runtime.evaluate", {"expression": expression, "awaitPromise": True,
            "returnByValue": True, "userGesture": True}, session)
        if "exceptionDetails" in result:
            raise RuntimeError("The browser fixture expression failed")
        return result.get("result", {}).get("value")

    def close(self):
        if self.process.poll() is None:
            try:
                self.call("Browser.close")
            except (OSError, ValueError, EOFError, TimeoutError, RuntimeError):
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.getpgid(self.process.pid) == self.process.pid:
                    os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=5)
        os.close(self.input)
        os.close(self.output)
