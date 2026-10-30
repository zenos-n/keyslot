"""Ctrl+C must clean up a hidden, unlocked app without a Python traceback."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

root = Path(__file__).resolve().parents[1]
script = '''
import json,os,sys
from pathlib import Path
from unittest.mock import patch
from keyslot.app import Keyslot
from keyslot.application import main

class Fixture(Keyslot):
    def _activate(self, *_):
        super()._activate()
        session=self.active_session
        directory=Path(os.environ['XDG_CONFIG_HOME'])
        session.vault.create(directory/'signal-fixture.kdbx', 'public fixture master')
        session.window.show_vault(session.vault.snapshot)
        self.set_background(True)
        session.host_window.close()
        assert self.background and session.vault.unlocked
        (directory/'ready.json').write_text(json.dumps({'app':os.getpid(),'helper':session.vault._process.pid}))

with patch('keyslot.app.Keyslot', Fixture):
    raise SystemExit(main())
'''

with tempfile.TemporaryDirectory(prefix='keyslot-signals-') as directory:
    temporary = Path(directory)
    runner = temporary / 'runner.py'
    runner.write_text(script)
    env = os.environ.copy()
    env.update(XDG_CONFIG_HOME=directory, PYTHONPATH=str(root), GTK_A11Y='none')
    ready = temporary / 'ready.json'
    process = subprocess.Popen(['dbus-run-session', '--config-file=' + str(root / 'tools/test-session.conf'),
                                '--', sys.executable, str(runner)], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        if not ready.exists():
            process.terminate()
            out, err = process.communicate(timeout=3)
            raise AssertionError('Hidden signal fixture did not start: ' + out + err)
        state = json.loads(ready.read_text())
        os.kill(state['app'], signal.SIGINT)
        out, err = process.communicate(timeout=5)
        assert process.returncode == 130, (process.returncode, out, err)
        assert 'Traceback' not in err and 'KeyboardInterrupt' not in err, err
        try:
            os.kill(state['helper'], 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError('Ctrl+C left the unlocked vault helper running')
        print('Ctrl+C: hidden application quits, vault helper is reaped, no traceback: PASS')
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
