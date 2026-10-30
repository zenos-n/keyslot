"""SSH startup, cancellation and policy scheduling without a desktop or real agent."""
from collections import deque
from contextlib import contextmanager
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from keyslot.backend import VaultError
from keyslot.session import SessionJobs
from keyslot.ssh_integration import SSHIntegration
from keyslot.startup import Startup


class Manager:
    def __init__(self):
        self.alive = True
        self.process = SimpleNamespace(poll=lambda: None if self.alive else 0)
        self.cleanup_ok = True
        self.closed = threading.Event()
        self.failed = False

    def close(self):
        self.alive = False
        self.closed.set()

    def status(self):
        return {"cleanup_ok": not self.failed}

    def retry_cleanup(self):
        self.failed = False
        return self.status()


class Vault:
    def __init__(self):
        self.unlocked, self.identity, self.generation = True, object(), 0
        self.entries = [SimpleNamespace(uuid=name, title=name, recycled=name == "recycled", attachments=["KeeAgent.settings"])
                        for name in ("auto", "manual", "disabled", "broken", "recycled")]
        self.snapshot = SimpleNamespace(entries=self.entries)
        self.configured, self.prepared, self.added = [], [], []
        self.wait = None

    @contextmanager
    def operation(self, generation):
        if generation != self.generation:
            raise VaultError("Cancelled fixture operation")
        yield

    def cancel(self):
        self.unlocked = False
        self.generation += 1

    def finish_lock(self):
        pass

    def lock(self):
        self.cancel()

    def ssh_configure(self, manager, socket="", provider=""):
        self.configured.append((manager, self.identity, socket, provider))
        self.ssh_manager = manager

    def ssh_settings(self, entry):
        return {"enabled": entry.uuid != "disabled", "auto_add": entry.uuid != "manual", "configured": True}

    def ssh_prepare(self, entry):
        self.prepared.append(entry.uuid)
        if entry.uuid == "broken":
            raise VaultError("Fixture SSH key password is wrong")
        if self.wait:
            self.wait.wait(3)
        return {"token": entry.uuid}

    def ssh_add(self, token, approved):
        self.added.append((token, approved))


class Session:
    def __init__(self, dispatch, changed):
        self.vault = Vault()
        self.errors = []
        self.jobs = SessionJobs(self.vault, dispatch, changed, lambda: None, self.error)

    @property
    def epoch(self):
        return self.jobs.epoch

    def error(self, message):
        self.errors.append(message)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.callbacks = deque()
        self.manager = Manager()
        self.app = SimpleNamespace(startup=SimpleNamespace(ssh=True, ssh_socket="/fixture/agent", ssh_provider="internal"),
                                   sessions=[], active_session=None)
        self.integration = SSHIntegration(self.app, self.callbacks.append, lambda: self.manager)
        self.addCleanup(self.integration.close)
        self.session = Session(self.callbacks.append, self.integration.state_changed)
        self.app.sessions = [self.session]
        self.app.active_session = self.session
        self.addCleanup(self.session.jobs.close)

    def pump(self, condition, timeout=4):
        end = time.monotonic() + timeout
        while not condition():
            while self.callbacks:
                self.callbacks.popleft()()
            self.integration.state_changed()
            if time.monotonic() >= end:
                self.fail("SSH controller did not reach the expected state")
            time.sleep(.002)

    def settled(self):
        return bool(self.integration._states.get(self.session, {}).get("done"))

    def test_saved_policy_loads_once_per_helper_and_reports_failed_keys_without_touching_idle(self):
        self.integration.start()
        self.pump(self.settled)
        vault = self.session.vault
        self.assertEqual(vault.added, [("auto", True)])
        self.assertEqual(vault.prepared, ["auto", "broken"])
        self.assertEqual(len(vault.configured), 1)
        self.assertIn("password is wrong", self.session.errors[0])
        for _ in range(5):
            self.integration.state_changed()
        self.assertEqual(vault.added, [("auto", True)])
        self.assertTrue(self.session.vault.unlocked)
        self.session.jobs.lock()
        self.pump(lambda: not self.session.jobs.busy)
        vault.identity, vault.unlocked = object(), True
        self.pump(self.settled)
        self.assertEqual(len(vault.configured), 2)
        self.assertEqual(vault.added, [("auto", True), ("auto", True)])

    def test_lock_while_preparing_cannot_add_a_key_after_unlock(self):
        gate = threading.Event()
        self.session.vault.wait = gate
        self.addCleanup(gate.set)
        self.integration.start()
        self.pump(lambda: bool(self.session.vault.prepared))
        self.session.jobs.lock()
        gate.set()
        self.pump(lambda: not self.integration._states)
        self.session.jobs.executor.submit(lambda: None).result(timeout=3)
        self.assertEqual(self.session.vault.added, [])

    def test_foreground_job_takes_priority_and_automatic_work_is_noninteractive(self):
        gate = threading.Event()
        self.addCleanup(gate.set)
        self.session.jobs.run(lambda: gate.wait(3))
        self.integration.start()
        self.pump(lambda: self.integration.ready)
        self.assertEqual(self.session.vault.configured, [])
        gate.set()
        self.pump(self.settled)
        self.assertEqual(self.session.vault.added, [("auto", True)])

    def test_stopping_during_startup_retires_the_late_relay(self):
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        def factory():
            entered.set()
            gate.wait(3)
            return self.manager
        self.integration.factory = factory
        self.integration.start()
        self.assertTrue(entered.wait(1))
        self.integration.stop()
        gate.set()
        self.assertTrue(self.manager.closed.wait(2))
        self.assertIsNone(self.integration.manager)
        self.assertEqual(self.session.vault.added, [])

    def test_shutdown_during_startup_reaps_late_relay_without_dispatch(self):
        gate, entered = threading.Event(), threading.Event()
        def factory():
            entered.set()
            gate.wait(2)
            return self.manager
        self.integration.factory = factory
        self.integration.start()
        self.assertTrue(entered.wait(1))
        timer = threading.Timer(.05, gate.set)
        timer.start()
        self.integration.close()
        timer.join()
        self.assertTrue(self.manager.closed.is_set())
        self.assertIsNone(self.integration.manager)

    def test_cleanup_failure_is_visible_and_retry_clears_status_without_reloading_keys(self):
        self.integration.start()
        self.pump(self.settled)
        self.manager.failed = True
        self.integration.check()
        self.pump(lambda: "cleanup failed" in self.integration.error)
        self.assertIn("Retry Cleanup", self.session.errors[-1])
        self.integration.check(retry=True)
        self.pump(lambda: not self.integration.error)
        self.assertEqual(self.session.vault.added, [("auto", True)])

    def test_shutdown_reports_unconfirmed_cleanup_without_needing_another_mainloop_turn(self):
        self.integration.start()
        self.pump(self.settled)
        self.manager.cleanup_ok = False
        self.assertFalse(self.integration.close())
        self.assertFalse(self.integration.close())
        self.assertTrue(self.manager.closed.is_set())

    def test_crashed_relay_is_reported_and_never_restarted_without_a_user_action(self):
        self.integration.start()
        self.pump(self.settled)
        self.manager.alive = False
        self.integration.check()
        self.assertIn("stopped unexpectedly", self.integration.error)
        self.assertFalse(self.integration.starting)
        self.pump(lambda: self.session.vault.ssh_manager is None)
        self.assertEqual([value[0] for value in self.session.vault.configured], [self.manager, None])
        self.assertTrue(self.session.vault.unlocked)

    def test_startup_failure_is_visible_and_can_be_retried(self):
        def fail():
            raise VaultError("Fixture helper is missing")
        self.integration.factory = fail
        self.integration.start()
        self.pump(lambda: bool(self.session.errors))
        self.assertIn("helper is missing", self.integration.error)
        self.assertTrue(self.session.vault.unlocked)
        self.integration.factory = lambda: self.manager
        self.integration.start()
        self.pump(self.settled)
        self.assertEqual(self.session.vault.added, [("auto", True)])

    def test_disabling_detaches_helpers_without_locking_or_automatic_restart(self):
        self.integration.start()
        self.pump(self.settled)
        self.app.startup.ssh = False
        self.integration.stop()
        self.pump(lambda: self.session.vault.ssh_manager is None)
        self.assertTrue(self.manager.closed.wait(1))
        self.assertTrue(self.session.vault.unlocked)
        self.assertIsNone(self.integration.manager)
        self.assertEqual(self.session.vault.added, [("auto", True)])

    def test_multiple_vaults_have_independent_helpers_and_automatic_queues(self):
        second = Session(self.callbacks.append, self.integration.state_changed)
        self.addCleanup(second.jobs.close)
        second.vault.entries = second.vault.entries[:1]
        second.vault.snapshot.entries = second.vault.entries
        self.app.sessions.append(second)
        self.integration.start()
        self.pump(lambda: self.settled() and bool(self.integration._states.get(second, {}).get("done")))
        self.assertEqual(second.vault.added, [("auto", True)])
        self.assertEqual(second.errors, [])
        self.assertNotEqual(second.vault.identity, self.session.vault.identity)
        self.session.jobs.lock()
        self.assertTrue(second.vault.unlocked)

    def test_startup_settings_opt_in_validation_and_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Startup(directory)
            self.assertFalse(settings.ssh)
            settings.save(False, False, ssh=True, ssh_socket="/tmp/fixture-agent", ssh_provider="/fixture/provider")
            settings.save(True, False, Path(directory) / "vault.kdbx", browser=True, lock_minutes=0)
            loaded = Startup(directory)
            self.assertTrue(loaded.ssh)
            self.assertEqual((loaded.ssh_socket, loaded.ssh_provider), ("/tmp/fixture-agent", "/fixture/provider"))
            for options in ({"ssh_socket": "relative"}, {"ssh_socket": "\n"}, {"ssh_provider": "bad\0path"}, {"ssh": "yes"}):
                with self.assertRaises(ValueError):
                    loaded.save(False, False, **options)
            self.assertTrue(Startup(directory).ssh)
            settings.path.write_text('{"ssh": true, "ssh_socket": "relative"}')
            self.assertFalse(Startup(directory).ssh)
