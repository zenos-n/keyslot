import queue
import threading
import unittest
from contextlib import contextmanager

from keyslot.backend import VaultError
from keyslot.session import SessionJobs


class FakeVault:
    def __init__(self):
        self.unlocked = True
        self.cancelled = threading.Event()
        self.locked = threading.Event()
        self.generation = 0

    def cancel(self):
        self.generation += 1
        self.unlocked = False
        self.cancelled.set()

    def lock(self):
        self.cancel()
        self.finish_lock()

    def finish_lock(self):
        self.locked.set()

    @contextmanager
    def operation(self, generation):
        if generation != self.generation:
            raise VaultError("Cancelled")
        yield


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.callbacks = queue.Queue()
        self.sessions = []

    def session(self):
        events, errors = [], []
        jobs = SessionJobs(FakeVault(), self.callbacks.put, lambda: events.append("changed"),
                           lambda: events.append("clear"), errors.append)
        self.sessions.append(jobs)
        return jobs, events, errors

    def tearDown(self):
        for jobs in self.sessions:
            jobs.close()

    def dispatch(self):
        self.callbacks.get(timeout=2)()

    def test_results_remain_with_their_originating_session(self):
        first, _, _ = self.session()
        second, _, _ = self.session()
        a, b = [], []
        self.assertTrue(first.run(lambda: "first database", a.append))
        self.assertTrue(second.run(lambda: "second database", b.append))
        self.dispatch()
        self.dispatch()
        self.assertEqual(a, ["first database"])
        self.assertEqual(b, ["second database"])
        self.assertFalse(first.busy or second.busy)

    def test_foreground_action_waits_for_background_read_without_losing_busy_state(self):
        jobs, _events, _errors = self.session()
        ready, release = threading.Event(), threading.Event()
        results = []
        def background():
            ready.set()
            release.wait(2)
            return "background"
        self.assertTrue(jobs.run(background, results.append, interactive=False))
        self.assertTrue(ready.wait(1))
        self.assertTrue(jobs.busy)
        self.assertFalse(jobs.interactive)
        self.assertTrue(jobs.run(lambda: "foreground", results.append))
        self.assertTrue(jobs.interactive)
        self.assertFalse(jobs.run(lambda: "second foreground"))
        release.set()
        self.dispatch()
        self.assertTrue(jobs.busy and jobs.interactive)
        self.dispatch()
        self.assertEqual(results, ["background", "foreground"])
        self.assertFalse(jobs.busy)

    def test_lock_cancels_foreground_action_queued_behind_background_read(self):
        jobs, _events, _errors = self.session()
        ready, release = threading.Event(), threading.Event()
        calls = []
        def background():
            ready.set()
            release.wait(2)
        self.assertTrue(jobs.run(background, interactive=False))
        self.assertTrue(ready.wait(1))
        self.assertTrue(jobs.run(lambda: calls.append("must not run")))
        jobs.lock()
        release.set()
        jobs.executor.submit(lambda: None).result(timeout=2)
        self.dispatch()
        self.dispatch()
        self.assertFalse(calls)
        self.assertFalse(jobs.busy)

    def test_lock_cancels_only_its_session_and_drops_late_results(self):
        first, events, _ = self.session()
        second, _, _ = self.session()
        entered = threading.Event()
        results = []
        def operation():
            entered.set()
            first.vault.cancelled.wait()
            return "late secret"
        first.run(operation, results.append)
        self.assertTrue(entered.wait(timeout=2))
        first.lock()
        self.dispatch()
        self.assertEqual(results, [])
        self.assertIn("clear", events)
        self.assertFalse(first.busy)
        self.assertTrue(second.vault.unlocked)
        self.assertFalse(second.vault.cancelled.is_set())
        self.assertTrue(first.vault.locked.wait(timeout=2))

    def test_one_operation_per_session_and_other_sessions_keep_running(self):
        first, _, _ = self.session()
        second, _, _ = self.session()
        first.run(lambda: first.vault.cancelled.wait())
        self.assertFalse(first.run(lambda: self.fail("A second operation must not run")))
        results = []
        self.assertTrue(second.run(lambda: 42, results.append))
        self.dispatch()
        self.assertEqual(results, [42])
        self.assertTrue(first.busy)

    def test_close_blocks_resurrection_and_is_idempotent(self):
        jobs, _, _ = self.session()
        entered = threading.Event()
        results = []
        def operation():
            entered.set()
            jobs.vault.cancelled.wait()
            return "late result"
        jobs.run(operation, results.append)
        self.assertTrue(entered.wait(timeout=2))
        jobs.close()
        jobs.close()
        self.dispatch()
        self.assertEqual(results, [])
        self.assertFalse(jobs.run(lambda: self.fail("Closed sessions must not restart")))

    def test_expected_errors_preserve_open_state_and_unexpected_errors_lock(self):
        jobs, events, errors = self.session()
        def expected():
            raise VaultError("Public fixture error")
        jobs.run(expected)
        self.dispatch()
        self.assertTrue(jobs.vault.unlocked)
        self.assertEqual(errors, ["Public fixture error"])
        inline = []
        jobs.run(expected, failed=inline.append)
        self.dispatch()
        self.assertEqual(inline, ["Public fixture error"])
        self.assertEqual(errors, ["Public fixture error"])
        self.assertTrue(jobs.vault.unlocked)
        def unexpected():
            raise RuntimeError("sensitive diagnostic must not be displayed")
        jobs.run(unexpected)
        self.dispatch()
        self.assertFalse(jobs.vault.unlocked)
        self.assertNotIn("sensitive", errors[-1])
        self.assertIn("clear", events)
        jobs.run(expected, failed=inline.append)
        self.dispatch()
        self.assertEqual(inline, ["Public fixture error"])
        self.assertEqual(errors[-1], "Public fixture error")
