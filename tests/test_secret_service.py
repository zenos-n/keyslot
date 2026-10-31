"""Provider reply lifetime and login-owner binding without touching a desktop bus."""
from concurrent.futures import Future
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from gi.repository import Gio, GLib

from keyslot.backend import Snapshot
from keyslot.secret_service import SecretService, Collection, WireSession, Call, ServiceError
from keyslot.secret_prompts import SecretPrompt
from keyslot.startup import Startup, LoginKeyring


class ImmediateExecutor:
    def submit(self, operation):
        future = Future()
        try:
            future.set_result(operation())
        except Exception as exc:
            future.set_exception(exc)
        return future


class PromptDismissal(unittest.TestCase):
    def test_opening_unlock_form_does_not_mistake_reentrant_lock_for_cancel(self):
        service = SimpleNamespace(peers={":1.9": object()}, prompts={}, closed=False,
                                  collections={}, app=SimpleNamespace(sessions=[]), instance="fixture")
        class Session:
            pass
        session = Session()
        session.jobs = SimpleNamespace(closed=False, busy=False)
        session.vault = SimpleNamespace(unlocked=False)
        session.dialogs, session.file_requests = [], set()
        session.path = "/tmp/public-fixture.kdbx"
        collection = SimpleNamespace(session=session)
        service.collections = {session: collection}
        service.app.sessions = [session]
        prompt = SecretPrompt(service, ":1.9", "unlock", {})
        service.active_prompt = prompt
        prompt.started = True
        prompt.stage = "running"
        prompt._parent = Mock(return_value=session)
        prompt.complete = Mock()
        def open_form(_path):
            prompt.check()  # The lock emitted before presenting the form.
            session.dialogs.append(object())
        session._unlock_dialog = open_form
        prompt._ensure_unlocked([collection], Mock())
        prompt.check()
        prompt.complete.assert_not_called()
        self.assertIs(prompt.waiting, session)

    def test_dismissed_prompts_keep_the_operation_result_type(self):
        for kind, signature, value in (("unlock", "ao", []),
                                       ("create-item", "o", "/"),
                                       ("create-collection", "o", "/"),
                                       ("delete-item", "b", False),
                                       ("close-collection", "b", False)):
            with self.subTest(kind=kind):
                service = SimpleNamespace(peers={":1.9": object()}, prompts={},
                    active_prompt=None, closed=False, _emit=Mock(), _remove=Mock(), instance="fixture")
                prompt = SecretPrompt(service, ":1.9", kind, {})
                service.prompts[prompt.path] = prompt
                prompt.complete(True)
                dismissed, result = service._emit.call_args.args[4]
                self.assertTrue(dismissed)
                self.assertEqual(result.get_type_string(), signature)
                self.assertEqual(result.unpack(), value)
                self.assertFalse(service.prompts)


class ReplyLifetime(unittest.TestCase):
    def setUp(self):
        self.provider = object.__new__(SecretService)
        self.provider.closed = False
        self.provider.instance = "fixture"
        self.provider.options = {"confirm_access": True}
        self.provider.peers = {":1.9": object()}
        self.provider.calls, self.provider.sessions = set(), {}
        self.provider.executor = ImmediateExecutor()
        class Session:
            pass
        self.session = Session()
        self.session.epoch = 1
        self.session.jobs = SimpleNamespace(closed=False)
        self.session.vault = SimpleNamespace(identity=object(), generation=1, unlocked=True,
            snapshot=Snapshot("Fixture", secret_group="group"))
        self.collection = Collection(self.session, "/org/freedesktop/secrets/collection/fixture")
        self.provider.collections = {self.session: self.collection}
        self.invocation = Mock()
        self.invocation.get_parameters.return_value = GLib.Variant("()", ())
        self.queue = []
        self.dispatch = patch("keyslot.secret_service.GLib.idle_add", side_effect=lambda callback: self.queue.append(callback))
        self.dispatch.start()
        self.addCleanup(self.dispatch.stop)

    def submit(self, **values):
        self.provider._submit(":1.9", self.invocation, lambda: "sensitive fixture response",
            lambda value: self.invocation.return_value(value), **values)
        self.assertEqual(len(self.queue), 1)

    def test_lock_after_computation_discards_sensitive_reply(self):
        self.submit(contexts=[(self.collection, self.provider._context(self.collection))])
        self.session.epoch += 1
        self.session.vault.unlocked = False
        self.session.vault.snapshot = None
        self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.assertEqual(self.invocation.return_dbus_error.call_args.args[0], "org.freedesktop.Secret.Error.IsLocked")

    def test_session_close_after_computation_discards_sensitive_reply(self):
        wire = WireSession("/org/freedesktop/secrets/session/fixture", ":1.9", "fixture", object())
        self.provider.sessions[wire.path] = wire
        self.submit(wire_sessions=[wire])
        self.provider.sessions.pop(wire.path)
        self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.assertEqual(self.invocation.return_dbus_error.call_args.args[0], "org.freedesktop.Secret.Error.NoSession")

    def test_exposed_group_change_after_computation_discards_reply(self):
        self.submit(contexts=[(self.collection, self.provider._context(self.collection))])
        self.session.vault.snapshot = Snapshot("Fixture", secret_group="other-group")
        self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.assertEqual(self.invocation.return_dbus_error.call_args.args[0], "org.freedesktop.Secret.Error.IsLocked")

    def test_peer_disconnect_and_policy_change_do_not_publish_late_reply(self):
        self.submit()
        self.provider.peers.pop(":1.9")
        self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.provider.peers[":1.9"] = object()
        self.submit()
        self.provider.options["confirm_access"] = False
        self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.assertEqual(self.invocation.return_dbus_error.call_args.args[0], "org.freedesktop.Secret.Error.IsLocked")

    def test_per_peer_request_quota_and_generic_errors_do_not_expose_values(self):
        self.provider.calls = {Call(":1.9", Mock(), time.monotonic() + 100) for _ in range(16)}
        with self.assertRaises(ServiceError):
            self.submit()
        self.assertFalse(self.queue)
        self.provider._error(self.invocation, RuntimeError("sensitive fixture content"))
        self.assertNotIn("sensitive", self.invocation.return_dbus_error.call_args.args[1])

    def test_policy_round_trip_discards_already_computed_reply(self):
        self.submit()
        self.provider.instance = "new-policy-generation"
        self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.assertEqual(self.invocation.return_dbus_error.call_args.args[0], "org.freedesktop.Secret.Error.IsLocked")

    def test_policy_change_invalidates_cached_metadata_without_snapshot_change(self):
        self.session.path = "/tmp/public-fixture.kdbx"
        self.collection.snapshot = self.session.vault.snapshot
        self.collection.items = {"entry": object()}
        self.provider.app = SimpleNamespace(startup=SimpleNamespace(secret_service={"confirm_access": False}),
                                            sessions=[self.session], active_session=self.session)
        self.provider._active_collection = self.collection
        self.provider._changed = Mock()
        self.provider._notify = Mock()
        prompt = Mock()
        self.provider.prompts = {"fixture": prompt}
        self.provider.prompt_check = 0
        self.provider.state_changed()
        self.assertNotEqual(self.provider.instance, "fixture")
        prompt.complete.assert_called_once_with(True)
        self.provider._changed.assert_called_once_with(self.collection.item_path("entry"), "item", ["Attributes"])
        self.assertFalse(self.provider._notify.call_args.args[2]["Locked"].unpack())
        self.assertEqual(len(self.queue), 1)

    def test_bulk_reply_limit_spans_vaults_and_duplicate_items_are_read_once(self):
        other = type(self.session)()
        other.__dict__.update(self.session.__dict__)
        second = Collection(other, "/org/freedesktop/secrets/collection/other")
        self.provider.collections[other] = second
        one, two = self.collection.item_path("first"), second.item_path("second")
        self.provider.objects = {one: ("item", (self.collection, "first"), 1), two: ("item", (second, "second"), 2)}
        self.provider.options["notify"] = False
        self.provider._changed = Mock()
        self.provider._vault = Mock(side_effect=lambda _c, _context, _op, **args:
                                    {"secrets": [{"entry": identifier} for identifier in args["entries"]]})
        wire = WireSession("/org/freedesktop/secrets/session/fixture", ":1.9", "fixture", object())
        self.provider.sessions[wire.path] = wire
        self.provider._encode = Mock(return_value=(wire.path, b"", b"x" * 16, "text/plain"))
        limit = 16 + 10 + 2 * max(len(one), len(two)) + 64
        with patch("keyslot.secret_service.MAX_SECRET_REPLY", limit):
            self.provider._get_secrets(":1.9", [one, two], wire, self.invocation)
            self.queue.pop()()
        self.invocation.return_value.assert_not_called()
        self.assertEqual(self.invocation.return_dbus_error.call_args.args[0], "org.freedesktop.DBus.Error.LimitsExceeded")
        self.invocation.reset_mock()
        self.provider._vault.reset_mock()
        self.provider._get_secrets(":1.9", [one, one], wire, self.invocation)
        self.queue.pop()()
        self.assertEqual(self.provider._vault.call_args.kwargs["entries"], ["first"])
        self.assertEqual(len(self.invocation.return_value.call_args.args[0].unpack()[0]), 1)

    def test_property_updates_coalesce_and_publish_values_without_credentials(self):
        self.provider.connection = Mock()
        self.provider.connection.get_unique_name.return_value = ":1.1"
        self.provider.property_changes = {}
        path = self.collection.item_path("entry")
        self.provider.objects = {path: ("item", (self.collection, "entry"), 1)}
        self.provider._vault = Mock(return_value={"label": "Updated", "created": 1, "modified": 2,
                                                  "attributes": {"fixture": "public"}, "locked": True})
        self.provider._notify = Mock()
        self.provider._changed(path, "item", ["Label"])
        self.provider._changed(path, "item", ["Attributes", "Locked"])
        self.assertEqual(len(self.queue), 1)
        self.queue.pop()()
        self.assertEqual(len(self.queue), 1)
        self.queue.pop()()
        self.assertFalse(self.provider.property_changes)
        props = self.provider._notify.call_args.args[2]
        self.assertEqual(props["Attributes"].unpack(), {"fixture": "public"})
        self.assertEqual(props["Label"].unpack(), "Updated")
        self.assertNotIn("Locked", props)  # Grants belong to individual peers.
        self.assertFalse(self.provider._vault.call_args.kwargs.get("include_totp", False))
        self.provider._notify.reset_mock()
        self.provider._changed(path, "item", ["Attributes"])
        self.session.epoch += 1
        self.queue.pop()()
        self.provider._notify.assert_not_called()


class LoginOwnerBinding(unittest.TestCase):
    def keyring(self):
        keyring = object.__new__(LoginKeyring)
        keyring.secret = SimpleNamespace(Service=SimpleNamespace(__gtype__="fixture-type", open_sync=Mock()),
            ServiceFlags=SimpleNamespace(OPEN_SESSION=1, LOAD_COLLECTIONS=2))
        return keyring

    def test_existing_provider_is_pinned_by_unique_owner_without_activation(self):
        keyring = self.keyring()
        connection = Mock()
        connection.get_unique_name.return_value = ":1.1"
        def invoke(_name, _path, _interface, method, *_args):
            self.assertEqual(method, "GetNameOwner")
            return GLib.Variant("(s)", (":1.2",))
        connection.call_sync.side_effect = invoke
        with patch.object(Gio, "bus_get_sync", return_value=connection):
            keyring._service()
        keyring.secret.Service.open_sync.assert_called_once_with("fixture-type", ":1.2", 3, None)

    def test_own_provider_is_rejected_before_any_libsecret_open(self):
        keyring = self.keyring()
        connection = Mock()
        connection.get_unique_name.return_value = ":1.1"
        connection.call_sync.return_value = GLib.Variant("(s)", (":1.1",))
        with patch.object(Gio, "bus_get_sync", return_value=connection), self.assertRaisesRegex(ValueError, "active password service"):
            keyring._service()
        keyring.secret.Service.open_sync.assert_not_called()

    def test_store_uses_the_selected_collection_service(self):
        keyring = self.keyring()
        keyring.schema = object()
        value = object()
        keyring.secret.Value = SimpleNamespace(new=Mock(return_value=value))
        selected = Mock()
        service = Mock()
        selected.get_object_path.return_value = "/org/freedesktop/secrets/collection/login"
        keyring._collection = Mock(return_value=(service, selected))
        keyring.store("/tmp/public-fixture.kdbx", {"password": "public fixture"})
        service.store_sync.assert_called_once()
        self.assertIs(service.store_sync.call_args.args[4], value)

    def test_service_options_persist_without_changing_startup_or_accepting_nonbooleans(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Startup(directory)
            expected = settings.secret_service | {"enabled": True, "confirm_delete": False}
            settings.save(False, False, secret_service=expected)
            settings.save(False, False, background=False)
            self.assertEqual(Startup(directory).secret_service, expected)
            before = settings.path.read_bytes()
            with self.assertRaises(ValueError):
                settings.save(False, False, secret_service=expected | {"confirm_access": "yes"})
            self.assertEqual(settings.path.read_bytes(), before)
