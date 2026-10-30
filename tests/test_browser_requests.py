"""Controller consent/lifecycle tests; native crypto and vault behavior have separate gates."""
import base64
from types import SimpleNamespace
import unittest

from keyslot.browser_requests import BrowserRequests
from keyslot.backend import VaultError


KEY = base64.b64encode(bytes(range(32))).decode()
OTHER = base64.b64encode(bytes(reversed(range(32)))).decode()


class Jobs:
    closed = False
    deferred = False

    def __init__(self):
        self.queue = []

    def run(self, operation, done, failed, *, interactive=True):
        assert not interactive, "Browser polling must not trigger foreground loading UI"
        if self.deferred:
            self.queue.append((operation, done, failed))
        else:
            try:
                done(operation())
            except VaultError as exc:
                failed(str(exc))
        return True

    def complete(self):
        operation, done, failed = self.queue.pop(0)
        try:
            done(operation())
        except VaultError as exc:
            failed(str(exc))


class Vault:
    unlocked = True
    allowed = False
    group_exists = False
    delete_found = True
    passkey_error = None

    def __init__(self):
        self.identity = object()
        self.calls = []

    def browser_info(self):
        self.calls.append("info")
        return {"hash": "fixture-hash", "name": "Fixture"}

    def browser_prepare_passkey(self, *args):
        self.calls.append(("prepare_passkey", args))
        return {"error_code": self.passkey_error} if self.passkey_error else {"token": "passkey-token", "registration": args[2] == "register"}

    def browser_finish_passkey(self, token, approved=False, entry="", group="", replace=False):
        self.calls.append(("finish_passkey", token, approved, entry, group, replace))
        return {"type": "public-key", "id": "public-credential"} if approved else {"errorCode": 22}

    def browser_prepare_delete(self, identifier, key, entry):
        self.calls.append(("prepare_delete", identifier, key, entry))
        return {"found": self.delete_found, "token": "delete-token", "permanent": False}

    def browser_delete(self, token, approved=False):
        self.calls.append(("delete", token, approved))
        return approved

    def browser_totp(self, identifier, key, entry):
        self.calls.append(("totp", identifier, key, entry))
        return "123456"

    def browser_groups(self, identifier, key):
        self.calls.append(("groups", identifier, key))
        return {"groups": [{"name": "Root", "uuid": "root", "children": []}]}

    def browser_prepare_group(self, identifier, key, name):
        self.calls.append(("prepare_group", identifier, key, name))
        return {"exists": self.group_exists, "name": "Existing", "uuid": "existing", "token": "group-token"}

    def browser_create_group(self, token, approved=False):
        self.calls.append(("create_group", token, approved))
        return {"name": "Created", "uuid": "created"} if approved else {}

    def browser_associations(self):
        return []

    def browser_associate(self, name, key, replace=False):
        self.calls.append(("associate", name, key, replace))
        return {}

    def browser_authenticate(self, name, key):
        self.calls.append(("authenticate", name, key))
        return {"authenticated": name == "Browser" and key == KEY, "hash": "fixture-hash"}

    def browser_lookup(self, *args, **options):
        self.calls.append(("lookup", args, options))
        return {"token": "private-token", "entries": [{"uuid": "entry", "title": "Fixture", "username": "user",
                                                    "group": "Root", "allowed": self.allowed}]}

    def browser_release(self, token, selected, approved=False, remember=False):
        self.calls.append(("release", token, selected, approved, remember))
        return [{"login": "user", "password": "public fixture password"}]

    def browser_deny(self, token, selected, remember=False):
        self.calls.append(("deny", token, selected, remember))
        return []

    def browser_prepare_save(self, *args, **options):
        self.calls.append(("prepare_save", args, options))
        return {"token": "save-token", "changed": True, "update": False}

    def browser_save(self, token, approved=False, group=""):
        self.calls.append(("save", token, approved, group))
        return approved


class UI:
    def __init__(self):
        self.prompts, self.dismissed, self.unlocks = [], [], []

    def prompt(self, kind, session, data, done):
        self.prompts.append((kind, session, data, done))
        return lambda: self.dismissed.append(kind)

    def pair(self, *args):
        return self.prompt("pair", *args)

    def access(self, *args):
        return self.prompt("access", *args)

    def unlock(self, session):
        self.unlocks.append(session)

    def save_login(self, *args):
        return self.prompt("save", *args)

    def saved(self, session):
        self.saved_session = session

    def create_group(self, *args):
        return self.prompt("create_group", *args)

    def group_created(self, session):
        self.group_session = session

    def generate(self, *args):
        return self.prompt("generate", *args)

    def delete_entry(self, *args):
        return self.prompt("delete", *args)

    def deleted(self, session):
        self.deleted_session = session

    def passkey(self, *args):
        return self.prompt("passkey", *args)

    def passkey_saved(self, session):
        self.passkey_session = session


class BrowserRequestTests(unittest.TestCase):
    def setUp(self):
        self.touches = []
        self.session = SimpleNamespace(vault=Vault(), jobs=Jobs(), epoch=0, busy=False, dialogs=[], touch=lambda: self.touches.append(1))
        self.lock_calls = []
        def lock():
            self.lock_calls.append(self.session)
            self.session.vault.unlocked = False
            self.session.epoch += 1
            self.controller.state_changed()
        self.session.lock = lock
        self.app = SimpleNamespace(sessions=[self.session], active_session=self.session, select_session=lambda _session: None)
        self.ui, self.replies = UI(), []
        self.controller = BrowserRequests(self.app, self.ui, self.replies.append)
        self.counter = 0

    def request(self, action, generation="1", connection="connection", **body):
        self.counter += 1
        event = {"event": "request", "id": str(self.counter), "connection": connection, "client": "client",
                 "generation": generation, "public_key": KEY, "action": action, "body": {"action": action, **body}}
        self.controller.receive(event)
        return event

    def authenticate(self):
        self.request("test-associate", id="Browser", key=KEY)
        self.assertEqual(self.replies[-1]["result"]["id"], "Browser")

    def logins(self, **body):
        return self.request("get-logins", url="https://example.org", keys=[{"id": "Browser", "key": KEY}], **body)

    def test_pairing_requires_consent_and_uses_only_gtk_name_and_replace_choice(self):
        self.request("associate", key=OTHER)
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.request("associate", key=KEY, idKey=KEY, name="untrusted name", replace=True)
        self.assertEqual(self.ui.prompts[-1][0], "pair")
        self.assertNotIn(KEY, str(self.ui.prompts[-1][2]))
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "associate" for call in self.session.vault.calls))
        self.ui.prompts[-1][3]({"name": "Chosen name", "replace": False})
        self.assertIn(("associate", "Chosen name", KEY, False), self.session.vault.calls)
        self.assertEqual(self.replies[-1]["result"]["id"], "Chosen name")
        self.assertEqual(self.ui.dismissed, ["pair"])

    def test_passkey_requests_validate_authentication_and_nested_protocol_errors(self):
        self.request("passkeys-get", publicKey={"challenge": "fixture"}, origin="https://example.org")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.authenticate()
        self.request("passkeys-get", publicKey={}, origin="https://example.org")
        self.assertEqual(self.replies[-1]["error_code"], 24)
        self.request("passkeys-get", publicKey={"challenge": "fixture"})
        self.assertEqual(self.replies[-1]["error_code"], 25)
        self.session.vault.passkey_error = 28
        self.request("passkeys-get", publicKey={"challenge": "fixture"}, origin="https://example.org")
        self.assertEqual(self.replies[-1]["result"], {"response": {"errorCode": 28}})
        self.assertFalse(self.ui.prompts)
        self.assertFalse(self.touches)

    def test_passkey_register_and_signing_use_only_explicit_gtk_choices(self):
        self.authenticate()
        fields = {"publicKey": {"challenge": "fixture"}, "origin": "https://example.org", "approved": True,
                  "entry": "remote-entry", "replace": True}
        self.request("passkeys-register", **fields)
        self.assertEqual(self.ui.prompts[-1][0], "passkey")
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "finish_passkey" for c in self.session.vault.calls))
        self.ui.prompts[-1][3](None)
        self.assertEqual(self.replies[-1]["result"], {"response": {"errorCode": 22}})
        self.request("passkeys-register", **fields)
        self.ui.prompts[-1][3]({"entry": "gtk-entry", "group": "", "replace": False})
        self.assertIn(("finish_passkey", "passkey-token", True, "gtk-entry", "", False), self.session.vault.calls)
        self.assertIs(self.ui.passkey_session, self.session)
        self.request("passkeys-get", **fields)
        self.ui.prompts[-1][3]({"entry": "gtk-passkey", "group": "", "replace": False})
        self.assertEqual(self.replies[-1]["result"]["response"]["id"], "public-credential")
        self.assertEqual(self.touches, [1, 1])

    def test_cancelled_passkey_request_cannot_sign_or_register_later(self):
        self.authenticate()
        fields = {"publicKey": {"challenge": "fixture"}, "origin": "https://example.org"}
        event = self.request("passkeys-get", **fields)
        callback = self.ui.prompts[-1][3]
        self.controller.receive({"event": "cancel", "id": event["id"]})
        callback({"entry": "late", "group": "", "replace": False})
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "finish_passkey" for c in self.session.vault.calls))
        event = self.request("passkeys-register", **fields)
        self.session.jobs.deferred = True
        self.ui.prompts[-1][3]({"entry": "", "group": "", "replace": False})
        self.controller.receive({"event": "disconnected", "connection": event["connection"]})
        self.session.jobs.complete()
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "finish_passkey" for c in self.session.vault.calls))

    def test_browser_generation_requires_explicit_apply_without_accepting_remote_password(self):
        self.request("generate-password", password="remote value")
        self.assertEqual(self.ui.prompts[-1][0], "generate")
        self.assertFalse(self.replies)
        self.assertFalse(self.touches)
        self.ui.prompts[-1][3]("local generated password")
        self.assertEqual(self.replies[-1]["result"], {"password": "local generated password"})
        self.assertEqual(self.touches, [1])

    def test_cancelled_generator_cannot_send_a_late_password(self):
        event = self.request("generate-password")
        callback = self.ui.prompts[-1][3]
        self.controller.receive({"event": "cancel", "id": event["id"]})
        callback("late password")
        self.assertFalse(self.replies)
        self.assertFalse(self.touches)
        self.request("generate-password")
        self.ui.prompts[-1][3](None)
        self.assertEqual(self.replies[-1]["error_code"], 6)

    def test_browser_deletion_requires_authentication_and_confirmation(self):
        self.request("delete-entry", uuid="entry")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.authenticate()
        self.request("delete-entry", uuid="entry", approved=True, permanent=True)
        self.assertNotIn(("delete", "delete-token", True), self.session.vault.calls)
        self.ui.prompts[-1][3](False)
        self.assertEqual(self.replies[-1]["result"], {"success": "false"})
        self.request("delete-entry", uuid="entry")
        self.ui.prompts[-1][3](True)
        self.assertIn(("delete", "delete-token", True), self.session.vault.calls)
        self.assertIs(self.ui.deleted_session, self.session)
        self.assertEqual(self.replies[-1]["result"], {"success": "true"})
        self.session.vault.delete_found = False
        count = len(self.ui.prompts)
        self.request("delete-entry", uuid="missing")
        self.assertEqual(self.replies[-1]["result"], {"success": "false"})
        self.assertEqual(len(self.ui.prompts), count)

    def test_cancelled_queued_deletion_and_late_consent_cannot_mutate(self):
        self.authenticate()
        event = self.request("delete-entry", uuid="entry")
        callback = self.ui.prompts[-1][3]
        self.controller.receive({"event": "cancel", "id": event["id"]})
        callback(True)
        self.assertNotIn(("delete", "delete-token", True), self.session.vault.calls)
        event = self.request("delete-entry", uuid="entry")
        self.session.jobs.deferred = True
        self.ui.prompts[-1][3](True)
        self.controller.receive({"event": "disconnected", "connection": event["connection"]})
        self.session.jobs.complete()
        self.assertNotIn(("delete", "delete-token", True), self.session.vault.calls)

    def save_login(self, **body):
        return self.request("set-login", **{"id": "Browser", "url": "https://example.org", "login": "alice",
                                            "password": "public new password", **body})

    def test_browser_save_requires_authentication_and_gui_consent(self):
        self.save_login()
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.authenticate()
        self.save_login(id="another")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        event = self.save_login(approved=True, group="untrusted", groupUuid="browser-group")
        self.assertNotIn("password", event["body"])
        kind, _session, data, done = self.ui.prompts[-1]
        self.assertEqual(kind, "save")
        self.assertNotIn("public new password", str(data))
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "save" for c in self.session.vault.calls))
        done({"group": "gtk-group"})
        self.assertIn(("save", "save-token", True, "gtk-group"), self.session.vault.calls)
        self.assertIs(self.ui.saved_session, self.session)
        self.assertEqual(self.replies[-1]["result"], {"hash": "fixture-hash", "count": None, "entries": None, "error": "success"})
        self.assertEqual(self.touches, [1])

    def test_cancelled_save_and_late_approval_never_write(self):
        self.authenticate()
        self.save_login()
        self.ui.prompts[-1][3](None)
        self.assertIn(("save", "save-token", False, ""), self.session.vault.calls)
        self.assertEqual(self.replies[-1]["result"]["error"], "error")
        event = self.save_login()
        callback = self.ui.prompts[-1][3]
        self.controller.receive({"event": "cancel", "id": event["id"]})
        callback({"group": ""})
        self.assertNotIn(("save", "save-token", True, ""), self.session.vault.calls)
        self.assertFalse(self.touches)

    def test_cancel_before_queued_browser_save_prevents_mutation(self):
        self.authenticate()
        event = self.save_login()
        self.session.jobs.deferred = True
        self.ui.prompts[-1][3]({"group": ""})
        self.controller.receive({"event": "disconnected", "connection": event["connection"]})
        self.session.jobs.complete()
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "save" for c in self.session.vault.calls))

    def test_malformed_save_fields_and_unchanged_save_are_not_prompted(self):
        self.authenticate()
        self.save_login(password=None)
        self.assertEqual(self.replies[-1]["error_code"], 12)
        self.save_login(url="")
        self.assertEqual(self.replies[-1]["error_code"], 14)
        self.session.vault.browser_prepare_save = lambda *_args, **_kwargs: {"token": "save-token", "changed": False}
        self.save_login()
        self.assertFalse(self.ui.prompts)
        self.assertEqual(self.replies[-1]["result"]["error"], "error")

    def test_totp_and_group_reads_require_authentication_without_extending_idle(self):
        self.request("get-totp", uuid="1" * 32)
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.request("get-database-groups")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.authenticate()
        self.request("get-totp", uuid="1" * 32)
        self.assertEqual(self.replies[-1]["result"], {"totp": "123456"})
        self.request("get-totp", uuid=None)
        self.assertEqual(self.replies[-1]["error_code"], 18)
        self.request("get-database-groups")
        self.assertEqual(self.replies[-1]["result"]["groups"]["groups"][0]["name"], "Root")
        self.request("get-database-groups", id="another")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.assertFalse(self.ui.prompts)
        self.assertFalse(self.touches)

    def test_browser_group_creation_requires_gui_consent_but_existing_groups_do_not_write(self):
        self.authenticate()
        self.request("create-new-group", groupName="Web/New", approved=True)
        self.assertEqual(self.ui.prompts[-1][0], "create_group")
        self.assertNotIn(("create_group", "group-token", True), self.session.vault.calls)
        self.ui.prompts[-1][3](None)
        self.assertIn(("create_group", "group-token", False), self.session.vault.calls)
        self.assertEqual(self.replies[-1]["error_code"], 17)
        self.request("create-new-group", groupName="Web/New")
        self.ui.prompts[-1][3](True)
        self.assertIn(("create_group", "group-token", True), self.session.vault.calls)
        self.assertEqual(self.replies[-1]["result"], {"name": "Created", "uuid": "created"})
        self.assertIs(self.ui.group_session, self.session)
        self.assertEqual(self.touches, [1])
        self.session.vault.group_exists = True
        count = len(self.ui.prompts)
        self.request("create-new-group", groupName="Existing")
        self.assertEqual(len(self.ui.prompts), count)
        self.assertEqual(self.replies[-1]["result"], {"name": "Existing", "uuid": "existing"})

    def test_cancelled_group_request_ignores_late_or_queued_approval(self):
        self.authenticate()
        event = self.request("create-new-group", groupName="Web/New")
        callback = self.ui.prompts[-1][3]
        self.controller.receive({"event": "cancel", "id": event["id"]})
        callback(True)
        self.assertNotIn(("create_group", "group-token", True), self.session.vault.calls)
        self.assertFalse(self.touches)
        event = self.request("create-new-group", groupName="Web/New")
        self.session.jobs.deferred = True
        self.ui.prompts[-1][3](True)
        self.controller.receive({"event": "disconnected", "connection": event["connection"]})
        self.session.jobs.complete()
        self.assertNotIn(("create_group", "group-token", True), self.session.vault.calls)

    def test_unassociated_browser_and_wrong_key_list_cannot_request_credentials(self):
        self.logins(approved=True, remember=True)
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.assertFalse(self.session.vault.calls)
        self.authenticate()
        self.request("get-logins", url="https://example.org", keys=[{"id": "Browser", "key": OTHER}])
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.assertFalse(any(call[0] == "lookup" for call in self.session.vault.calls if isinstance(call, tuple)))

    def test_remote_approval_fields_are_not_consent_and_polling_does_not_touch_idle(self):
        self.authenticate()
        self.logins(approved=True, remember=True)
        self.assertEqual(self.ui.prompts[-1][0], "access")
        self.assertFalse(any(call[0] == "release" for call in self.session.vault.calls if isinstance(call, tuple)))
        self.assertFalse(self.touches)
        self.ui.prompts[-1][3]({"allow": True, "selected": ["entry"], "remember": False})
        self.assertIn(("release", "private-token", ["entry"], True, False), self.session.vault.calls)
        self.assertEqual(self.replies[-1]["result"]["entries"][0]["password"], "public fixture password")
        self.assertEqual(self.touches, [1])

    def test_previously_allowed_entries_do_not_open_a_prompt_or_extend_idle(self):
        self.authenticate()
        self.session.vault.allowed = True
        self.logins(approved=True, remember=True)
        self.assertFalse(self.ui.prompts)
        self.assertFalse(self.touches)
        self.assertIn(("release", "private-token", ["entry"], False, False), self.session.vault.calls)

    def test_cancel_closes_prompt_and_ignores_late_consent(self):
        self.authenticate()
        event = self.logins()
        callback = self.ui.prompts[-1][3]
        self.controller.receive({"event": "cancel", "id": event["id"]})
        count = len(self.replies)
        callback({"allow": True, "selected": ["entry"], "remember": True})
        self.assertEqual(len(self.replies), count)
        self.assertEqual(self.ui.dismissed, ["access"])
        self.assertFalse(any(call[0] == "release" for call in self.session.vault.calls if isinstance(call, tuple)))

    def test_rekey_and_disconnect_clear_authentication_and_old_prompts(self):
        self.authenticate()
        self.logins()
        callback = self.ui.prompts[-1][3]
        self.request("get-logins", generation="2", url="https://example.org", keys=[{"id": "Browser", "key": KEY}])
        self.assertEqual(self.replies[-1]["error_code"], 8)
        callback({"allow": True, "selected": ["entry"], "remember": True})
        self.assertFalse(self.controller.associations)
        self.authenticate()
        self.logins()
        self.controller.receive({"event": "disconnected", "connection": "connection"})
        self.assertFalse(self.controller.associations)
        self.assertFalse(self.controller.pending)

    def test_lock_or_helper_replacement_cannot_reuse_prior_consent(self):
        self.authenticate()
        self.logins()
        callback = self.ui.prompts[-1][3]
        self.session.vault.unlocked = False
        self.session.epoch += 1
        self.controller.state_changed()
        self.assertEqual(self.replies[-2]["error_code"], 1)
        self.assertEqual(self.replies[-1], {"notification": "database-locked"})
        callback({"allow": True, "selected": ["entry"], "remember": True})
        self.assertFalse(self.controller.associations)
        self.session.vault.unlocked = True
        self.authenticate()
        self.session.vault.identity = object()
        self.controller.state_changed()
        self.assertFalse(self.controller.associations)

    def test_browser_lock_rechecks_authentication_and_replies_before_notification(self):
        self.request("lock-database")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.authenticate()
        authenticate = self.session.vault.browser_authenticate
        self.session.vault.browser_authenticate = lambda *_: {"authenticated": False}
        self.request("lock-database")
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.assertFalse(self.lock_calls)
        self.session.vault.browser_authenticate = authenticate
        second = SimpleNamespace(vault=Vault(), jobs=Jobs(), epoch=0)
        self.app.sessions.append(second)
        event = self.request("lock-database")  # Upstream derives the database hash, not from a remote field.
        self.assertEqual(self.replies[-2], {"id": event["id"], "result": {}})
        self.assertEqual(self.replies[-1], {"notification": "database-locked"})
        self.assertEqual(self.lock_calls, [self.session])
        self.assertFalse(self.session.vault.unlocked)
        self.assertTrue(second.vault.unlocked)
        self.assertFalse(self.touches)

    def test_cancelled_browser_lock_cannot_execute_after_rekey_or_disconnect(self):
        self.authenticate()
        self.session.jobs.deferred = True
        event = self.request("lock-database")
        self.controller.receive({"event": "cancel", "id": event["id"]})
        self.session.jobs.complete()
        self.assertFalse(self.lock_calls)
        self.assertTrue(self.session.vault.unlocked)

    def test_notifications_track_active_identity_and_lock_without_repeating_for_polling(self):
        self.controller.state_changed()
        self.assertFalse(self.replies)
        self.session.lock()
        self.controller.state_changed()
        self.assertEqual(self.replies, [{"notification": "database-locked"}])
        self.session.vault.unlocked = True
        self.controller.state_changed()
        self.controller.state_changed()
        self.assertEqual(self.replies[-1], {"notification": "database-unlocked"})
        count = len(self.replies)
        self.session.vault.identity = object()
        self.controller.state_changed()
        self.assertEqual(len(self.replies), count + 1)
        self.assertEqual(self.replies[-1], {"notification": "database-unlocked"})
        count = len(self.replies)
        self.session.vault.snapshot = SimpleNamespace(root="replaced-database-root")
        self.controller.state_changed()
        self.assertEqual(len(self.replies), count + 1)
        self.assertEqual(self.replies[-1], {"notification": "database-unlocked"})
        self.app.active_session = None
        self.controller.state_changed()
        self.assertEqual(self.replies[-1], {"notification": "database-locked"})
        self.controller.close()
        count = len(self.replies)
        self.app.active_session = self.session
        self.controller.state_changed()
        self.assertEqual(len(self.replies), count)
        self.assertFalse(self.touches)

    def test_cancellation_before_deferred_pair_save_cannot_write_association(self):
        event = self.request("associate", key=KEY)
        self.session.jobs.deferred = True
        self.ui.prompts[-1][3]({"name": "Browser", "replace": False})
        self.assertTrue(self.session.jobs.queue)
        self.controller.receive({"event": "cancel", "id": event["id"]})
        self.session.jobs.complete()
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "associate" for call in self.session.vault.calls))

    def test_authentication_is_scoped_to_database_and_connection(self):
        self.authenticate()
        second = SimpleNamespace(vault=Vault(), jobs=Jobs(), epoch=0, busy=False, dialogs=[], touch=lambda: None)
        self.app.sessions.append(second)
        self.app.active_session = second
        self.logins()
        self.assertEqual(self.replies[-1]["error_code"], 8)
        self.app.active_session = self.session
        self.request("get-logins", connection="another", url="https://example.org", keys=[{"id": "Browser", "key": KEY}])
        self.assertEqual(self.replies[-1]["error_code"], 8)

    def test_existing_editor_is_not_closed_or_replaced_by_browser_prompt(self):
        self.authenticate()
        editor = object()
        self.session.dialogs.append(editor)
        self.logins()
        self.assertEqual(self.replies[-1]["error_code"], 6)
        self.assertEqual(self.session.dialogs, [editor])
        self.assertFalse(self.ui.prompts)

    def test_queued_foreground_work_takes_precedence_over_browser_prompt(self):
        self.authenticate()
        self.session.busy = True
        self.logins()
        self.assertEqual(self.replies[-1]["error_code"], 6)
        self.assertFalse(self.ui.prompts)


if __name__ == "__main__":
    unittest.main()
