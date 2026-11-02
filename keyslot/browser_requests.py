"""Browser requests stay on private pipes; consent comes from GTK or the companion."""
from dataclasses import dataclass
import base64

from .backend import VaultError
from .core_backend import EngineError
from .startup import BROWSER_MATCH_DEFAULTS


@dataclass(repr=False)
class Pending:
    identifier: str
    client: tuple
    event: dict
    session: object
    epoch: int
    identity: object
    policy: tuple
    dismiss: object = None


@dataclass(repr=False)
class Association:
    session: object
    epoch: int
    identity: object
    identifier: str
    key: str


def public_key(value):
    if not isinstance(value, str):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
        return len(decoded) == 32 and base64.b64encode(decoded).decode() == value
    except ValueError:
        return False


class BrowserRequests:
    def __init__(self, application, ui, reply):
        self.app, self.ui, self.reply = application, ui, reply
        self.pending = {}
        self.associations = {}
        self.closed = False
        self.state = self._state()

    def _state(self):
        session = self.app.active_session
        identity = session.vault.identity if session and not session.jobs.closed and session.vault.unlocked else None
        root = getattr(getattr(session.vault, "snapshot", None), "root", None) if identity is not None else None
        return session, identity, root, self.app.startup.browser_policy_value

    def _session_valid(self, item):
        session = item.session
        return (not self.closed and session in self.app.sessions and not session.jobs.closed
                and session.vault.unlocked and session.epoch == item.epoch
                and session.vault.identity is item.identity)

    def _valid(self, request):
        return (self.pending.get(request.identifier) is request and self._session_valid(request)
                and request.policy == self.app.startup.browser_policy_value)

    def _drop(self, request):
        if self.pending.get(request.identifier) is not request:
            return
        self.pending.pop(request.identifier)
        dismiss, request.dismiss = request.dismiss, None
        if dismiss:
            dismiss()

    def _finish(self, request, result=None, error=None):
        if self.pending.get(request.identifier) is not request:
            return
        if error is None and not self._valid(request):
            error = 1
        self._drop(request)
        self.reply({"id": request.identifier, "error_code": error} if error is not None
                   else {"id": request.identifier, "result": result})

    def state_changed(self):
        if self.closed:
            return
        for request in list(self.pending.values()):
            if not self._valid(request):
                self._finish(request, error=1)
        for client, association in list(self.associations.items()):
            if not self._session_valid(association):
                self.associations.pop(client, None)
        state = self._state()
        if state != self.state:
            self.state = state
            self.reply({"notification": "database-unlocked" if state[1] is not None else "database-locked"})

    def close(self):
        self.closed = True
        for request in list(self.pending.values()):
            self._drop(request)
        self.associations.clear()

    def _job(self, request, operation, done):
        def perform():
            if not self._valid(request):
                raise VaultError("The browser request was cancelled.")
            try:
                return True, operation()
            except EngineError as exc:
                return False, {"association_failed": 8, "conflict": 1, "expired": 5,
                               "denied": 6, "invalid_request": 12, "invalid_uuid": 18, "not_found": 15,
                               "listing_denied": 19, "no_groups": 16, "too_large": 7, "references_not_allowed": 34}.get(exc.code, 6)

        def complete(value):
            if not self._valid(request):
                self._finish(request, error=1)
            elif value[0]:
                done(value[1])
            else:
                self._finish(request, error=value[1])
        # Polling must not reset inactivity lock. Only an actual GTK consent action touches activity.
        if not request.session.jobs.run(perform, complete, lambda _message: self._finish(request, error=6), interactive=False):
            self._finish(request, error=6)

    def _prompt(self, request, prompt, data, done, foreground=True):
        if not self._valid(request):
            self._finish(request, error=1)
            return
        if (request.session.dialogs or request.session.busy
                or any(item is not request and item.dismiss for item in self.pending.values())):
            self._finish(request, error=6)
            return
        if foreground:
            self.app.select_session(request.session)
        dismiss = prompt(request.session, data, lambda value: done(value) if self._valid(request) else None)
        if self._valid(request):
            request.dismiss = dismiss
        elif dismiss:
            dismiss()

    def receive(self, event):
        if self.closed or not isinstance(event, dict):
            return
        kind = event.get("event")
        if kind == "cancel":
            if request := self.pending.get(event.get("id")):
                self._drop(request)
            return
        if kind == "disconnected":
            connection = event.get("connection")
            for request in list(self.pending.values()):
                if request.client[0] == connection:
                    self._drop(request)
            self.associations = {key: value for key, value in self.associations.items() if key[0] != connection}
            return
        if kind != "request":
            return
        identifier = event.get("id")
        fields = [event.get(name) for name in ("connection", "client", "generation")]
        body, action = event.get("body"), event.get("action")
        if (not isinstance(identifier, str) or not identifier or not all(isinstance(v, str) and v for v in fields)
                or not isinstance(body, dict) or body.get("action") != action):
            if isinstance(identifier, str):
                self.reply({"id": identifier, "error_code": 12})
            return
        client = tuple(fields)
        for old in list(self.associations):
            if old[:2] == client[:2] and old != client:
                self.associations.pop(old)
        for request in list(self.pending.values()):
            if request.client[:2] == client[:2] and request.client != client:
                self._drop(request)
        session = self.app.active_session
        if session is None or session.jobs.closed or not session.vault.unlocked:
            self.reply({"id": identifier, "error_code": 1})
            if event.get("trigger_unlock") is True and session is not None:
                self.ui.unlock(session)
            return
        if identifier in self.pending or len(self.pending) >= 128:
            self.reply({"id": identifier, "error_code": 6})
            return
        request = Pending(identifier, client, event, session, session.epoch, session.vault.identity,
                          self.app.startup.browser_policy_value)
        self.pending[identifier] = request
        vault = session.vault
        if action == "get-databasehash":
            self._job(request, vault.browser_info, lambda value: self._finish(request, {"hash": value["hash"]}))
        elif action == "associate":
            self._associate(request, body)
        elif action == "test-associate":
            identifier, key = body.get("id"), body.get("key")
            if not isinstance(identifier, str) or not identifier or not public_key(key):
                self._finish(request, error=8)
                return
            def authenticated(value):
                if not value["authenticated"]:
                    self._finish(request, error=8)
                    return
                self.associations[client] = Association(session, session.epoch, vault.identity, identifier, key)
                self._finish(request, {"hash": value["hash"], "id": identifier})
            self._job(request, lambda: vault.browser_authenticate(identifier, key), authenticated)
        elif action == "get-logins":
            self._logins(request, body)
        elif action == "set-login":
            self._save_login(request, body)
        elif action == "lock-database":
            self._lock_database(request, body)
        elif action == "generate-password":
            def generated(password):
                if not isinstance(password, str) or not password:
                    self._finish(request, error=6)
                else:
                    request.session.touch()
                    self._finish(request, {"password": password})
            self._prompt(request, self.ui.generate, {}, generated)
        elif action == "delete-entry":
            self._delete_entry(request, body)
        elif action in {"passkeys-register", "passkeys-get"}:
            self._passkey(request, body, action == "passkeys-register")
        elif action in {"get-totp", "get-database-groups", "get-database-entries", "create-new-group"}:
            self._entry_or_group(request, action, body)
        else:
            self._finish(request, error=12)

    def _passkey(self, request, body, registration):
        association = self.associations.get(request.client)
        if (not association or association.session is not request.session or not self._session_valid(association)
                or ("id" in body and body["id"] != association.identifier)):
            self._finish(request, error=8)
            return
        options, origin = body.get("publicKey"), body.get("origin")
        if not isinstance(options, dict) or not options:
            self._finish(request, error=24)
            return
        if not isinstance(origin, str) or not origin:
            self._finish(request, error=25)
            return
        group = body.get("groupName", "")
        if not isinstance(group, str):
            self._finish(request, error=12)
            return
        vault = request.session.vault

        def ready(review):
            if error := review.get("error_code"):
                if error in (24, 25):
                    self._finish(request, error=error)
                else:
                    self._finish(request, {"response": {"errorCode": error}})
                return
            def completed(value):
                if registration and "errorCode" not in value:
                    self.ui.passkey_saved(request.session)
                self._finish(request, {"response": value})
            def chosen(choice):
                if choice is None:
                    self._job(request, lambda: vault.browser_finish_passkey(review["token"]), completed)
                    return
                if (not isinstance(choice, dict) or not isinstance(choice.get("entry"), str)
                        or not isinstance(choice.get("group"), str) or type(choice.get("replace")) is not bool):
                    self._finish(request, error=6)
                    return
                request.session.touch()
                self._job(request, lambda: vault.browser_finish_passkey(review["token"], approved=True,
                    entry=choice["entry"], group=choice["group"], replace=choice["replace"]), completed)
            self._prompt(request, self.ui.passkey, review, chosen)
        self._job(request, lambda: vault.browser_prepare_passkey(association.identifier, association.key,
            "register" if registration else "get", options, origin, group), ready)

    def _delete_entry(self, request, body):
        association = self.associations.get(request.client)
        if not association or association.session is not request.session or not self._session_valid(association):
            self._finish(request, error=8)
            return
        uuid = body.get("uuid")
        if not isinstance(uuid, str) or not uuid:
            self._finish(request, error=18)
            return
        vault = request.session.vault

        def ready(review):
            if not review["found"]:
                self._finish(request, {"success": "false"})
                return
            def deleted(changed):
                if changed:
                    self.ui.deleted(request.session)
                self._finish(request, {"success": "true" if changed else "false"})
            def chosen(choice):
                if choice is True:
                    request.session.touch()
                self._job(request, lambda: vault.browser_delete(review["token"], approved=choice is True), deleted)
            self._prompt(request, self.ui.delete_entry, review, chosen)
        self._job(request, lambda: vault.browser_prepare_delete(association.identifier, association.key, uuid), ready)

    def _lock_database(self, request, body):
        association = self.associations.get(request.client)
        if not association or association.session is not request.session or not self._session_valid(association):
            self._finish(request, error=8)
            return
        vault = request.session.vault

        def checked(value):
            info, authentication = value
            if not authentication["authenticated"]:
                self._finish(request, error=8)
            elif not info.get("hash"):
                self._finish(request, error=2)
            else:
                # Send the successful response before lock invalidates requests and broadcasts its state.
                self._finish(request, {})
                request.session.lock()
        self._job(request, lambda: (vault.browser_info(), vault.browser_authenticate(association.identifier, association.key)), checked)

    def _entry_or_group(self, request, action, body):
        association = self.associations.get(request.client)
        if (not association or association.session is not request.session or not self._session_valid(association)
                or ("id" in body and body["id"] != association.identifier)):
            self._finish(request, error=8)
            return
        vault = request.session.vault
        if action == "get-totp":
            uuid = body.get("uuid")
            if not isinstance(uuid, str) or not uuid:
                self._finish(request, error=18)
                return
            self._job(request, lambda: vault.browser_totp(association.identifier, association.key, uuid),
                      lambda value: self._finish(request, {"totp": value}))
        elif action == "get-database-groups":
            self._job(request, lambda: vault.browser_groups(association.identifier, association.key),
                      lambda value: self._finish(request, {"groups": value}))
        elif action == "get-database-entries":
            settings = self.app.startup
            def allowed():
                try:
                    return settings.browser_listing_allowed()
                except (OSError, ValueError, VaultError):
                    return False
            def list_entries():
                if not allowed():
                    raise EngineError("listing_denied", "Access to all entries is denied.")
                entries = vault.browser_entries(association.identifier, association.key, allowed=True)
                if not allowed():
                    raise EngineError("listing_denied", "Access to all entries is denied.")
                return entries
            def listed(entries):
                # The user may revoke the switch after the worker finishes but before GTK delivers its result.
                if not settings.browser_listing:
                    self._finish(request, error=19)
                else:
                    self._finish(request, {"entries": entries})
            self._job(request, list_entries, listed)
        else:
            name = body.get("groupName")
            if not isinstance(name, str) or not name:
                self._finish(request, error=17)
                return

            def ready(review):
                if review["exists"]:
                    self._finish(request, {"name": review["name"], "uuid": review["uuid"]})
                    return

                def created(value):
                    if not value:
                        self._finish(request, error=17)
                        return
                    self.ui.group_created(request.session)
                    self._finish(request, value)

                def chosen(choice):
                    if choice is True:
                        request.session.touch()
                    self._job(request, lambda: vault.browser_create_group(review["token"], approved=choice is True), created)
                self._prompt(request, self.ui.create_group, review, chosen)
            self._job(request, lambda: vault.browser_prepare_group(association.identifier, association.key, name), ready)

    def _save_login(self, request, body):
        association = self.associations.get(request.client)
        if (not association or association.session is not request.session or not self._session_valid(association)
                or body.get("id") != association.identifier):
            self._finish(request, error=8)
            return
        url = body.get("url")
        if not isinstance(url, str) or not url:
            self._finish(request, error=14)
            return
        fields = {name: body.get(remote, "") for name, remote in
                  (("login", "login"), ("password", "password"), ("submit_url", "submitUrl"),
                   ("entry", "uuid"), ("group_uuid", "groupUuid"))}
        if any(not isinstance(value, str) for value in fields.values()):
            self._finish(request, error=12)
            return
        favicon = body.get("downloadFavicon", False)
        if type(favicon) is bool:
            favicon_requested = favicon
        elif isinstance(favicon, str) and favicon in ("", "true", "false"):
            favicon_requested = favicon == "true"
        else:
            self._finish(request, error=12)
            return
        vault = request.session.vault

        def ready(value):
            info, review = value
            # Pending GTK consent needs metadata/token, not a second copy of the supplied password.
            fields.clear()
            body.pop("password", None)

            review["favicon_requested"] = favicon_requested and not review["update"]

            def saved(outcome, icon_options=None):
                changed = outcome["changed"]
                if changed:
                    self.ui.saved(request.session)
                self._finish(request, {"hash": info["hash"], "count": None, "entries": None,
                                       "error": "success" if changed else "error"})
                if changed and outcome.get("entry") and outcome.get("icon_request") and icon_options is not None:
                    try:
                        self.ui.favicon_saved(request.session, outcome["entry"], icon_options, outcome["icon_request"])
                    except Exception:
                        from .icon_views import _release
                        _release(request.session, outcome["icon_request"])
                        request.session.toast("Login saved; its website icon could not be started")
                elif changed and icon_options is not None:
                    request.session.toast("Login saved; its website icon could not be queued")

            def legacy_save(approved=False, group=""):
                return {"changed": vault.browser_save(review["token"], approved=approved, group=group), "entry": ""}

            def chosen(choice):
                if choice is None:
                    self._job(request, legacy_save, saved)
                    return
                if not isinstance(choice, dict) or not isinstance(choice.get("group"), str) or type(choice.get("favicon", False)) is not bool:
                    self._finish(request, error=6)
                    return
                icon_options = choice.get("icon_options") if review["favicon_requested"] and choice.get("favicon") else None
                if icon_options is not None and (not isinstance(icon_options, dict) or set(icon_options) != {"timeout", "fallback"}
                    or type(icon_options["timeout"]) is not int or not 1 <= icon_options["timeout"] <= 300
                    or type(icon_options["fallback"]) is not bool):
                    self._finish(request, error=6)
                    return
                request.session.touch()
                if icon_options is not None:
                    self._job(request, lambda: vault.browser_save_details(review["token"], approved=True, group=choice["group"]),
                              lambda outcome: saved(outcome, icon_options))
                else:
                    self._job(request, lambda: legacy_save(True, choice["group"]), saved)

            if not review["changed"]:
                self._job(request, legacy_save, saved)
            else:
                self._prompt(request, self.ui.save_login, review, chosen)
        self._job(request, lambda: (vault.browser_info(), vault.browser_prepare_save(
            association.identifier, association.key, url, **fields)), ready)

    def _associate(self, request, body):
        key = body.get("key")
        identification = body.get("idKey") or key
        if key != request.event.get("public_key") or not public_key(key) or not public_key(identification):
            self._finish(request, error=8)
            return
        vault = request.session.vault
        def ready(value):
            info, connections = value
            def chosen(choice):
                if choice is None:
                    self._finish(request, error=6)
                    return
                name = choice.get("name") if isinstance(choice, dict) else None
                replace = choice.get("replace", False) if isinstance(choice, dict) else False
                if not isinstance(name, str) or not name.strip() or type(replace) is not bool:
                    self._finish(request, error=6)
                    return
                request.session.touch()
                def saved(_snapshot):
                    self.associations[request.client] = Association(request.session, request.session.epoch,
                        vault.identity, name, identification)
                    self._finish(request, {"hash": info["hash"], "id": name})
                self._job(request, lambda: vault.browser_associate(name, identification, replace=replace), saved)
            self._prompt(request, self.ui.pair, {"database": info["name"], "connections": connections}, chosen)
        self._job(request, lambda: (vault.browser_info(), vault.browser_associations()), ready)

    def _logins(self, request, body):
        association = self.associations.get(request.client)
        if not association or association.session is not request.session or not self._session_valid(association):
            self._finish(request, error=8)
            return
        keys = body.get("keys")
        if not isinstance(keys, list) or not any(isinstance(k, dict) and k.get("id") == association.identifier
                                               and k.get("key") == association.key for k in keys):
            self._finish(request, error=8)
            return
        url, form = body.get("url"), body.get("submitUrl", "")
        if not isinstance(url, str) or not url:
            self._finish(request, error=14)
            return
        if not isinstance(form, str):
            self._finish(request, error=12)
            return
        vault = request.session.vault
        def found(value):
            info, lookup = value
            token, entries = lookup["token"], lookup["entries"]
            def send(credentials):
                self._finish(request, {"hash": info["hash"], "id": body.get("id", "") if isinstance(body.get("id", ""), str) else "",
                    "entries": credentials, "count": len(credentials)})
            if not entries:
                self._job(request, lambda: vault.browser_deny(token, []), lambda _value: self._finish(request, error=15))
            elif all(entry["allowed"] for entry in entries):
                self._job(request, lambda: vault.browser_release(token, [e["uuid"] for e in entries]), send)
            else:
                def chosen(choice):
                    if choice is None:
                        self._finish(request, error=6)
                        return
                    if (not isinstance(choice, dict) or type(choice.get("allow")) is not bool
                            or type(choice.get("remember")) is not bool or type(choice.get("trust", False)) is not bool
                            or (choice.get("trust", False) and not choice["allow"])):
                        self._finish(request, error=6)
                        return
                    selected = choice.get("selected")
                    if not isinstance(selected, list) or any(not isinstance(v, str) for v in selected):
                        self._finish(request, error=6)
                        return
                    request.session.touch()
                    if choice["allow"]:
                        self._job(request, lambda: vault.browser_release(token, selected, approved=True,
                            remember=choice["remember"], trust=choice.get("trust", False)), send)
                    else:
                        self._job(request, lambda: vault.browser_deny(token, [e["uuid"] for e in entries], remember=choice["remember"]), send)
                self._prompt(request, self.ui.access, {"url": url, "submit_url": form, "entries": entries,
                    "connection": association.identifier, "database": info["name"],
                    "http_auth": body.get("httpAuth") == "true"},
                    chosen, foreground=False)
        self._job(request, lambda: (vault.browser_info(), vault.browser_lookup(association.identifier, association.key,
            url, form, http_auth=body.get("httpAuth") == "true", **dict(zip(BROWSER_MATCH_DEFAULTS, request.policy)))), found)
