"""Opt-in Secret Service provider. Vaults and wire crypto stay in private native helpers."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import time
import uuid

from gi.repository import Gio, GLib
from .backend import VaultError
from .core_backend import EngineError
from .secret_cipher import SecretCipher, encoded, decoded
from .secret_interfaces import INTERFACES, NAME, PREFIX, PROPERTIES, ROOT

MAX_SECRET_REPLY = 24 * 1024 * 1024


class SecretServiceBusy(VaultError):
    """Another provider is running; startup can continue without this service."""


class ServiceError(Exception):
    def __init__(self, name, message):
        self.name, self.message = name, message


def invalid(message="The Secret Service request is invalid."):
    raise ServiceError("org.freedesktop.DBus.Error.InvalidArgs", message)


def string(value, maximum=65536):
    if not isinstance(value, str) or len(value) > maximum or "\0" in value:
        invalid()
    return value


def attributes(value):
    if not isinstance(value, dict) or len(value) > 1024:
        invalid()
    return {string(key, 1024): string(item) for key, item in value.items()}


def item_properties(value):
    allowed = {PREFIX + "Item.Label", PREFIX + "Item.Attributes"}
    if not isinstance(value, dict) or not set(value) <= allowed:
        invalid("Only item Label and Attributes can be set at creation.")
    return dict(label=string(value.get(PREFIX + "Item.Label", "")),
                attributes=attributes(value.get(PREFIX + "Item.Attributes", {})))


def wire_secret(value):
    path, parameters, secret, content_type = value
    if len(parameters) > 16 or len(secret) > 8 * 1024 * 1024 + 16:
        invalid("The Secret Service payload is invalid or too large.")
    return path, bytes(parameters), bytes(secret), string(content_type, 1024)


@dataclass(eq=False)
class Collection:
    session: object
    path: str
    items: dict = field(default_factory=dict)
    snapshot: object = None

    def item_path(self, identifier):
        return self.path + "/" + identifier.replace("-", "")


@dataclass(eq=False)
class WireSession:
    path: str
    peer: str
    identifier: str
    identity: object


@dataclass(eq=False)
class Call:
    peer: str
    invocation: object
    expires: float
    size: int = 0
    live: bool = True


class SecretService:
    def __init__(self, app):
        self.app = app
        self.options = dict(app.startup.secret_service)
        self.connection = app.get_dbus_connection()
        self.instance = uuid.uuid4().hex
        self.cipher = SecretCipher()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="secret-service")
        self.objects, self.collections, self.aliases = {}, {}, {}
        self.sessions, self.prompts, self.peers, self.calls = {}, {}, {}, set()
        self.closed = False
        self.owner = False
        self.error = ""
        self.subscription = self.timer = 0
        self.closed_signal = 0
        self.prompt_check = 0
        self._active_collection = None
        self.property_changes = {}
        try:
            result = self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "RequestName", GLib.Variant("(su)", (NAME, 4)), GLib.VariantType.new("(u)"),
                Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
            if result not in (1, 4):
                raise SecretServiceBusy("Another Secret Service already owns the session bus name. Keyslot has not replaced it. Stop that provider before enabling Keyslot’s service.")
            self.owner = True
            self._register(ROOT, "service", self)
            self.subscription = self.connection.signal_subscribe("org.freedesktop.DBus", "org.freedesktop.DBus",
                "NameOwnerChanged", "/org/freedesktop/DBus", None, Gio.DBusSignalFlags.NONE, self._name_changed)
            self.closed_signal = self.connection.connect("closed", self._bus_closed)
            self.timer = GLib.timeout_add_seconds(1, self._tick)
            self.state_changed()
        except Exception:
            self.close()
            raise

    def _register(self, path, kind, value):
        registration = self.connection.register_object(path, INTERFACES[kind], self._call, None, None)
        self.objects[path] = (kind, value, registration)

    def _remove(self, path):
        value = self.objects.pop(path, None)
        if value:
            self.connection.unregister_object(value[2])

    def _emit(self, path, interface, signal, signature, values, destination=None):
        if not self.closed:
            self.connection.emit_signal(destination, path, interface, signal, GLib.Variant(signature, values))

    def _changed(self, path, kind, invalidated):
        if kind == "service":
            self._notify(path, kind, {"Collections": GLib.Variant("ao", [c.path for c in self.collections.values()])})
            return
        target = self.objects.get(path)
        if not target:
            return
        collection = target[1] if kind == "collection" else target[1][0]
        if not collection.session.vault.unlocked:
            self._notify(path, kind, {"Locked": GLib.Variant("b", True), "Items": GLib.Variant("ao", [])} if kind == "collection"
                         else {"Locked": GLib.Variant("b", True)})
            return
        token = object()
        previous = self.property_changes.get(path)
        fields = set(invalidated) | (previous[1] if previous else set())
        self.property_changes[path] = token, fields
        if previous:
            return
        context = self._context(collection)
        args = dict(peer=self.connection.get_unique_name())
        if kind == "item":
            args["entry"] = target[1][1]
        future = self.executor.submit(lambda: self._vault(collection, context, "info", **args))
        def completed():
            pending = self.property_changes.pop(path, None)
            if self.closed or not pending or self.objects.get(path) is not target:
                return False
            try:
                self._valid_vault(collection, context)
                if pending[0] is not token:
                    self._changed(path, kind, pending[1])
                    return False
                data = future.result()
                props = {"Label": GLib.Variant("s", data["label"]), "Created": GLib.Variant("t", max(0, data["created"])),
                         "Modified": GLib.Variant("t", max(0, data["modified"]))}
                if kind == "item":
                    # Public metadata only; authorization and TOTP replies belong to individual peers.
                    props["Attributes"] = GLib.Variant("a{ss}", data["attributes"])
                else:
                    props["Locked"] = GLib.Variant("b", False)
                    props["Items"] = GLib.Variant("ao", [collection.item_path(identifier) for identifier in data["items"]])
                self._notify(path, kind, {key: value for key, value in props.items() if key in fields})
            except (VaultError, GLib.Error, OSError):
                pass
            return False
        future.add_done_callback(lambda *_: GLib.idle_add(completed))

    def _notify(self, path, kind, properties, destination=None):
        # libsecret does not reload invalidated properties; send their actual values.
        self._emit(path, PROPERTIES, "PropertiesChanged", "(sa{sv}as)", (PREFIX + kind.title(), properties, []), destination)

    def _peer(self, sender):
        if sender not in self.peers:
            if len(self.peers) >= 256:
                raise ServiceError("org.freedesktop.DBus.Error.LimitsExceeded", "Too many Secret Service clients.")
            user = self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "GetConnectionUnixUser", GLib.Variant("(s)", (sender,)), GLib.VariantType.new("(u)"),
                Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
            if user != os.getuid():
                raise ServiceError("org.freedesktop.DBus.Error.AccessDenied", "Only this user may access Keyslot’s Secret Service.")
            self.peers[sender] = object()
        return self.peers[sender]

    def peer_label(self, sender):
        try:
            pid = self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "GetConnectionUnixProcessID", GLib.Variant("(s)", (sender,)), GLib.VariantType.new("(u)"),
                Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
            return f"{executable.name} (PID {pid}, {sender})"
        except (GLib.Error, OSError):
            return "Application " + sender

    def _name_changed(self, _c, _sender, _path, _interface, _signal, parameters):
        if self.closed:
            return
        name, old, new = parameters.unpack()
        if name == NAME and old == self.connection.get_unique_name() and new != old:
            self.close()
            return
        if not name.startswith(":") or new or name not in self.peers:
            return
        self.peers.pop(name, None)
        for call in list(self.calls):
            if call.peer == name:
                call.live = False
                self.calls.discard(call)
        for prompt in list(self.prompts.values()):
            if prompt.peer == name:
                prompt.complete(True)
        for session in list(self.sessions.values()):
            if session.peer == name:
                self._remove(session.path)
                self.sessions.pop(session.path, None)
        collections = [(collection, self._context(collection)) for collection in self.collections.values()
                       if collection.session.vault.unlocked and not collection.session.jobs.closed]
        def cleanup():
            try:
                self.cipher.drop_peer(name)
            except VaultError:
                pass
            for collection, context in collections:
                try:
                    self._vault(collection, context, "drop-peer", peer=name)
                except VaultError:
                    pass
        self.executor.submit(cleanup)

    def _bus_closed(self, *_args):
        def stopped():
            if not self.closed:
                self.app.secret_service_error = "The desktop session bus disconnected. Restart Keyslot to provide Secret Service again."
                self.close()
            return False
        GLib.idle_add(stopped)

    def _tick(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        for call in list(self.calls):
            if call.expires < time.monotonic():
                call.live = False
                self.calls.discard(call)
                call.invocation.return_dbus_error("org.freedesktop.DBus.Error.Timeout", "The Secret Service request timed out.")
        for prompt in list(self.prompts.values()):
            prompt.check()
        return GLib.SOURCE_CONTINUE

    def _check_prompts(self):
        self.prompt_check = 0
        if not self.closed:
            for prompt in list(self.prompts.values()):
                prompt.check()
        return GLib.SOURCE_REMOVE

    def _error(self, invocation, error):
        if isinstance(error, ServiceError):
            invocation.return_dbus_error(error.name, error.message)
            return
        code = getattr(error, "code", "")
        name = {"no_session": PREFIX + "Error.NoSession", "denied": PREFIX + "Error.IsLocked",
                "locked": PREFIX + "Error.IsLocked", "disabled": PREFIX + "Error.IsLocked",
                "not_found": PREFIX + "Error.NoSuchObject", "invalid_request": "org.freedesktop.DBus.Error.InvalidArgs",
                "unsupported": "org.freedesktop.DBus.Error.NotSupported", "busy": "org.freedesktop.DBus.Error.LimitsExceeded"}.get(code,
                "org.freedesktop.DBus.Error.Failed")
        message = str(error) if isinstance(error, VaultError) else "Keyslot could not complete this Secret Service request."
        invocation.return_dbus_error(name, message)

    def _submit(self, peer, invocation, operation, done, *, contexts=(), wire_sessions=()):
        size = invocation.get_parameters().get_size()
        if len(self.calls) >= 128 or sum(call.peer == peer for call in self.calls) >= 16 or size + sum(call.size for call in self.calls) > 32 * 1024 * 1024:
            raise ServiceError("org.freedesktop.DBus.Error.LimitsExceeded", "Too many pending Secret Service requests.")
        identity = self.peers[peer]
        call = Call(peer, invocation, time.monotonic() + 120, size)
        self.calls.add(call)
        policy = self.instance, self.options["confirm_access"]
        def valid():
            if self.closed or not call.live or self.peers.get(peer) is not identity:
                raise VaultError("The Secret Service client disconnected.")
            if (self.instance, self.options["confirm_access"]) != policy:
                raise EngineError("denied", "The Secret Service access policy changed. Try again.")
            for collection, context in contexts:
                self._valid_vault(collection, context)
            for session in wire_sessions:
                if self.sessions.get(session.path) is not session:
                    raise EngineError("no_session", "The Secret Service session was closed.")
        def perform():
            valid()
            return operation()
        future = self.executor.submit(perform)
        def completed():
            self.calls.discard(call)
            if self.closed or not call.live or self.peers.get(peer) is not identity:
                return False
            try:
                # Vault locks and session closure must also discard already-computed secret replies.
                valid()
                result = future.result()
                call.live = False
                done(result)
            except Exception as exc:
                call.live = False
                self._error(invocation, exc)
            return False
        future.add_done_callback(lambda *_: GLib.idle_add(completed))

    def _context(self, collection):
        session = collection.session
        snapshot = session.vault.snapshot
        return session.epoch, session.vault.identity, session.vault.generation, snapshot.secret_group if snapshot else ""

    def _valid_vault(self, collection, context):
        session = collection.session
        snapshot = session.vault.snapshot
        if (self.closed or session.jobs.closed or not session.vault.unlocked
                or snapshot is None
                or self.collections.get(session) is not collection
                or context[:2] != (session.epoch, session.vault.identity)
                or context[3] != snapshot.secret_group):
            raise EngineError("locked", "The Secret Service vault was locked or closed.")

    def _vault(self, collection, context, operation, **values):
        self._valid_vault(collection, context)
        session = collection.session
        with session.vault.operation(context[2]):
            session.vault.secret_request("configure", confirm_access=self.options["confirm_access"], instance=self.instance)
            return session.vault.secret_request(operation, **values)

    def state_changed(self):
        if self.closed:
            return
        policy_changed = self.options["confirm_access"] != self.app.startup.secret_service["confirm_access"]
        self.options = dict(self.app.startup.secret_service)
        if policy_changed:
            self.instance = uuid.uuid4().hex
            for prompt in list(self.prompts.values()):
                prompt.complete(True)
        for session, collection in list(self.collections.items()):
            if session not in self.app.sessions or session.jobs.closed or (session.vault.unlocked and not session.vault.snapshot.secret_group):
                self._remove_collection(collection)
        for session in list(self.app.sessions):
            if session.jobs.closed or not session.path:
                continue
            snapshot = session.vault.snapshot if session.vault.unlocked else None
            if snapshot is not None and not snapshot.secret_group:
                continue
            collection = self.collections.get(session)
            if not collection:
                identifier = hashlib.sha256(str(Path(session.path).resolve()).encode()).hexdigest()[:32]
                collection = Collection(session, ROOT + "/collection/" + identifier)
                if collection.path in self.objects:
                    continue
                self.collections[session] = collection
                self._register(collection.path, "collection", collection)
                self._emit(ROOT, PREFIX + "Service", "CollectionCreated", "(o)", (collection.path,))
                self._changed(ROOT, "service", ["Collections"])
            if collection.snapshot is snapshot:
                continue
            collection.snapshot = snapshot
            exposed = set()
            if snapshot is not None:
                children = {}
                for group in snapshot.groups:
                    children.setdefault(group.parent, []).append(group.uuid)
                queue = [snapshot.secret_group]
                while queue:
                    identifier = queue.pop()
                    if identifier in exposed:
                        continue
                    exposed.add(identifier)
                    queue.extend(children.get(identifier, []))
            entries = {entry.uuid: entry for entry in snapshot.entries if not entry.recycled and entry.group in exposed} if snapshot else {}
            for identifier in set(collection.items) - set(entries):
                path = collection.item_path(identifier)
                self._notify(path, "item", {"Locked": GLib.Variant("b", True)})
                self._remove(path)
                self._emit(collection.path, PREFIX + "Collection", "ItemDeleted", "(o)", (path,))
            for identifier, entry in entries.items():
                path = collection.item_path(identifier)
                if identifier not in collection.items:
                    self._register(path, "item", (collection, identifier))
                    self._emit(collection.path, PREFIX + "Collection", "ItemCreated", "(o)", (path,))
                elif entry != collection.items[identifier]:
                    self._emit(collection.path, PREFIX + "Collection", "ItemChanged", "(o)", (path,))
                    self._changed(path, "item", ["Locked", "Label", "Attributes", "Modified"])
            collection.items = entries
            for path, (kind, value, _) in list(self.objects.items()):
                if kind == "collection" and value is collection:
                    self._changed(path, "collection", ["Items", "Label", "Locked", "Created", "Modified"])
            self._emit(ROOT, PREFIX + "Service", "CollectionChanged", "(o)", (collection.path,))
        active = self.collections.get(self.app.active_session)
        if active and active is not self._active_collection:
            self._set_alias("default", active)
        self._active_collection = active
        if policy_changed:
            for collection in self.collections.values():
                for identifier in collection.items:
                    path = collection.item_path(identifier)
                    self._notify(path, "item", {"Locked": GLib.Variant("b", self.options["confirm_access"])})
                    self._changed(path, "item", ["Attributes"])
        # Forms lock and emit state while they are still being constructed.
        if not self.prompt_check:
            self.prompt_check = GLib.idle_add(self._check_prompts)

    def _remove_collection(self, collection):
        for identifier in list(collection.items):
            self._notify(collection.item_path(identifier), "item", {"Locked": GLib.Variant("b", True)})
            self._remove(collection.item_path(identifier))
        for name, target in list(self.aliases.items()):
            if target is collection:
                self._set_alias(name, None)
        self._remove(collection.path)
        self.collections.pop(collection.session, None)
        self._emit(ROOT, PREFIX + "Service", "CollectionDeleted", "(o)", (collection.path,))
        self._changed(ROOT, "service", ["Collections"])

    def _set_alias(self, name, collection):
        name = string(name, 256)
        if not name or "/" in name:
            invalid("Choose a nonempty collection alias without slashes.")
        encoded_name = "".join(chr(byte) if (65 <= byte <= 90 or 97 <= byte <= 122 or 48 <= byte <= 57)
                               else f"_{byte:02x}" for byte in name.encode())
        path = ROOT + "/aliases/" + encoded_name
        if self.aliases.get(name) is collection:
            return
        self._remove(path)
        if collection:
            self.aliases[name] = collection
            self._register(path, "collection", collection)
        else:
            self.aliases.pop(name, None)

    def _wire_session(self, peer, path):
        session = self.sessions.get(path)
        if session is None or session.peer != peer:
            raise ServiceError(PREFIX + "Error.NoSession", "This session does not belong to the caller.")
        return session

    def _decode(self, wire, session):
        path, parameters, value, content_type = wire
        if path != session.path or len(parameters) > 16 or len(value) > 8 * 1024 * 1024 + 16:
            invalid("The Secret Service payload is invalid or too large.")
        return self.cipher.call("decode", session.peer, session.identifier, session.identity,
            parameters=encoded(parameters), value=encoded(value), content_type=string(content_type, 1024))

    def _encode(self, value, session):
        result = self.cipher.call("encode", session.peer, session.identifier, session.identity,
            parameters="", value=value["value"], content_type=value["content_type"])
        return session.path, decoded(result["parameters"]), decoded(result["value"]), result["content_type"]

    def _call(self, _connection, sender, path, interface, method, parameters, invocation):
        try:
            if parameters.get_size() > 12 * 1024 * 1024:
                invalid("The Secret Service request exceeds the message size limit.")
            if self.closed or path not in self.objects:
                raise ServiceError(PREFIX + "Error.NoSuchObject", "This Secret Service object is unavailable.")
            self._peer(sender)
            kind, target, _ = self.objects[path]
            if kind in ("session", "prompt") and target.peer != sender:
                raise ServiceError("org.freedesktop.DBus.Error.AccessDenied", "This object belongs to another caller.")
            if interface == PROPERTIES:
                self._properties(sender, kind, target, method, parameters, invocation)
            elif kind == "service":
                self._service(sender, method, parameters, invocation)
            elif kind == "collection":
                self._collection(sender, target, method, parameters, invocation)
            elif kind == "item":
                self._item(sender, *target, method, parameters, invocation)
            elif kind == "session":
                self._session_close(target, invocation)
            elif kind == "prompt":
                if method == "Dismiss":
                    target.complete(True)
                    invocation.return_value(None)
                else:
                    target.start()
                    invocation.return_value(None)
        except Exception as exc:
            self._error(invocation, exc)

    def _properties(self, peer, kind, target, method, parameters, invocation):
        values = parameters.unpack()
        if values[0] != PREFIX + kind.title():
            invalid("The requested Secret Service interface is unavailable.")
        if kind in ("session", "prompt"):
            if method == "GetAll":
                invocation.return_value(GLib.Variant("(a{sv})", ({},)))
                return
            invalid("This object has no D-Bus properties.")
        if method == "Set":
            prop = values[1]
            value = parameters.get_child_value(2).get_variant().unpack()
            if kind == "collection" and prop == "Label":
                collection, operation = target, dict(kind="collection-label", label=string(value))
            elif kind == "item" and prop in ("Label", "Attributes"):
                collection, identifier = target
                operation = dict(kind="set-label", label=string(value)) if prop == "Label" else dict(kind="set-attributes", attributes=attributes(value))
                operation["entry"] = identifier
            else:
                invalid("This property is read-only.")
            context = self._context(collection)
            def done(_result):
                collection.session.window.show_vault(collection.session.vault.snapshot)
                self.state_changed()
                invocation.return_value(None)
            self._submit(peer, invocation, lambda: self._vault(collection, context, "mutate", peer=peer, **operation), done,
                         contexts=[(collection, context)])
            return
        def respond(data):
            if method == "Get":
                if values[1] not in data:
                    invalid("This Secret Service property is unavailable.")
                invocation.return_value(GLib.Variant("(v)", (data[values[1]],)))
            else:
                invocation.return_value(GLib.Variant("(a{sv})", (data,)))
        if kind == "service":
            respond({"Collections": GLib.Variant("ao", [collection.path for collection in self.collections.values()])})
            return
        collection = target if kind == "collection" else target[0]
        context = self._context(collection)
        if not collection.session.vault.unlocked:
            if kind == "item":
                raise ServiceError(PREFIX + "Error.IsLocked", "The vault is locked.")
            respond({"Items": GLib.Variant("ao", []), "Label": GLib.Variant("s", Path(collection.session.path).stem),
                     "Locked": GLib.Variant("b", True), "Created": GLib.Variant("t", 0), "Modified": GLib.Variant("t", 0)})
            return
        args = dict(peer=peer)
        if kind == "item":
            args["entry"] = target[1]
            args["include_totp"] = method == "GetAll" or values[1] == "Attributes"
        def done(data):
            props = {"Label": GLib.Variant("s", data["label"]), "Created": GLib.Variant("t", max(0, data["created"])),
                     "Modified": GLib.Variant("t", max(0, data["modified"]))}
            if kind == "item":
                props["Locked"] = GLib.Variant("b", data["locked"])
                props["Attributes"] = GLib.Variant("a{ss}", data["attributes"])
            else:
                props["Locked"] = GLib.Variant("b", False)
                props["Items"] = GLib.Variant("ao", [collection.item_path(identifier) for identifier in data["items"]])
            respond(props)
        self._submit(peer, invocation, lambda: self._vault(collection, context, "info", **args), done,
                     contexts=[(collection, context)])

    def _service(self, peer, method, parameters, invocation):
        values = parameters.unpack()
        if method == "OpenSession":
            algorithm = string(values[0], 128)
            value = parameters.get_child_value(1).get_variant()
            if algorithm == "plain":
                if value.get_type_string() != "s" or value.unpack() != "":
                    invalid("Plain sessions require an empty string input.")
                wire = ""
            elif algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7":
                if value.get_type_string() != "ay" or len(value.unpack()) > 128:
                    invalid("DH sessions require a public key byte array.")
                wire = encoded(value.unpack())
            else:
                raise ServiceError("org.freedesktop.DBus.Error.NotSupported", "Unsupported Secret Service session algorithm.")
            def done(result):
                path = ROOT + "/session/" + result["session"]
                session = WireSession(path, peer, result["session"], result["identity"])
                self.sessions[path] = session
                self._register(path, "session", session)
                output = GLib.Variant("s", "") if result["plain"] else GLib.Variant("ay", decoded(result["output"]))
                invocation.return_value(GLib.Variant("(vo)", (output, path)))
            self._submit(peer, invocation, lambda: self.cipher.open(peer, algorithm, wire), done)
        elif method == "ReadAlias":
            collection = self.aliases.get(string(values[0], 256))
            invocation.return_value(GLib.Variant("(o)", (collection.path if collection else "/",)))
        elif method == "SetAlias":
            name, path = values
            target = self.objects.get(path)
            if path != "/" and (not target or target[0] != "collection"):
                raise ServiceError(PREFIX + "Error.NoSuchObject", "Choose an existing collection.")
            self._set_alias(name, target[1] if path != "/" else None)
            invocation.return_value(None)
        elif method == "SearchItems":
            self._search(peer, None, attributes(values[0]), invocation)
        elif method in ("Unlock", "Lock"):
            self._lock_objects(peer, values[0], invocation, method == "Lock")
        elif method == "GetSecrets":
            self._get_secrets(peer, values[0], self._wire_session(peer, values[1]), invocation)
        elif method == "CreateCollection":
            properties, alias = values
            if set(properties) - {PREFIX + "Collection.Label"}:
                invalid("Only a collection Label can be set at creation.")
            label = string(properties.get(PREFIX + "Collection.Label", "New Collection"))
            alias = string(alias, 256)
            if "/" in alias:
                invalid("Collection aliases cannot contain slashes.")
            if alias and alias in self.aliases:
                invocation.return_value(GLib.Variant("(oo)", (self.aliases[alias].path, "/")))
            else:
                prompt = self._prompt(peer, "create-collection", label=label, alias=alias)
                invocation.return_value(GLib.Variant("(oo)", ("/", prompt.path)))

    def _search(self, peer, collection, values, invocation, *, after_unlock=False):
        selected = [collection] if collection else list(self.collections.values())
        contexts = [(item, self._context(item)) for item in selected if item.session.vault.unlocked]
        if not contexts and self.options["unlock_before_search"] and not after_unlock:
            prompt = self._prompt(peer, "search", collection=collection, attributes=values, invocation=invocation)
            prompt.start()
            return
        def perform():
            unlocked, locked = [], []
            for item, context in contexts:
                result = self._vault(item, context, "search", peer=peer, attributes=values)
                unlocked.extend(item.item_path(identifier) for identifier in result["unlocked"])
                locked.extend(item.item_path(identifier) for identifier in result["locked"])
            return unlocked, locked
        def done(result):
            invocation.return_value(GLib.Variant("(ao)", (result[0] + result[1],)) if collection else GLib.Variant("(aoao)", result))
        self._submit(peer, invocation, perform, done, contexts=contexts)

    def _collection(self, peer, collection, method, parameters, invocation):
        values = parameters.unpack()
        if method == "SearchItems":
            self._search(peer, collection, attributes(values[0]), invocation)
        elif method == "Delete":
            prompt = self._prompt(peer, "close-collection", collection=collection)
            invocation.return_value(GLib.Variant("(o)", (prompt.path,)))
        elif method == "CreateItem":
            properties, wire, replace = values
            wire = wire_secret(wire)
            data = item_properties(properties)
            session = self._wire_session(peer, wire[0])
            prompt = self._prompt(peer, "create-item", collection=collection, wire=wire, wire_session=session,
                                  replace=replace, **data)
            invocation.return_value(GLib.Variant("(oo)", ("/", prompt.path)))

    def _item(self, peer, collection, identifier, method, parameters, invocation):
        values = parameters.unpack()
        if method == "Delete":
            prompt = self._prompt(peer, "delete-item", collection=collection, entry=identifier)
            invocation.return_value(GLib.Variant("(o)", (prompt.path,)))
        elif method == "GetSecret":
            self._get_secrets(peer, [collection.item_path(identifier)], self._wire_session(peer, values[0]), invocation, single=True)
        elif method == "SetSecret":
            wire = wire_secret(values[0])
            session = self._wire_session(peer, wire[0])
            context = self._context(collection)
            def perform():
                value = self._decode(wire, session)
                return self._vault(collection, context, "mutate", peer=peer, kind="set-secret", entry=identifier,
                                   value=value["value"], content_type=value["content_type"])
            def done(_result):
                collection.session.window.show_vault(collection.session.vault.snapshot)
                self.state_changed()
                invocation.return_value(None)
            self._submit(peer, invocation, perform, done, contexts=[(collection, context)], wire_sessions=[session])

    def _get_secrets(self, peer, paths, wire_session, invocation, single=False):
        if len(paths) > 1024:
            invalid("Choose at most 1024 Secret Service items.")
        groups = {}
        for path in dict.fromkeys(paths):
            target = self.objects.get(path)
            if not target or target[0] != "item":
                if single:
                    raise ServiceError(PREFIX + "Error.NoSuchObject", "The item is no longer exposed.")
                continue
            collection, identifier = target[1]
            groups.setdefault(collection, []).append(identifier)
        contexts = {collection: self._context(collection) for collection in groups}
        def perform():
            result = {}
            size = 0
            for collection, identifiers in groups.items():
                values = self._vault(collection, contexts[collection], "get", peer=peer, entries=identifiers, skip_locked=not single)
                for value in values["secrets"]:
                    path = collection.item_path(value["entry"])
                    wire = self._encode(value, wire_session)
                    size += len(wire[1]) + len(wire[2]) + len(wire[3].encode()) + len(path) * 2 + 64
                    if size > MAX_SECRET_REPLY:
                        raise ServiceError("org.freedesktop.DBus.Error.LimitsExceeded", "Request fewer items; this Secret Service reply exceeds the data limit.")
                    result[path] = wire
            return result
        def done(result):
            if result and self.options["notify"]:
                notification = Gio.Notification.new("Password Used")
                notification.set_body(f"{self.peer_label(peer)} read {len(result)} item(s) through Secret Service.")
                try:
                    self.app.send_notification("secret-service-access", notification)
                except GLib.Error:
                    pass
            # Consuming a one-shot grant is not a vault lock; clients use cached
            # Locked values to decide whether to load secrets.
            if single:
                if paths[0] not in result:
                    raise ServiceError(PREFIX + "Error.IsLocked", "Authorize the item before reading its secret.")
                invocation.return_value(GLib.Variant("((oayays))", (result[paths[0]],)))
            else:
                invocation.return_value(GLib.Variant("(a{o(oayays)})", (result,)))
        self._submit(peer, invocation, perform, done, contexts=list(contexts.items()), wire_sessions=[wire_session])

    def _lock_objects(self, peer, paths, invocation, locking):
        if len(paths) > 1024:
            invalid("Choose at most 1024 Secret Service objects.")
        targets = []
        for path in dict.fromkeys(paths):
            value = self.objects.get(path)
            if value and value[0] in ("collection", "item"):
                targets.append((path, value[0], value[1]))
        if locking:
            collections = {value if kind == "collection" else value[0] for _, kind, value in targets}
            for collection in collections:
                collection.session.lock()
            self.state_changed()
            invocation.return_value(GLib.Variant("(aoo)", ([collection.path for collection in collections], "/")))
            return
        if not targets:
            invocation.return_value(GLib.Variant("(aoo)", ([], "/")))
            return
        contexts = {target.session if kind == "collection" else target[0].session:
                    (target if kind == "collection" else target[0]) for _, kind, target in targets}
        unlocked_contexts = {collection: self._context(collection) for collection in contexts.values() if collection.session.vault.unlocked}
        def partition():
            immediate, pending = [], []
            for path, kind, target in targets:
                collection = target if kind == "collection" else target[0]
                if collection not in unlocked_contexts:
                    pending.append((path, kind, target))
                elif kind == "collection":
                    immediate.append(path)
                else:
                    context = unlocked_contexts[collection]
                    data = self._vault(collection, context, "info", peer=peer, entry=target[1])
                    if data["locked"]:
                        pending.append((path, kind, target))
                    else:
                        immediate.append(path)
            return immediate, pending
        def done(result):
            immediate, pending = result
            prompt = self._prompt(peer, "unlock", targets=pending) if pending else None
            invocation.return_value(GLib.Variant("(aoo)", (immediate, prompt.path if prompt else "/")))
        self._submit(peer, invocation, partition, done, contexts=list(unlocked_contexts.items()))

    def _prompt(self, peer, kind, **values):
        from .secret_prompts import SecretPrompt
        if len(self.prompts) >= 64 or sum(prompt.peer == peer for prompt in self.prompts.values()) >= 8:
            raise ServiceError("org.freedesktop.DBus.Error.LimitsExceeded", "Too many pending Secret Service prompts.")
        size = len(values.get("wire", (None, b"", b"", ""))[2])
        size += sum(len(key.encode()) + len(value.encode()) for key, value in values.get("attributes", {}).items())
        size += len(values.get("label", "").encode())
        if size + sum(prompt.size for prompt in self.prompts.values()) > 32 * 1024 * 1024:
            raise ServiceError("org.freedesktop.DBus.Error.LimitsExceeded", "Pending Secret Service prompts exceed the data limit.")
        prompt = SecretPrompt(self, peer, kind, values)
        prompt.size = size
        self.prompts[prompt.path] = prompt
        self._register(prompt.path, "prompt", prompt)
        return prompt

    def _session_close(self, session, invocation):
        self._remove(session.path)
        self.sessions.pop(session.path, None)
        for prompt in list(self.prompts.values()):
            if prompt.values.get("wire_session") is session:
                prompt.complete(True)
        def cleanup():
            try:
                self.cipher.call("close", session.peer, session.identifier, session.identity)
            except VaultError:
                pass
        self.executor.submit(cleanup)
        invocation.return_value(None)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.cipher.close()
        if self.subscription:
            self.connection.signal_unsubscribe(self.subscription)
        if self.closed_signal:
            self.connection.disconnect(self.closed_signal)
            self.closed_signal = 0
        if self.timer:
            GLib.source_remove(self.timer)
        if self.prompt_check:
            GLib.source_remove(self.prompt_check)
            self.prompt_check = 0
        for prompt in list(self.prompts.values()):
            prompt.complete(True)
        for call in list(self.calls):
            if call.live:
                call.live = False
                call.invocation.return_dbus_error("org.freedesktop.DBus.Error.Disconnected", "Keyslot Secret Service stopped.")
        self.calls.clear()
        self.property_changes.clear()
        for path in list(self.objects):
            self._remove(path)
        self.collections.clear()
        self.aliases.clear()
        self.sessions.clear()
        if self.owner:
            try:
                self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ReleaseName",
                    GLib.Variant("(s)", (NAME,)), None, Gio.DBusCallFlags.NONE, 3000, None)
            except GLib.Error:
                pass
            self.owner = False
        self.executor.shutdown(wait=False, cancel_futures=True)
