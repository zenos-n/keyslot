"""Real libsecret and GTK consent on a private bus, with owned encrypted vaults only."""
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
import json
import os
from pathlib import Path
from unittest.mock import patch
import selectors
import subprocess
import sys
import tempfile
import threading
import time

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))
temporary = tempfile.TemporaryDirectory(prefix="keyslot-secret-ui-")
directory = Path(temporary.name)
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk
from keyslot.app import Keyslot
from keyslot.application import VaultSession
from keyslot.backend import VaultError
from keyslot.startup import LoginKeyring
from keyslot.secret_interfaces import NAME, PREFIX, PROPERTIES, ROOT
from keyslot import secret_views

pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="secret-fixture")
clients, raw_connections = [], []
responses = deque()
answered = set()
failure = []
completions = []
debug = deque(maxlen=80)
app = Keyslot()


def widgets(root):
    yield root
    child = root.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "Secret Service fixture timed out"
        yield


def read(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(15), "libsecret client timed out"
        line = process.stdout.readline()
        assert line, "libsecret client exited: " + process.stderr.read()
        return json.loads(line)


def client():
    process = subprocess.Popen([sys.executable, str(ROOT_DIR / "tools/secret-client.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    clients.append(process)
    return process, pool.submit(read, process)


def send(process, operation, **values):
    process.stdin.write(json.dumps(dict(op=operation, **values)) + "\n")
    process.stdin.flush()
    return pool.submit(read, process)


def connection():
    value = Gio.DBusConnection.new_for_address_sync(os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
    raw_connections.append(value)
    return value


def call(connection, path, interface, method, parameters=None):
    future = Future()
    def completed(connection, result):
        try:
            future.set_result(connection.call_finish(result).unpack())
        except Exception as exc:
            future.set_exception(exc)
    connection.call(NAME, path, interface, method, parameters, None, Gio.DBusCallFlags.NONE, 20000, None, completed)
    return future


def result(future):
    yield from wait(future.done)
    return future.result()


def prompt(connection, path):
    future = Future()
    def finished(_c, _sender, _path, _interface, _signal, values):
        if not future.done():
            future.set_result(values.unpack())
    subscription = connection.signal_subscribe(NAME, PREFIX + "Prompt", "Completed", path, None,
        Gio.DBusSignalFlags.NONE, finished)
    started = call(connection, path, PREFIX + "Prompt", "Prompt", GLib.Variant("(s)", ("",)))
    yield from result(started)
    try:
        return (yield from result(future))
    finally:
        connection.signal_unsubscribe(subscription)


def error_name(future):
    try:
        future.result()
    except GLib.Error as exc:
        return Gio.DBusError.get_remote_error(exc)
    raise AssertionError("Expected a D-Bus error")


def scenario():
    yield from wait(lambda: app.active_session is not None)
    session = app.active_session
    app.set_background(False)
    path = directory / "primary.kdbx"
    session.requested_path = path
    session.vault.create(path, "public fixture master")
    session.vault.add_group(session.vault.snapshot.root, "Exposed")
    group = next(group.uuid for group in session.vault.snapshot.groups if group.name == "Exposed")
    session.vault.save_entry(session.vault.snapshot.root, "Hidden", "", "", "", "hidden fixture secret")
    session.window.show_vault(session.vault.snapshot)
    secret_views.settings(session)
    yield from wait(lambda: session.dialogs and not session.busy)
    dialog = session.dialogs[-1]
    row = next(widget for widget in widgets(dialog) if isinstance(widget, Adw.ComboRow))
    groups = [group for group in session.vault.snapshot.groups if not group.recycled]
    row.set_selected(next(index + 1 for index, value in enumerate(groups) if value.uuid == group))
    next(widget for widget in widgets(dialog) if isinstance(widget, Gtk.Button) and widget.get_label() == "Save").emit("clicked")
    yield from wait(lambda: not session.dialogs and not session.busy)
    assert session.vault.snapshot.secret_group == group

    # An existing provider is never replaced, even when the preference is enabled.
    incumbent = connection()
    incumbent.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
        GLib.Variant("(su)", (NAME, 4)), None, Gio.DBusCallFlags.NONE, 3000, None)
    options = app.startup.secret_service | {"enabled": True, "notify": False}
    try:
        app.set_secret_service(options)
        raise AssertionError("Keyslot replaced an existing Secret Service")
    except VaultError:
        pass
    incumbent.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ReleaseName",
        GLib.Variant("(s)", (NAME,)), None, Gio.DBusCallFlags.NONE, 3000, None)
    app.set_secret_service(options)
    provider = app.secrets
    original_emit = provider._emit
    def emitted(path, interface, signal, signature, values, destination=None):
        if signal == "Completed":
            completions.append((path, values[0], values[1].get_type_string(), destination))
        elif signal == "PropertiesChanged":
            debug.append(("changed", path, list(values[1]), values[2], destination))
        return original_emit(path, interface, signal, signature, values, destination)
    provider._emit = emitted
    original_vault = provider._vault
    def traced_vault(collection, context, operation, **values):
        value = original_vault(collection, context, operation, **values)
        debug.append((operation, values.get("peer"), values.get("entry"), value.get("locked"),
                      len(value.get("secrets", [])), "TOTP" in value.get("attributes", {})))
        return value
    provider._vault = traced_vault
    original_error = provider._error
    def traced_error(invocation, error):
        debug.append(("error", invocation.get_method_name(), type(error).__name__, str(error)))
        return original_error(invocation, error)
    provider._error = traced_error
    assert provider and provider.owner
    collection = provider.collections[session]
    # The master-credential keyring adapter refuses to route back into our own service.
    own_keyring = pool.submit(lambda: LoginKeyring()._service())
    yield from wait(own_keyring.done)
    try:
        own_keyring.result()
        raise AssertionError("Login unlock recursively selected Keyslot’s provider")
    except ValueError as exc:
        assert "active password service" in str(exc)

    a, started = client()
    hello_a = yield from result(started)
    assert hello_a["algorithm"] == "dh-ietf1024-sha256-aes128-cbc-pkcs7", hello_a
    responses.append(("Create Password Item?", "allow"))
    stored = yield from result(send(a, "store"))
    assert stored == {"stored": True}, stored
    found = yield from result(send(a, "items"))
    assert len(found["unlocked"]) == 1 and not found["locked"], found
    item = found["unlocked"][0]
    assert (yield from result(send(a, "lookup")))["value"] == "public libsecret fixture"

    # A separate real libsecret process cannot inherit the creator's grants.
    b, started = client()
    hello_b = yield from result(started)
    assert hello_b["peer"] != hello_a["peer"]
    found = yield from result(send(b, "items"))
    assert found == {"unlocked": [], "locked": [item]}, found
    responses.append(("Allow Password Access?", "allow"))
    assert (yield from result(send(b, "lookup")))["value"] == "public libsecret fixture"
    responses.append(("Allow Password Access?", "deny"))
    denied = yield from result(send(b, "lookup"))
    assert denied.get("value") is None, denied
    responses.append(("Allow Password Access?", "remember"))
    assert (yield from result(send(b, "lookup")))["value"] == "public libsecret fixture"
    assert (yield from result(send(b, "lookup")))["value"] == "public libsecret fixture"
    yield from result(send(b, "quit"))
    yield from wait(lambda: hello_b["peer"] not in provider.peers)

    # Plain sessions and binary values through the actual wire interface, independently of GI's UTF-8-only Secret.Value binding.
    raw = connection()
    opened = yield from result(call(raw, ROOT, PREFIX + "Service", "OpenSession",
                                  GLib.Variant("(sv)", ("plain", GLib.Variant("s", "")))))
    wire_session = opened[1]
    payload = b"\x00\xff\x80public binary fixture"
    properties = {PREFIX + "Item.Label": GLib.Variant("s", "Public Binary Item"),
                  PREFIX + "Item.Attributes": GLib.Variant("a{ss}", {"fixture": "binary"})}
    created = yield from result(call(raw, collection.path, PREFIX + "Collection", "CreateItem",
        GLib.Variant("(a{sv}(oayays)b)", (properties, (wire_session, b"", payload, "application/octet-stream"), False))))
    responses.append(("Create Password Item?", "allow"))
    dismissed, binary_item = yield from prompt(raw, created[1])
    assert not dismissed and binary_item.startswith(collection.path + "/")
    secret = yield from result(call(raw, binary_item, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (wire_session,))))
    assert bytes(secret[0][2]) == payload and secret[0][3] == "application/octet-stream"
    metadata = yield from result(call(raw, binary_item, PROPERTIES, "GetAll", GLib.Variant("(s)", (PREFIX + "Item",))))
    assert metadata[0]["Label"] == "Public Binary Item" and "Password" not in metadata[0]["Attributes"]
    yield from result(call(raw, ROOT, PREFIX + "Service", "SetAlias", GLib.Variant("(so)", ("fixture", collection.path))))
    assert (yield from result(call(raw, ROOT, PREFIX + "Service", "ReadAlias", GLib.Variant("(s)", ("fixture",)))))[0] == collection.path
    alias_metadata = yield from result(call(raw, ROOT + "/aliases/fixture", PROPERTIES, "GetAll",
                                           GLib.Variant("(s)", (PREFIX + "Collection",))))
    assert binary_item in alias_metadata[0]["Items"]
    yield from result(call(raw, binary_item, PROPERTIES, "Set",
        GLib.Variant("(ssv)", (PREFIX + "Item", "Label", GLib.Variant("s", "Renamed Binary Item")))))
    yield from result(call(raw, binary_item, PROPERTIES, "Set",
        GLib.Variant("(ssv)", (PREFIX + "Item", "Attributes", GLib.Variant("a{ss}", {"fixture": "binary-renamed"})))))
    payload += b" updated"
    yield from result(call(raw, binary_item, PREFIX + "Item", "SetSecret",
        GLib.Variant("((oayays))", ((wire_session, b"", payload, "application/octet-stream"),))))
    secret = yield from result(call(raw, binary_item, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (wire_session,))))
    assert bytes(secret[0][2]) == payload
    metadata = yield from result(call(raw, binary_item, PROPERTIES, "GetAll", GLib.Variant("(s)", (PREFIX + "Item",))))
    assert metadata[0]["Label"] == "Renamed Binary Item" and metadata[0]["Attributes"]["fixture"] == "binary-renamed"
    outsider = connection()
    denied = call(outsider, binary_item, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (wire_session,)))
    yield from wait(denied.done)
    assert error_name(denied) == PREFIX + "Error.NoSession"

    # Closing a wire session revokes access before asynchronous native cleanup.
    extra = yield from result(call(raw, ROOT, PREFIX + "Service", "OpenSession",
        GLib.Variant("(sv)", ("plain", GLib.Variant("s", "")))))
    yield from result(call(raw, extra[1], PREFIX + "Session", "Close"))
    closed = call(raw, binary_item, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (extra[1],)))
    yield from wait(closed.done)
    assert error_name(closed) == PREFIX + "Error.NoSession"

    # A real client's metadata loading cannot consume the password half of a one-shot grant.
    session.vault.save_entry(group, "One-time Fixture", "", "", "", "public one-time fixture password")
    otp_entry = next(entry for entry in session.vault.snapshot.entries if entry.title == "One-time Fixture")
    session.vault.set_attribute(otp_entry, "fixture", "otp", False)
    otp_entry = next(entry for entry in session.vault.snapshot.entries if entry.uuid == otp_entry.uuid)
    session.vault.set_attribute(otp_entry, "xdg:schema", "com.neg_zero.keyslot.PublicFixture", False)
    otp_entry = next(entry for entry in session.vault.snapshot.entries if entry.uuid == otp_entry.uuid)
    session.vault.set_totp(otp_entry, "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture")
    session.window.show_vault(session.vault.snapshot)
    c, started = client()
    yield from result(started)
    responses.append(("Allow Password Access?", "allow"))
    loaded = yield from result(send(c, "load", fixture="otp"))
    assert len(loaded["items"]) == 1 and loaded["items"][0]["value"] == "public one-time fixture password", loaded
    otp_path = loaded["items"][0]["path"]
    yield from result(send(c, "quit"))
    opened = yield from result(call(outsider, ROOT, PREFIX + "Service", "OpenSession",
        GLib.Variant("(sv)", ("plain", GLib.Variant("s", "")))))
    unlocked = yield from result(call(outsider, ROOT, PREFIX + "Service", "Unlock", GLib.Variant("(ao)", ([otp_path],))))
    responses.append(("Allow Password Access?", "allow"))
    assert not (yield from prompt(outsider, unlocked[1]))[0]
    data = yield from result(call(outsider, otp_path, PROPERTIES, "GetAll", GLib.Variant("(s)", (PREFIX + "Item",))))
    assert len(data[0]["Attributes"]["TOTP"]) == 6 and not data[0]["Locked"]
    secret = yield from result(call(outsider, otp_path, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (opened[1],))))
    assert bytes(secret[0][2]) == b"public one-time fixture password"
    data = yield from result(call(outsider, otp_path, PROPERTIES, "GetAll", GLib.Variant("(s)", (PREFIX + "Item",))))
    assert "TOTP" not in data[0]["Attributes"] and data[0]["Locked"]

    # A policy round trip revokes existing grants even if no native request ran between toggles.
    app.set_secret_service(options | {"confirm_access": False})
    app.set_secret_service(options)
    revoked = call(raw, binary_item, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (wire_session,)))
    yield from wait(revoked.done)
    assert error_name(revoked) == PREFIX + "Error.IsLocked"
    unlocked = yield from result(call(raw, ROOT, PREFIX + "Service", "Unlock", GLib.Variant("(ao)", ([binary_item],))))
    responses.append(("Allow Password Access?", "remember"))
    assert not (yield from prompt(raw, unlocked[1]))[0]

    # Lock after native lookup but before the encrypted reply is dispatched: no stale plaintext reply may escape.
    entered, release = threading.Event(), threading.Event()
    original = provider.cipher.call
    def paused(operation, *args, **kwargs):
        if operation == "encode":
            entered.set()
            assert release.wait(8), "Late-reply fixture did not release the cipher"
        return original(operation, *args, **kwargs)
    provider.cipher.call = paused
    late = call(raw, binary_item, PREFIX + "Item", "GetSecret", GLib.Variant("(o)", (wire_session,)))
    yield from wait(entered.is_set)
    locked = yield from result(call(raw, ROOT, PREFIX + "Service", "Lock", GLib.Variant("(ao)", ([binary_item],))))
    assert locked == ([collection.path], "/"), locked
    release.set()
    yield from wait(late.done)
    provider.cipher.call = original
    assert error_name(late) == PREFIX + "Error.IsLocked"
    assert not session.vault.unlocked and not provider.collections[session].items

    # Real compatibility-mode search opens the normal GTK vault unlock UI, then asks for entry access.
    pending = send(a, "lookup")
    yield from wait(lambda: any(dialog.get_title() == "Unlock Database" for dialog in session.dialogs))
    dialog = next(dialog for dialog in session.dialogs if dialog.get_title() == "Unlock Database")
    master = next(widget for widget in widgets(dialog) if isinstance(widget, Adw.PasswordEntryRow) and widget.get_title() == "Master Password")
    master.set_text("public fixture master")
    responses.append(("Allow Password Access?", "remember"))
    next(widget for widget in widgets(dialog) if isinstance(widget, Gtk.Button) and widget.get_label() == "Unlock").emit("clicked")
    assert (yield from result(pending))["value"] == "public libsecret fixture"

    # Update and delete retain KeePass history/recycle semantics and require the real GTK confirmations.
    responses.append(("Update Password Item?", "allow"))
    assert (yield from result(send(a, "store", value="updated libsecret fixture")))["stored"]
    assert (yield from result(send(a, "lookup")))["value"] == "updated libsecret fixture"
    live = next(entry for entry in session.vault.snapshot.entries if entry.title == "Public libsecret item" and not entry.recycled)
    assert session.vault.history(live)
    responses.append(("Delete Password Item?", "allow"))
    assert (yield from result(send(a, "clear")))["cleared"]
    assert next(entry for entry in session.vault.snapshot.entries if entry.uuid == live.uuid).recycled

    # Collection creation uses real libsecret and the real GTK master-credential form.
    responses.append(("Create Password Collection?", "deny"))
    denied = yield from result(send(a, "create_collection", label="Denied Fixture"))
    assert not denied.get("collection"), denied
    assert len(app.sessions) == 1
    created_path = directory / "created-by-libsecret.kdbx"
    def owned_file(self, callback, **options):
        assert options.get("save") and options.get("kdbx"), options
        callback(str(created_path))
    with patch.object(VaultSession, "choose_file", owned_file):
        responses.append(("Create Password Collection?", "allow"))
        pending = send(a, "create_collection", label="Created libsecret vault", alias="fixture-created")
        yield from wait(lambda: any(dialog.get_title() == "New Database" for current in app.sessions for dialog in current.dialogs))
        created_session = next(current for current in app.sessions if any(dialog.get_title() == "New Database" for dialog in current.dialogs))
        dialog = next(dialog for dialog in created_session.dialogs if dialog.get_title() == "New Database")
        for widget in widgets(dialog):
            if isinstance(widget, Adw.PasswordEntryRow) and widget.get_title() in ("Master Password", "Repeat Password"):
                widget.set_text("public created fixture master")
        next(widget for widget in widgets(dialog) if isinstance(widget, Gtk.Button) and widget.get_label() == "Create Database").emit("clicked")
        new_collection = (yield from result(pending))["collection"]
    assert new_collection == provider.collections[created_session].path
    assert created_session.vault.snapshot.name == "Created libsecret vault"
    assert created_session.vault.snapshot.secret_group == created_session.vault.snapshot.root
    assert (yield from result(call(raw, ROOT, PREFIX + "Service", "ReadAlias", GLib.Variant("(s)", ("fixture-created",)))))[0] == new_collection
    responses.append(("Create Password Item?", "allow"))
    assert (yield from result(send(a, "store", collection=new_collection, fixture="secondary")))["stored"]
    assert (yield from result(send(a, "lookup", fixture="secondary")))["value"] == "public libsecret fixture"
    contents = created_path.read_bytes()
    responses.append(("Close Password Collection?", "deny"))
    denied = yield from result(send(a, "close_collection", path=new_collection))
    assert "error" not in denied, denied  # libsecret treats prompt dismissal as a completed request.
    assert created_session in app.sessions and created_session.vault.unlocked
    responses.append(("Close Password Collection?", "allow"))
    assert (yield from result(send(a, "close_collection", path=new_collection)))["closed"]
    yield from wait(lambda: created_session not in app.sessions)
    assert created_path.read_bytes() == contents and session.vault.unlocked
    assert (yield from result(call(raw, ROOT, PREFIX + "Service", "ReadAlias", GLib.Variant("(s)", ("fixture-created",)))))[0] == "/"

    # Disable releases the name and closes private sessions; existing vault data remains unlocked and intact.
    app.set_secret_service(options | {"enabled": False})
    assert provider.closed and not provider.objects and session.vault.unlocked
    assert not responses, responses
    app.quit()


steps = scenario()
def tick():
    try:
        for session in list(app.sessions):
            for dialog in list(session.dialogs):
                if isinstance(dialog, Adw.AlertDialog):
                    if dialog in answered:
                        continue
                    heading = dialog.get_heading()
                    if heading == "Could Not Complete Operation":
                        raise AssertionError(dialog.get_body())
                    if responses and heading == responses[0][0]:
                        _, response = responses.popleft()
                        label = dialog.get_response_label(response)
                        button = next(widget for widget in widgets(dialog) if isinstance(widget, Gtk.Button) and widget.get_label() == label)
                        answered.add(dialog)
                        button.emit("clicked")
        next(steps)
        return True
    except StopIteration:
        return False
    except Exception as exc:
        provider = app.secrets
        if provider:
            debug.append(("prompts", [(p.kind, p.stage, p.busy, p.finished) for p in provider.prompts.values()]))
            debug.append(("calls", [(call.peer, call.invocation.get_method_name(), call.invocation.get_object_path()) for call in provider.calls]))
        failure.append(exc)
        app.quit()
        return False


app.connect("activate", lambda *_: GLib.timeout_add(20, tick))
status = app.run(["keyslot-secret-ui"])
for process in clients:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=3)
for value in raw_connections:
    value.close_sync(None)
pool.shutdown(wait=True, cancel_futures=True)
temporary.cleanup()
diagnostics = [process.stderr.read() for process in clients]
if failure:
    print("Unanswered responses:", list(responses))
    print("Completions:", completions)
    print("Server state:", debug)
    for diagnostic in diagnostics:
        print("Client stderr:", diagnostic)
    raise failure[0]
assert not any("CRITICAL" in diagnostic or "Traceback" in diagnostic for diagnostic in diagnostics), diagnostics
if status:
    raise SystemExit(status)
print("Secret Service: encrypted libsecret items/collections, GTK consent/cancellation, TOTP, policy revocation, binary wire, metadata caches and late-reply lock: PASS")
