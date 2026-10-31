"""Real GTK consent → upstream proxy → encrypted transport → native disposable vault."""
import base64
import os
from pathlib import Path
import queue
import struct
import subprocess
import sys
import tempfile
import threading
import traceback

ROOT = Path(__file__).resolve().parents[1]
if "--private-bus" not in sys.argv:
    raise SystemExit(subprocess.run(["dbus-run-session", "--config-file=" + str(ROOT / "tools/test-session.conf"),
        "--", sys.executable, str(Path(__file__).resolve()), "--private-bus"]).returncode)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
temporary = tempfile.TemporaryDirectory(prefix="ksbp-", dir="/tmp")
directory = Path(temporary.name)
(directory / "runtime").mkdir(mode=0o700)
os.environ["XDG_RUNTIME_DIR"] = str(directory / "runtime")
os.environ["XDG_CONFIG_HOME"] = str(directory / "config")

from keyslot.app import Keyslot
from keyslot import preferences
from keyslot.browser_hosts import NativeHosts
from test_browser_transport import Crypto, b64, encoded, read_bytes
from test_passkeys import creation, assertion, decode
from gi.repository import Adw, Gdk, GLib, Gtk

Gtk.init_check()
assert Gdk.Display.get_default() is not None, "A display is required"
app = Keyslot()
failures = queue.Queue()
state = {"phase": "starting", "replacement_cancelled": False, "replacement_approved": False,
         "setup_cancelled": False, "setup_approved": False, "answered_alerts": set(), "answered_access": set(),
         "notifications": []}
pair_key = b64(bytes(range(32)))
old_key = b64(bytes(reversed(range(32))))
password = "public encrypted browser fixture"
prompt_shown, late_done, unlock_done, activity_ready = threading.Event(), threading.Event(), threading.Event(), threading.Event()
settings_done = threading.Event()
proxy = None
bridge = None
worker = None
old_registration = b'{"public-fixture":"previous browser registration"}\n'
activity_calls = []
original_touch = app.touch


def record_activity(*args):
    activity_calls.append(([frame.name for frame in traceback.extract_stack(limit=6)], [type(arg).__name__ for arg in args]))
    original_touch(*args)


app.touch = record_activity


def widgets(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def click(dialog, label):
    button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == label)
    assert button.get_sensitive()
    button.emit("clicked")


def guard(callback):
    def run(*args):
        try:
            return callback(*args)
        except Exception as exc:
            failures.put(exc)
            app.quit()
            return False
    return run


@guard
def start():
    session = app.active_session
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.path, "public GTK browser master")
    session.vault.save_entry(session.vault.snapshot.root, "Website login", "alice", "https://example.org", "", password)
    login = next(e for e in session.vault.snapshot.entries if e.title == "Website login")
    session.vault.set_totp(login, "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture")
    session.vault.save_entry(session.vault.snapshot.root, "Cancelled login", "bob", "https://cancel.example.net", "", "public cancelled fixture")
    session.vault.save_entry(session.vault.snapshot.root, "Permanent candidate", "bob", "https://remove.example.net", "", "public removable fixture")
    session.copy = lambda *_: (_ for _ in ()).throw(AssertionError("Browser generation must not copy to the clipboard"))
    session.vault.browser_associate("Fixture browser", old_key)
    session.window.show_vault(session.vault.snapshot)
    app._native_hosts = NativeHosts(os.environ["KEYSLOT_BROWSER_PROXY"],
                                   directory / "home", directory / "config", directory / "data")
    registration = app.native_hosts().paths["chromium"]
    registration.parent.mkdir(parents=True)
    registration.write_bytes(old_registration)
    preferences.show(session)
    preference = session.dialogs[-1]
    enabled = next(w for w in widgets(preference) if isinstance(w, Adw.SwitchRow) and w.get_title() == "Browser Integration")
    enabled.set_active(True)
    assert app.startup.browser and app.browser is not None
    click(preference, "Configure…")
    state["phase"] = "setup"
    global bridge
    bridge = app.browser.pipe
    GLib.timeout_add(20, drive)
    GLib.timeout_add(20, launch)
    return False


@guard
def launch():
    if state["phase"] != "client-ready" or app.active_session.dialogs:
        return True
    if not app.browser.ready:
        assert not app.browser.pipe.closed, "Browser transport failed before readiness"
        return True
    global worker
    worker = threading.Thread(target=client, name="browser-fixture", daemon=True)
    worker.start()
    return False


@guard
def drive():
    session = app.active_session
    phase = state["phase"]
    if phase == "finished":
        assert not session.vault.unlocked
        assert not session.dialogs
        app.native_hosts().disable("chromium")
        assert app.native_hosts().paths["chromium"].read_bytes() == old_registration
        app.set_browser(False, persist=True)
        assert not app.startup.browser
        app.quit()
        return False
    dialogs = list(session.dialogs)
    for dialog in reversed(dialogs):
        if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() == "Replace Existing Passkey?":
            if dialog in state["answered_alerts"]:
                return True
            state["answered_alerts"].add(dialog)
            if not state.get("passkey_replace_cancelled"):
                state["passkey_replace_cancelled"] = True
                click(dialog, "Cancel")
            else:
                click(dialog, "Replace Passkey")
            return True
        if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() in {"Delete Entry Permanently?", "Move Entry to Recycle Bin?"}:
            if dialog in state["answered_alerts"]:
                return True
            state["answered_alerts"].add(dialog)
            if phase == "delete-cancel":
                click(dialog, "Cancel")
            elif phase == "delete-recycle":
                click(dialog, "Move to Recycle Bin")
            elif phase == "delete-permanent":
                click(dialog, "Delete Permanently")
            else:
                raise AssertionError("Unexpected browser deletion prompt")
            return True
        if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() == "Use Keyslot for Chromium?":
            if dialog in state["answered_alerts"]:
                return True
            state["answered_alerts"].add(dialog)
            if not state["setup_cancelled"]:
                click(dialog, "Cancel")
                assert app.native_hosts().paths["chromium"].read_bytes() == old_registration
                state["setup_cancelled"] = True
            else:
                click(dialog, "Use Keyslot")
                state["setup_approved"] = True
            return True
        if isinstance(dialog, Adw.AlertDialog) and dialog.get_heading() == "Replace Browser Connection?":
            if dialog in state["answered_alerts"]:
                return True
            state["answered_alerts"].add(dialog)
            if not state["replacement_cancelled"]:
                click(dialog, "Cancel")
                assert session.vault.browser_authenticate("Fixture browser", old_key)["authenticated"]
                state["replacement_cancelled"] = True
            else:
                state["replacement_approved"] = True
                click(dialog, "Replace Connection")
            return True
        if dialog.get_title() == "Connect Browser":
            name = next(w for w in widgets(dialog) if isinstance(w, Adw.EntryRow) and w.get_title() == "Connection Name")
            name.set_text("Fixture browser")
            button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Connect Browser")
            if button.get_sensitive():
                button.emit("clicked")
            return True
        if dialog.get_title() == "Browser Setup":
            row = next(w for w in widgets(dialog) if isinstance(w, Adw.SwitchRow) and w.get_title() == "Chromium")
            if state["setup_approved"]:
                assert app.native_hosts().status("chromium")["enabled"]
                dialog.force_close()
                state["phase"] = "client-ready"
            else:
                if row.get_sensitive():
                    row.set_active(True)
            return True
        if dialog.get_title() == "Browser Access":
            assert not any(password in w.get_label() for w in widgets(dialog) if isinstance(w, Gtk.Label))
            if phase == "deny":
                if phase not in state["answered_access"]:
                    state["answered_access"].add(phase)
                    click(dialog, "Deny All")
            elif phase == "grant":
                if phase not in state["answered_access"]:
                    state["answered_access"].add(phase)
                    remember = next(w for w in widgets(dialog) if isinstance(w, Adw.SwitchRow))
                    remember.set_active(True)
                    click(dialog, "Allow Selected")
            elif phase == "cancel":
                state["cancelled_dialog"] = dialog
                state["late_button"] = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Allow Selected")
                prompt_shown.set()
            elif phase == "late":
                return True
            else:
                raise AssertionError("A browser prompt appeared without a pending consent request")
            return True
        if dialog.get_title() in {"Save Login", "Update Login"}:
            assert not any("public browser saved password" in w.get_label() for w in widgets(dialog) if isinstance(w, Gtk.Label))
            if phase in state["answered_access"]:
                return True
            state["answered_access"].add(phase)
            if phase == "save-cancel":
                click(dialog, "Cancel")
            elif phase == "save-create":
                group = next(w for w in widgets(dialog) if isinstance(w, Adw.ComboRow))
                group.set_selected(1)  # Choose the existing root instead of the default browser group.
                click(dialog, "Save Login")
            elif phase == "save-update":
                click(dialog, "Update Login")
            else:
                raise AssertionError("A browser save prompt appeared without a matching request")
            return True
        if dialog.get_title() == "Create Group":
            if phase in state["answered_access"]:
                return True
            state["answered_access"].add(phase)
            if phase == "group-cancel":
                click(dialog, "Cancel")
            elif phase == "group-create":
                click(dialog, "Create")
            else:
                raise AssertionError("A group creation prompt appeared without a matching request")
            return True
        if dialog.get_title() == "Password Generator":
            output = next(w for w in widgets(dialog) if isinstance(w, Adw.PasswordEntryRow))
            if not output.get_text():
                return True
            if phase == "generate-cancel":
                dialog.force_close()
            elif phase == "generate-apply":
                if not state.get("generator_configured"):
                    state["generator_configured"] = True
                    for row in widgets(dialog):
                        if isinstance(row, Adw.SwitchRow) and row.get_title() in {"Lowercase (a–z)", "Uppercase (A–Z)", "Symbols (!@#$…)"}:
                            row.set_active(False)
                    click(dialog, "Generate")
                elif phase not in state["answered_access"]:
                    assert output.get_text().isascii() and output.get_text().isdigit()
                    state["answered_access"].add(phase)
                    click(dialog, "Use Password")
            else:
                raise AssertionError("Unexpected browser generator")
            return True
        if dialog.get_title() in {"Create Passkey", "Sign In with Passkey"}:
            if phase in state["answered_access"]:
                return True
            if phase in {"passkey-register-cancel", "passkey-signin-cancel"}:
                state["answered_access"].add(phase)
                dialog.force_close()
            elif phase == "passkey-register":
                state["answered_access"].add(phase)
                click(dialog, "Create")
            elif phase == "passkey-replace":
                targets = next(w for w in widgets(dialog) if isinstance(w, Adw.ComboRow) and w.get_title() == "Save To")
                entries = [entry for entry in session.vault.snapshot.entries if not entry.recycled]
                index = next(i for i, entry in enumerate(entries) if entry.passkey)
                targets.set_selected(index + 1)
                button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == "Create")
                if button.get_sensitive():
                    button.emit("clicked")
            elif phase == "passkey-signin":
                state["answered_access"].add(phase)
                click(dialog, "Sign In")
            else:
                raise AssertionError("Unexpected passkey consent dialog")
            return True
    if phase == "late" and not late_done.is_set():
        if state["cancelled_dialog"] in session.dialogs:
            return True
        state["late_button"].emit("clicked")
        late_done.set()
    return True


@guard
def unlock_for_browser():
    session = app.active_session
    session.run_job(lambda: session.vault.unlock(session.path, "public GTK browser master"),
                    lambda snapshot: (session.window.show_vault(snapshot), unlock_done.set()))
    return False


@guard
def set_recycle_bin():
    session = app.active_session
    session.run_job(lambda: session.vault.save_settings(recycle_bin=state["recycle_bin"]),
                    lambda snapshot: (session.window.show_vault(snapshot), settings_done.set()))
    return False


@guard
def settled_activity():
    state["activity"] = app.last_activity
    state["activity_count"] = len(activity_calls)
    activity_ready.set()
    return False


def client():
    global proxy
    try:
        import json
        registration = json.loads(app.native_hosts().paths["chromium"].read_bytes())
        proxy = subprocess.Popen([registration["path"]], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        crypto = Crypto()

        def send(message):
            data = encoded(message)
            proxy.stdin.write(struct.pack("<I", len(data)) + data)
            proxy.stdin.flush()

        def receive():
            import json
            while True:
                size = struct.unpack("<I", read_bytes(proxy.stdout, 4, timeout=10))[0]
                assert size <= 1024 * 1024
                value = json.loads(read_bytes(proxy.stdout, size, timeout=10))
                if value.get("action") in {"database-locked", "database-unlocked"} and "message" not in value:
                    assert set(value) == {"action"}, "A public notification exposed unexpected fields"
                    state["notifications"].append(value["action"])
                else:
                    return value

        def handshake():
            send({"action": "change-public-keys", "clientID": "GTK-fixture", "nonce": b64(os.urandom(24)), "publicKey": b64(crypto.public)})
            response = receive()
            crypto.server = base64.b64decode(response["publicKey"], validate=True)

        def request(action, wait=True, expected_success="true", **fields):
            nonce = os.urandom(24)
            send({"action": action, "clientID": "GTK-fixture", "nonce": b64(nonce),
                  "message": crypto.encrypt({"action": action, **fields}, nonce)})
            if not wait:
                return None
            response = receive()
            return response if "errorCode" in response else crypto.decrypt(response, success=expected_success)

        keys = [{"id": "Fixture browser", "key": pair_key}]
        handshake()
        info = request("get-databasehash")
        assert len(info["hash"]) == 64
        state["phase"] = "pair"
        paired = request("associate", key=b64(crypto.public), idKey=pair_key)
        assert paired["id"] == "Fixture browser" and paired["hash"] == info["hash"]
        assert state["replacement_cancelled"] and state["replacement_approved"]
        assert request("test-associate", id="Fixture browser", key=pair_key)["id"] == "Fixture browser"
        state["phase"] = "deny"
        denied = request("get-logins", url="https://example.org/login", keys=keys, approved=True, remember=True)
        assert denied["entries"] == [] and denied["count"] == 0
        state["phase"] = "grant"
        granted = request("get-logins", url="https://example.org/login", keys=keys)
        assert granted["count"] == 1 and granted["entries"][0]["password"] == password
        # Let GTK finish the user-confirmed dialog transition before measuring background polling.
        GLib.timeout_add(150, settled_activity)
        assert activity_ready.wait(3)
        activity, activity_count = state["activity"], state["activity_count"]
        state["phase"] = "known"
        assert request("get-logins", url="https://example.org/login", keys=keys)["entries"][0]["login"] == "alice"
        uuid = granted["entries"][0]["uuid"]
        code = request("get-totp", uuid=uuid)["totp"]
        assert len(code) == 6 and code.isdigit()
        assert request("get-totp", uuid="invalid")["errorCode"] == "18"
        assert request("get-totp", uuid="1" * 32)["totp"] == ""
        root_group = request("get-database-groups")["groups"]["groups"][0]
        assert root_group["uuid"] == app.active_session.vault.snapshot.root.replace("-", "")
        assert app.last_activity == activity, "Browser polling extended inactivity unlock: " + repr(activity_calls[activity_count:])
        state["phase"] = "generate-cancel"
        assert request("generate-password", password="remote ignored value")["errorCode"] == "6"
        assert app.last_activity == activity, "Opening a browser generator extended inactivity unlock"
        state["phase"] = "generate-apply"
        generated = request("generate-password")["password"]
        assert len(generated) == 24 and generated.isascii() and generated.isdigit()
        passkey_fields = {"publicKey": creation(), "origin": "https://login.example.org", "keys": keys,
                          "groupName": "WebAuthn/Passkeys"}
        state["phase"] = "passkey-register-cancel"
        before = app.active_session.path.read_bytes()
        assert request("passkeys-register", approved=True, **passkey_fields)["response"]["errorCode"] == 22
        assert app.active_session.path.read_bytes() == before
        state["phase"] = "passkey-register"
        registered = request("passkeys-register", **passkey_fields)["response"]
        assert registered["type"] == "public-key" and "PRIVATE KEY" not in repr(registered)
        assert json.loads(decode(registered["response"]["clientDataJSON"]))["origin"] == passkey_fields["origin"]
        assert any("WebAuthn/Passkeys" in entry.group_path for entry in app.active_session.vault.snapshot.entries)
        state["phase"] = "passkey-replace"
        replaced = request("passkeys-register", **passkey_fields)["response"]
        assert replaced["id"] != registered["id"] and state["passkey_replace_cancelled"]
        state["phase"] = "passkey-signin-cancel"
        get_fields = {"publicKey": assertion(replaced["id"]), "origin": passkey_fields["origin"], "keys": keys}
        before = app.active_session.path.read_bytes()
        assert request("passkeys-get", **get_fields)["response"]["errorCode"] == 22
        assert app.active_session.path.read_bytes() == before
        state["phase"] = "passkey-signin"
        signed = request("passkeys-get", **get_fields)["response"]
        assert signed["id"] == replaced["id"] and signed["response"]["signature"]
        assert json.loads(decode(signed["response"]["clientDataJSON"]))["challenge"] == get_fields["publicKey"]["challenge"]
        assert app.active_session.path.read_bytes() == before
        assert request("passkeys-get", publicKey=assertion(), origin="http://example.org")["errorCode"] == "25"
        state["phase"] = "group-cancel"
        before = app.active_session.path.read_bytes()
        assert request("create-new-group", groupName="Web/Accounts", approved=True)["errorCode"] == "17"
        assert app.active_session.path.read_bytes() == before
        state["phase"] = "group-create"
        group = request("create-new-group", groupName="Web/Accounts")
        assert group["name"] == "Accounts" and len(group["uuid"]) == 32
        tree = request("get-database-groups")["groups"]["groups"][0]
        web = next(g for g in tree["children"] if g["name"] == "Web")
        assert web["children"][0]["uuid"] == group["uuid"]
        state["phase"] = "known"
        before = app.active_session.path.read_bytes()
        assert request("create-new-group", groupName="Web/Accounts")["uuid"] == group["uuid"]
        assert app.active_session.path.read_bytes() == before
        save_fields = {"id": "Fixture browser", "url": "https://saved.example.net/login", "login": "alice",
                       "password": "public browser saved password"}
        # Rejected before any GTK save prompt, including already authenticated clients.
        before = app.active_session.path.read_bytes()
        for field in ("login", "password"):
            for expression in ("{REF:P@T:Private}", "{T-CONV:/{PASSWORD}/BASE64/}", "{{{{{USERNAME}}}}}"):
                fields = dict(save_fields)
                fields[field] = expression
                assert request("set-login", **fields)["errorCode"] == "34"
                assert app.active_session.path.read_bytes() == before
        state["phase"] = "save-cancel"
        before = app.active_session.path.read_bytes()
        assert request("set-login", approved=True, **save_fields)["error"] == "error"
        assert app.active_session.path.read_bytes() == before
        state["phase"] = "save-create"
        created = request("set-login", **save_fields)
        assert created["error"] == "success" and created["count"] is None and created["entries"] is None
        snapshot = app.active_session.vault.snapshot
        saved = next(e for e in snapshot.entries if e.url == save_fields["url"])
        assert saved.group == snapshot.root and saved.history_count == 0
        state["phase"] = "save-update"
        save_fields.update(uuid=saved.uuid.replace("-", ""), login="bob", password="public browser updated password")
        assert request("set-login", **save_fields)["error"] == "success"
        updated = next(e for e in app.active_session.vault.snapshot.entries if e.uuid == saved.uuid)
        assert updated.username == "bob" and updated.history_count == 1 and updated.url == saved.url
        state["phase"] = "known"
        before = app.active_session.path.read_bytes()
        assert request("set-login", **save_fields)["error"] == "error"
        assert app.active_session.path.read_bytes() == before
        state["phase"] = "delete-cancel"
        assert request("delete-entry", uuid=save_fields["uuid"], approved=True, expected_success="false")["success"] == "false"
        assert app.active_session.path.read_bytes() == before
        state["phase"] = "delete-recycle"
        assert request("delete-entry", uuid=save_fields["uuid"])["success"] == "true"
        assert next(e for e in app.active_session.vault.snapshot.entries if e.uuid == saved.uuid).recycled
        assert request("delete-entry", uuid="1" * 32, expected_success="false")["success"] == "false"
        state["recycle_bin"] = False
        GLib.idle_add(set_recycle_bin)
        assert settings_done.wait(3)
        state["phase"] = "delete-permanent"
        candidate = next(e for e in app.active_session.vault.snapshot.entries if e.title == "Permanent candidate")
        assert request("delete-entry", uuid=candidate.uuid.replace("-", ""))["success"] == "true"
        assert not any(e.uuid == candidate.uuid for e in app.active_session.vault.snapshot.entries)
        settings_done.clear()
        state["recycle_bin"] = True
        GLib.idle_add(set_recycle_bin)
        assert settings_done.wait(3)
        state["phase"] = "cancel"
        request("get-logins", wait=False, url="https://cancel.example.net", keys=keys)
        assert prompt_shown.wait(3), "Cancellation test never reached GTK consent"
        handshake()  # Same client public key, new native generation; invalidates old consent/authentication.
        state["phase"] = "late"
        assert late_done.wait(3), "Cancelled consent did not close before the late callback"
        assert request("get-logins", url="https://example.org/login", keys=keys)["errorCode"] == "8"
        assert request("passkeys-get", **get_fields)["errorCode"] == "8"
        assert request("test-associate", id="Fixture browser", key=pair_key)["id"] == "Fixture browser"
        assert request("lock-database")["success"] == "true"
        assert request("get-databasehash")["errorCode"] == "1"
        assert request("get-totp", uuid=uuid)["errorCode"] == "1"
        assert request("get-database-groups")["errorCode"] == "1"
        assert state["notifications"] == ["database-locked"]
        GLib.idle_add(unlock_for_browser)
        assert unlock_done.wait(3), "The fixture never completed manual unlock"
        assert request("get-databasehash")["hash"] == info["hash"]
        assert state["notifications"] == ["database-locked", "database-unlocked"]
        assert request("get-logins", url="https://example.org/login", keys=keys)["errorCode"] == "8"
        assert request("test-associate", id="Fixture browser", key=pair_key)["id"] == "Fixture browser"
        assert request("lock-database")["success"] == "true"
        assert request("get-database-groups")["errorCode"] == "1"
        assert state["notifications"] == ["database-locked", "database-unlocked", "database-locked"]
        state["phase"] = "finished"
    except Exception as exc:
        failures.put(exc)
        GLib.idle_add(app.quit)
    finally:
        if proxy:
            proxy.stdin.close()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()
            proxy.stdout.close()


GLib.timeout_add(200, start)
GLib.timeout_add_seconds(40, lambda: (failures.put(AssertionError("Encrypted browser GTK smoke timed out")), app.quit(), False)[-1])
result = app.run(["keyslot-encrypted-browser-smoke"])
if worker:
    worker.join(timeout=4)
if bridge:
    assert bridge.closed and bridge.process.poll() is not None
endpoint = directory / "runtime/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer"
assert not endpoint.exists(), "Graceful private-pipe shutdown must remove only its own socket"
temporary.cleanup()
if not failures.empty():
    raise failures.get()
assert worker is not None and bridge is not None and state["phase"] == "finished" and late_done.is_set(), "Browser workflow did not complete"
assert result == 0
print("Real GTK browser workflows, encrypted locking and public lock/unlock notifications passed through the upstream proxy")
