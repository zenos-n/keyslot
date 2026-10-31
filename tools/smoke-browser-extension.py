"""Host acceptance: unmodified KeePassXC-Browser in an owned sandboxed Chromium profile."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if "--private-bus" not in sys.argv:
    raise SystemExit(subprocess.run(["dbus-run-session", "--config-file=" + str(ROOT / "tools/test-session.conf"),
        "--", sys.executable, str(Path(__file__).resolve()), "--private-bus", *sys.argv[1:]]).returncode)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--private-bus", action="store_true")
parser.add_argument("--browser", required=True)
parser.add_argument("--extension-zip", required=True)
args = parser.parse_args()
sys.path.insert(0, str(ROOT))
from browser_pipe import Browser

temporary = tempfile.TemporaryDirectory(prefix="ks-extension-", dir="/tmp")
directory = Path(temporary.name)
for name in ("runtime", "config", "data", "state", "cache", "home"):
    (directory / name).mkdir(mode=0o700)
for name, child in {"XDG_RUNTIME_DIR": "runtime", "XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data",
                    "XDG_STATE_HOME": "state", "XDG_CACHE_HOME": "cache", "HOME": "home"}.items():
    os.environ[name] = str(directory / child)

from keyslot.app import Keyslot
from gi.repository import Adw, Gdk, GLib, Gtk


class Site(BaseHTTPRequestHandler):
    def do_GET(self):
        page = b'<!doctype html><title>Public Keyslot fixture</title><form><label>User<input id="user" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *_):
        pass


openssl = os.environ.get("KEYSLOT_TEST_OPENSSL", "openssl")
subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj",
    "/CN=login.example.org", "-addext", "subjectAltName=DNS:login.example.org", "-keyout", str(directory / "tls.key"),
    "-out", str(directory / "tls.crt")], check=True, capture_output=True)
public = subprocess.run([openssl, "x509", "-in", str(directory / "tls.crt"), "-pubkey", "-noout"],
    check=True, capture_output=True).stdout
der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "DER"], input=public, check=True, capture_output=True).stdout
spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(directory / "tls.crt", directory / "tls.key")
server.socket = tls.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
origin = "https://login.example.org:" + str(server.server_port)
extension = directory / "extension"
with zipfile.ZipFile(args.extension_zip) as archive:
    archive.extractall(extension)

Gtk.init_check()
assert Gdk.Display.get_default() is not None, "Run this host check under Xvfb"
app = Keyslot()
failures = queue.Queue()
state = {"answered": set(), "seen": set(), "done": False}
worker = browser = None
password = "public browser fixture password"


def widgets(widget):
    yield widget
    child = widget.get_first_child()
    while child:
        yield from widgets(child)
        child = child.get_next_sibling()


def click(dialog, label):
    button = next(w for w in widgets(dialog) if isinstance(w, Gtk.Button) and w.get_label() == label)
    if not button.get_sensitive():
        return False
    button.emit("clicked")
    state["answered"].add(dialog)
    return True


def guard(callback):
    def run(*values):
        try:
            return callback(*values)
        except Exception as exc:
            failures.put(exc)
            app.quit()
            return False
    return run


@guard
def drive():
    if state["done"] or not failures.empty():
        app.quit()
        return False
    for dialog in reversed(list(app.active_session.dialogs)):
        if dialog in state["answered"]:
            continue
        title = dialog.get_title()
        state["seen"].add(title)
        if title == "Connect Browser":
            next(w for w in widgets(dialog) if isinstance(w, Adw.EntryRow)).set_text("Real browser fixture")
            click(dialog, "Connect Browser")
        elif title == "Browser Access":
            next(w for w in widgets(dialog) if isinstance(w, Adw.SwitchRow)).set_active(True)
            click(dialog, "Allow Selected")
        elif title in {"Save Login", "Update Login"}:
            click(dialog, title)
        elif title == "Create Group":
            click(dialog, "Create")
        elif title == "Password Generator":
            if next(w for w in widgets(dialog) if isinstance(w, Adw.PasswordEntryRow)).get_text():
                click(dialog, "Use Password")
        elif title == "Create Passkey":
            click(dialog, "Create")
        elif title == "Sign In with Passkey":
            click(dialog, "Sign In")
        else:
            raise AssertionError("Unexpected fixture dialog: " + title)
    return True


@guard
def start():
    session = app.active_session
    session.requested_path = directory / "fixture.kdbx"
    session.vault.create(session.path, "public browser master")
    session.vault.save_entry(session.vault.snapshot.root, "Fixture login", "alice", origin, "", password)
    entry = session.vault.snapshot.entries[0]
    session.vault.set_totp(entry, "otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP&issuer=Fixture")
    session.window.show_vault(session.vault.snapshot)
    app.set_browser(True, persist=False)
    finish = app.browser.requests._finish
    def observed_finish(request, result=None, error=None):
        if error is not None:
            print("Fixture browser rejection:", request.event.get("action"), error,
                  "queue_busy=", request.session.jobs.busy, "interactive=", request.session.jobs.interactive,
                  "dialogs=", [dialog.get_title() for dialog in request.session.dialogs], file=sys.stderr)
        return finish(request, result, error)
    app.browser.requests._finish = observed_finish
    GLib.timeout_add(20, drive)
    GLib.timeout_add(20, launch)
    return False


@guard
def launch():
    if not app.browser.ready:
        assert not app.browser.pipe.closed
        return True
    global worker
    worker = threading.Thread(target=client, name="real-extension-fixture", daemon=True)
    worker.start()
    return False


def client():
    global browser
    try:
        browser = Browser(args.browser, directory / "profile", directory / "browser.log", [
            "--no-proxy-server", "--host-resolver-rules=MAP login.example.org 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost",
            "--ignore-certificate-errors-spki-list=" + spki])
        version = browser.call("Browser.getVersion")["product"]
        # Chromium hashes the absolute unpacked path into an extension identity.
        identifier = "".join(chr(ord("a") + int(digit, 16)) for digit in
                             hashlib.sha256(str(extension).encode()).hexdigest()[:32])
        # Only this disposable manifest trusts the random unpacked extension identity.
        manifest = directory / "config/BraveSoftware/Brave-Browser/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"name": "org.keepassxc.keepassxc_browser", "description": "Public Keyslot fixture",
            "path": os.environ["KEYSLOT_BROWSER_PROXY"], "type": "stdio", "allowed_origins": ["chrome-extension://" + identifier + "/"]}))
        assert browser.call("Extensions.loadUnpacked", {"path": str(extension)})["id"] == identifier
        deadline = time.monotonic() + 10
        while True:
            targets = browser.call("Target.getTargets")["targetInfos"]
            target = next((t for t in targets if t["type"] == "service_worker" and identifier in t["url"]), None)
            if target:
                break
            assert time.monotonic() < deadline, "Extension worker did not start"
            time.sleep(.05)
        extension_session = browser.call("Target.attachToTarget", {"targetId": target["targetId"], "flatten": True})["sessionId"]
        browser.call("Runtime.enable", session=extension_session)
        evaluate = lambda expression: browser.evaluate(extension_session, expression)
        deadline = time.monotonic() + 10
        while not evaluate("typeof keepass !== 'undefined' && keepass.isKeePassXCAvailable"):
            assert time.monotonic() < deadline, "Real extension cannot discover Keyslot"
            time.sleep(.05)
        assert evaluate("(async()=>{await keepass.associate(null);return keepass.isAssociated()})()"), "Real extension pairing failed"
        evaluate("(async()=>{page.settings.passkeys=true;page.settings.passkeysFallback=false;await browser.storage.local.set({settings:page.settings})})()")
        target_id = browser.call("Target.createTarget", {"url": origin})["targetId"]
        page_session = browser.call("Target.attachToTarget", {"targetId": target_id, "flatten": True})["sessionId"]
        browser.call("Runtime.enable", session=page_session)
        deadline = time.monotonic() + 10
        while not browser.evaluate(page_session, "Boolean(document.querySelector('#user')) && Boolean(navigator.credentials?.create) && !navigator.credentials.create.toString().includes('[native code]')"):
            assert time.monotonic() < deadline, "Fixture page or extension content script did not load"
            time.sleep(.05)
        tab = evaluate("(async()=>{const t=(await browser.tabs.query({})).find(t=>t.url.startsWith(" + json.dumps(origin) + "));globalThis.fixtureTab=t;return t.id})()")
        assert tab is not None
        logins = evaluate("keepass.retrieveCredentials(fixtureTab," + json.dumps([origin, origin]) + ")")
        assert len(logins) == 1 and logins[0]["login"] == "alice" and logins[0]["password"] == password, "Real extension login decoding failed"
        totp = evaluate("keepass.getTotp(fixtureTab," + json.dumps([logins[0]["uuid"], ""]) + ")")
        assert isinstance(totp, str) and len(totp) == 6 and totp.isdigit()
        assert evaluate("browser.tabs.sendMessage(fixtureTab.id,{action:'fill_username_password'})") is not False
        deadline = time.monotonic() + 5
        while browser.evaluate(page_session, "[document.querySelector('#user').value,document.querySelector('#password').value]") != ["alice", password]:
            assert time.monotonic() < deadline, "Real extension did not fill the page"
            time.sleep(.05)
        generated = evaluate("keepass.generatePassword(fixtureTab)")
        assert isinstance(generated, str) and len(generated) >= 16, "Real extension generation failed"
        assert evaluate("(async()=>await keepass.addCredentials(fixtureTab,['bob','public saved password','https://saved.example.net'])===CreationError.CREATED)()"), "Real extension save failed"
        groups = evaluate("keepass.getDatabaseGroups(fixtureTab)")
        assert groups and "groups" in groups, "Real extension group listing failed"
        group = evaluate("keepass.createNewGroup(fixtureTab,['Real browser group'])")
        assert group.get("name") == "Real browser group" and group.get("uuid"), "Real extension group creation failed"
        print("Real extension login/fill/TOTP/generation/save/group checks passed; testing WebAuthn", flush=True)
        assert "[native code]" not in browser.evaluate(page_session, "navigator.credentials.create.toString()"), "Extension passkey interception is not enabled"
        # Exercise the page's actual WebAuthn API and the extension's content-script bridge.
        created = browser.evaluate(page_session, """(async()=>{
            const credential=await navigator.credentials.create({publicKey:{
                challenge:Uint8Array.from({length:32},(_,i)=>i),
                rp:{id:'example.org',name:'Public fixture'},
                user:{id:new TextEncoder().encode('public-user-id'),name:'alice',displayName:'Alice'},
                pubKeyCredParams:[{type:'public-key',alg:-7}],attestation:'none',
                authenticatorSelection:{residentKey:'preferred',userVerification:'required'},timeout:10000}});
            if(!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse))
                throw Error('The extension did not return a WebAuthn credential');
            return credential.toJSON();
        })()""")
        assert created["type"] == "public-key" and created["response"]["publicKeyAlgorithm"] == -7
        signed = browser.evaluate(page_session, """(async()=>{
            const id=""" + json.dumps(created["id"]) + """;
            const raw=Uint8Array.from(atob(id.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
            const credential=await navigator.credentials.get({publicKey:{rpId:'example.org',
                challenge:Uint8Array.from({length:32},(_,i)=>31-i),
                allowCredentials:[{type:'public-key',id:raw}],userVerification:'required',timeout:10000}});
            if(!(credential.response instanceof AuthenticatorAssertionResponse)) throw Error('Invalid assertion object');
            return credential.toJSON();
        })()""")
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        registered_data = json.loads(decode(created["response"]["clientDataJSON"]))
        assert registered_data["origin"] == origin and registered_data["type"] == "webauthn.create"
        assert decode(registered_data["challenge"]) == bytes(range(32))
        assert signed["id"] == created["id"]
        response = signed["response"]
        client_data = decode(response["clientDataJSON"])
        client_json = json.loads(client_data)
        assert client_json["origin"] == origin and client_json["type"] == "webauthn.get"
        assert decode(client_json["challenge"]) == bytes(reversed(range(32)))
        authenticator = decode(response["authenticatorData"])
        assert authenticator[:32] == hashlib.sha256(b"example.org").digest() and authenticator[32] & 5 == 5
        assert decode(response["userHandle"]) == b"public-user-id"
        (directory / "public.der").write_bytes(decode(created["response"]["publicKey"]))
        subprocess.run([openssl, "pkey", "-pubin", "-inform", "DER", "-in", str(directory / "public.der"),
            "-out", str(directory / "public.pem")], check=True, capture_output=True)
        message, signature = directory / "message", directory / "signature"
        message.write_bytes(authenticator + hashlib.sha256(client_data).digest())
        signature.write_bytes(decode(response["signature"]))
        verification = [openssl, "dgst", "-sha256", "-verify", str(directory / "public.pem"),
            "-signature", str(signature), str(message)]
        assert subprocess.run(verification, capture_output=True).returncode == 0, "Real WebAuthn signature failed verification"
        message.write_bytes(message.read_bytes() + b"tampered")
        assert subprocess.run(verification, capture_output=True).returncode != 0
        assert {"Connect Browser", "Browser Access", "Password Generator", "Save Login", "Create Group",
                "Create Passkey", "Sign In with Passkey"} <= state["seen"], "A required GTK consent surface was bypassed"
        state["done"] = True
        print("Real KeePassXC-Browser " + evaluate("browser.runtime.getManifest().version") + " on " + version + ": pairing, login retrieval, TOTP and DOM form filling passed", flush=True)
        print("Real extension generation, save, groups and DOM WebAuthn create/get with independent signature verification passed", flush=True)
    except Exception as exc:
        if browser:
            print("Browser diagnostic events:", json.dumps([e for e in browser.events
                if e.get("method") in {"Runtime.exceptionThrown", "Runtime.consoleAPICalled"}])[-6000:], file=sys.stderr)
        failures.put(exc)
    finally:
        if browser:
            browser.close()


GLib.timeout_add(200, start)
GLib.timeout_add_seconds(90, lambda: (failures.put(AssertionError("Real browser acceptance timed out")), app.quit(), False)[-1])
result = app.run(["keyslot-real-browser-smoke"])
if worker:
    worker.join(timeout=25)
server.shutdown()
server.server_close()
if not failures.empty():
    print((directory / "browser.log").read_text()[-2500:] if (directory / "browser.log").exists() else "Browser not started", file=sys.stderr)
    temporary.cleanup()
    raise failures.get()
assert worker is not None and not worker.is_alive(), "Owned browser worker did not stop"
assert state["done"] and result == 0, "Real browser acceptance did not complete"
temporary.cleanup()
