"""Native SSH acceptance against isolated GCR and actual OpenSSH agent forwarding."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from keyslot.core_backend import Vault
from keyslot.ssh_agent import SSHAgentManager


def wait(predicate, seconds=6):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError("The owned SSH service did not become ready")
        time.sleep(.025)


def run(arguments, *, env=None, input=None):
    return subprocess.run(arguments, env=env, input=input, capture_output=True, check=True, timeout=10)


def stop(process):
    # Every service below starts a separate process group, including its owned children.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)
    for stream in (process.stdin, process.stdout):
        if stream:
            stream.close()


def key(directory, name, kind="ed25519", password=""):
    path = directory / name
    command = ["ssh-keygen", "-q", "-t", kind, "-N", password, "-C", "Public isolated fixture", "-f", str(path)]
    if kind == "rsa":
        command += ["-b", "2048"]
    run(command)
    return path


def environment(path):
    return os.environ | {"SSH_AUTH_SOCK": str(path), "SSH_ASKPASS_REQUIRE": "force"}


def identities(path):
    result = subprocess.run(["ssh-add", "-L"], env=environment(path), capture_output=True, text=True, timeout=6)
    assert result.returncode in (0, 1), result.stderr
    return result.stdout.splitlines() if result.returncode == 0 else []


def signature(directory, path, agent):
    message = b"Public isolated SSH agent signature fixture"
    signed = run(["ssh-keygen", "-Y", "sign", "-U", "-f", str(path) + ".pub", "-n", "keyslot-platform"],
                 env=environment(agent), input=message).stdout
    signature_path, allowed = directory / "signature", directory / "allowed"
    signature_path.write_bytes(signed)
    allowed.write_text("alice " + Path(str(path) + ".pub").read_text())
    command = ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "alice", "-n", "keyslot-platform", "-s", str(signature_path)]
    run(command, input=message)
    assert subprocess.run(command, input=message + b" tampered", capture_output=True, timeout=6).returncode != 0


def exercise(directory, agent, stack, backend=None):
    assert not identities(agent), "The owned fixture agent must start empty"
    external = key(directory, "borrowed")
    run(["ssh-add", str(external)], env=environment(agent))
    manager = SSHAgentManager()
    stack.callback(manager.close)
    vault = Vault()
    stack.callback(vault.lock)
    database = directory / "fixture.kdbx"
    vault.create(database, "public platform vault master")
    vault.ssh_configure(manager, socket=str(agent))
    borrowed = vault.ssh_agent_keys()["keys"][0]
    assert not borrowed["owned"]
    for kind in ("ed25519", "rsa", "ecdsa"):
        path = key(directory, kind, kind, "public platform key passphrase")
        vault.save_entry(vault.snapshot.root, kind, "alice", "", "Preserve", "public platform key passphrase")
        entry = vault.snapshot.entries[-1]
        vault.save_ssh_settings(entry, enabled=True, source_type="file", file=str(path), remove_on_lock=True)
        entry = next(item for item in vault.snapshot.entries if item.uuid == entry.uuid)
        review = vault.ssh_prepare(entry)
        assert not review["loaded"]
        assert vault.ssh_add(review["token"], approved=True)["added"]
        signature(directory, path, agent)
    assert len(identities(agent)) == 4
    if backend:
        assert len(identities(backend)) == 4
    alias = directory / "agent-alias"
    alias.symlink_to(agent)
    vault.ssh_configure(manager, socket=str(alias))
    assert sum(info["owned"] for info in vault.ssh_agent_keys()["keys"]) == 3
    alias.unlink()
    vault.lock()
    assert len(identities(agent)) == 1
    assert manager.status()["cleanup_ok"]
    vault.unlock(database, "public platform vault master")
    vault.ssh_configure(manager, socket=str(agent))
    review = vault.ssh_review_removal([borrowed["fingerprint"]])
    assert vault.ssh_finish_removal(review["token"], approved=True)["complete"]
    assert not identities(agent)
    entry = vault.snapshot.entries[-1]
    vault.save_ssh_settings(entry, lifetime=True, seconds=1)
    entry = next(item for item in vault.snapshot.entries if item.uuid == entry.uuid)
    vault.ssh_add(vault.ssh_prepare(entry)["token"], approved=True)
    assert len(identities(agent)) == 1
    wait(lambda: not identities(agent), seconds=5)
    vault.lock()
    assert manager.status()["cleanup_ok"]
    if backend:
        assert not identities(backend)


def gcr(directory, stack):
    from gi.repository import GLib
    home = Path(GLib.get_home_dir())
    assert os.environ.get("NIX_BUILD_TOP") and not home.exists(), "Run GCR acceptance inside the Nix build sandbox"
    assert not (home / ".ssh").exists(), "GCR must never scan actual user SSH files"
    executable = os.environ["KEYSLOT_TEST_GCR"]
    base = directory / "gcr"
    base.mkdir(mode=0o700)
    log = stack.enter_context((directory / "gcr.log").open("wb"))
    env = dict(os.environ)
    for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        env.pop(name, None)
    process = subprocess.Popen([executable, "--base-dir", str(base)], env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
    stack.callback(stop, process)
    wait(lambda: (base / "ssh").exists() or process.poll() is not None)
    assert process.poll() is None, "Owned GCR service failed to start"
    exercise(directory, base / "ssh", stack)
    print("GCR agent: encrypted Ed25519/RSA/ECDSA signing, independent verify/tamper, alias ownership, borrowed keys, lock cleanup, reviewed removal and lifetime passed")


def forwarded(directory, stack):
    backend = directory / "backend-agent"
    log = stack.enter_context((directory / "forwarding.log").open("wb"))
    agent = subprocess.Popen(["ssh-agent", "-D", "-a", str(backend)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
    stack.callback(stop, agent)
    wait(backend.exists)
    host, client = key(directory, "host"), key(directory, "client")
    authorized = directory / "authorized"
    authorized.write_text(Path(str(client) + ".pub").read_text())
    authorized.chmod(0o600)
    assert directory.stat().st_mode & 0o777 == 0o700 and authorized.stat().st_mode & 0o777 == 0o600
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    username = "keyslot-fixture"
    home = directory / "home"
    home.mkdir(mode=0o700)
    passwd, group = directory / "passwd", directory / "group"
    shell = shutil.which("sh")
    assert shell and os.getuid() != 0, "Run forwarding acceptance as an ordinary user"
    passwd.write_text(f"{username}:x:{os.getuid()}:{os.getgid()}:Keyslot SSH fixture:{home}:{shell}\n")
    group.write_text(f"{username}:x:{os.getgid()}:{username}\n")
    server_env = os.environ | {"LD_PRELOAD": os.environ["KEYSLOT_TEST_NSS_WRAPPER"],
        "NSS_WRAPPER_PASSWD": str(passwd), "NSS_WRAPPER_GROUP": str(group)}
    empty = directory / "empty-shell-config"
    empty.mkdir(mode=0o700)
    helper = directory / "forwarded-session.py"
    helper.write_text('import json,os,sys\nprint(json.dumps({"socket":os.environ["SSH_AUTH_SOCK"]}),flush=True)\nsys.stdin.buffer.read(1)\n')
    command = shlex.join([sys.executable, "-u", str(helper)])
    config = directory / "sshd.conf"
    config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {host}
PidFile {directory / "sshd.pid"}
AuthorizedKeysFile {authorized}
StrictModes no
AllowUsers {username}
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
HostbasedAuthentication no
UsePAM no
UseDNS no
PermitUserEnvironment no
PermitTTY no
AllowAgentForwarding yes
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog no
SetEnv __ETC_ZSHENV_SOURCED=1 ZDOTDIR={empty} ENV=/dev/null BASH_ENV=/dev/null
ForceCommand {command}
''')
    sshd = shutil.which("sshd")
    assert sshd, "Supply OpenSSH's sshd for host forwarding acceptance"
    run([sshd, "-t", "-f", str(config)], env=server_env)
    server = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)],
        env=server_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
    stack.callback(stop, server)
    def listening():
        if server.poll() is not None:
            raise AssertionError("The owned loopback SSH server failed to start")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return True
        except OSError:
            return False
    wait(listening)
    known = directory / "known-hosts"
    known.write_text(f'[127.0.0.1]:{port} ' + Path(str(host) + ".pub").read_text())
    args = ["ssh", "-F", "/dev/null", "-p", str(port), "-i", str(client),
        "-o", f"IdentityAgent={backend}", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={known}", "-o", f"ForwardAgent={backend}",
        "-o", "ConnectTimeout=3", "-o", "ControlPath=none", f"{username}@127.0.0.1", "fixture"]
    session = subprocess.Popen(args, env=environment(backend), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
    stack.callback(stop, session)
    import select
    assert select.select([session.stdout], [], [], 8)[0], "Owned forwarding session did not respond"
    line = session.stdout.readline()
    assert line, "Owned SSH authentication failed; inspect the private fixture server log"
    endpoint = Path(json.loads(line)["socket"])
    assert endpoint.is_absolute() and endpoint.resolve().is_relative_to(home) and endpoint.stat().st_uid == os.getuid(), line.decode()
    exercise(directory, endpoint, stack, backend)
    print("OpenSSH forwarding: real loopback channel, encrypted-key signing/independent verification, alias ownership, borrowed keys, removal/lifetime and backend cleanup passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gcr", action="store_true")
    parser.add_argument("--forwarded", action="store_true")
    options = parser.parse_args()
    assert options.gcr != options.forwarded, "Choose one isolated agent acceptance mode"
    with tempfile.TemporaryDirectory(prefix="ks-agent-platform-", dir="/tmp") as temporary, ExitStack() as stack:
        try:
            (gcr if options.gcr else forwarded)(Path(temporary), stack)
        except Exception as error:
            if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                sys.stderr.buffer.write(error.stderr[-8192:])
            for log in Path(temporary).glob("*.log"):
                sys.stderr.buffer.write(log.read_bytes()[-8192:])
            raise
