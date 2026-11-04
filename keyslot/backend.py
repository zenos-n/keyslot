"""KeePassXC owns the file format and crypto; plaintext never goes to disk.

The CLI is a transitional backend, not a full KeePassXC integration API.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field


class VaultError(Exception):
    pass


@dataclass
class Entry:
    uuid: str
    path: str
    group: str
    title: str
    username: str = ""
    url: str = ""
    notes: str = ""
    tags: str = ""
    attributes: tuple[str, ...] = ()
    attachments: tuple[str, ...] = ()
    history_count: int = 0
    totp: bool = False
    passkey: bool = False
    recycled: bool = False
    addressable: bool = True
    group_path: str = ""
    expires: bool = False
    expiry: str = ""
    expired: bool = False
    icon: int = 0
    custom_icon: str = ""
    foreground: str = ""
    background: str = ""
    override_url: str = ""
    command_approved: bool = False
    exclude_reports: bool = False
    created: str = ""
    modified: str = ""
    _owner: object = field(default=None, repr=False)


@dataclass
class Group:
    path: str
    name: str
    depth: int
    recycled: bool = False
    addressable: bool = True
    uuid: str = ""
    parent: str = ""
    notes: str = ""
    icon: int = 48
    custom_icon: str = ""
    tags: str = ""
    searching: int = 0
    expires: bool = False
    expiry: str = ""
    expired: bool = False
    expanded: bool = True

    @property
    def identity(self):
        return self.uuid or self.path


@dataclass
class Snapshot:
    name: str
    recycle_bin_enabled: bool = True
    groups: list[Group] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)
    root: str = ""
    default_username: str = ""
    secret_group: str = ""
    modified: bool = False
    recovery_path: str = ""
    recovery_copy: bool = False
    recycle_bin: str = ""
    non_data_only: bool = False
    entry_order: tuple[str, ...] = ()


def ordered_entries(snapshot):
    ranks = {identifier: index for index, identifier in enumerate(snapshot.entry_order)}
    return sorted(snapshot.entries, key=lambda entry: (ranks.get(entry.uuid, len(ranks)), entry.title.casefold()))


def parse_snapshot(xml: bytes) -> Snapshot:
    if b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise VaultError("Unsupported XML declarations in database export.")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise VaultError("KeePassXC returned an invalid database export.") from exc
    snapshot = Snapshot(root.findtext("Meta/DatabaseName", ""),
                        root.findtext("Meta/RecycleBinEnabled", "True") == "True")
    recycled_uuid = root.findtext("Meta/RecycleBinUUID", "")

    def walk(node, path, depth, recycled=False, addressable=True):
        recycled = recycled or node.findtext("UUID") == recycled_uuid
        snapshot.groups.append(Group(path, node.findtext("Name", ""), depth,
                                     recycled, addressable))
        nodes = node.findall("Entry")
        titles = [n.findtext("String[Key='Title']/Value", "") for n in nodes]
        title_counts = Counter(titles)
        for n, title in zip(nodes, titles):
            fields = {s.findtext("Key", ""): s.find("Value") for s in n.findall("String")}

            def public(name):
                v = fields.get(name)
                return (v.text or "") if v is not None and not any(
                    v.get(flag) == "True" for flag in ("Protected", "ProtectInMemory")) else ""

            snapshot.entries.append(Entry(
                uuid=n.findtext("UUID", ""), path=path + title, group=path,
                title=title or "Untitled Entry", username=public("UserName"),
                url=public("URL"), notes=public("Notes"), tags=n.findtext("Tags", ""),
                attributes=tuple(k for k in fields if k not in
                                 ("Title", "UserName", "Password", "URL", "Notes")),
                attachments=tuple(b.findtext("Key", "") for b in n.findall("Binary")),
                history_count=len(n.findall("History/Entry")),
                totp=any(k.lower() == "otp" or k.lower().startswith("timeotp") for k in fields),
                recycled=recycled,
                addressable=addressable and bool(title) and "/" not in title and
                            not any(ord(c) < 32 for c in title) and title_counts[title] == 1,
            ))
        children = node.findall("Group")
        names = [n.findtext("Name", "") for n in children]
        name_counts = Counter(names)
        for child, name in zip(children, names):
            valid = bool(name) and "/" not in name and not any(ord(c) < 32 for c in name)
            walk(child, path + name + "/", depth + 1, recycled,
                 addressable and valid and name_counts[name] == 1)

    group = root.find("Root/Group")
    if group is None:
        raise VaultError("The database has no root group.")
    walk(group, "/", 0)
    return snapshot


def fingerprint(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def cli_token(text: str) -> str:
    # KeePassXC's command parser uses double quotes and backslash escapes, not shlex.
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise VaultError("This CLI backend cannot edit fields containing control characters or newlines.")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Vault:
    def __init__(self, executable="keepassxc-cli"):
        self.executable = shutil.which(executable)
        if not self.executable:
            raise VaultError("Install KeePassXC 2.7.12 or later to provide keepassxc-cli.")
        self.path: Path | None = None
        self.snapshot: Snapshot | None = None
        self._password = bytearray()
        self._keyfile = ""
        self._yubikey = ""
        self._no_password = False
        self._fingerprint = ""
        self._mutex = threading.RLock()
        self._cancelled = threading.Event()
        self._process_mutex = threading.Lock()
        self._process: subprocess.Popen | None = None

    @property
    def unlocked(self):
        return self.snapshot is not None and not self._cancelled.is_set()

    def cancel(self):
        """Interrupt KDF/hardware waits immediately, even while a worker holds the mutex."""
        self._cancelled.set()
        with self._process_mutex:
            if self._process is not None:
                self._process.kill()

    def lock(self):
        self.cancel()
        with self._mutex:
            self._password[:] = b"\0" * len(self._password)
            self._password.clear()
            self.snapshot = None
            self._fingerprint = ""

    def _auth(self):
        args = ["-q"]
        if self._keyfile:
            args += ["-k", self._keyfile]
        if self._yubikey:
            args += ["-y", self._yubikey]
        if self._no_password:
            args += ["--no-password"]
        return args

    def _spawn(self, args, **kwargs):
        if self._cancelled.is_set():
            raise VaultError("The database is locked.")
        with self._process_mutex:
            if self._cancelled.is_set():
                raise VaultError("The database is locked.")
            p = subprocess.Popen([self.executable, *map(str, args)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env={**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "TERM": "dumb"},
                                 **kwargs)
            self._process = p
            return p

    def _finish(self, p):
        if p.poll() is None:
            p.kill()
        p.wait()
        for stream in (p.stdin, p.stdout, p.stderr):
            stream.close()
        with self._process_mutex:
            if self._process is p:
                self._process = None

    def _run(self, args, data=b"", timeout=120):
        p = self._spawn(args)
        try:
            out, _err = p.communicate(data, timeout=timeout)
            if p.returncode:
                # Error text can contain entry data; do not surface it or log it.
                raise VaultError("KeePassXC could not complete the operation. Check the credentials, key file, hardware key, and file permissions.")
            return out
        except subprocess.TimeoutExpired as exc:
            raise VaultError("KeePassXC timed out. Check whether your hardware key needs a touch.") from exc
        finally:
            self._finish(p)

    def _password_input(self):
        return bytes(self._password) + b"\n" if not self._no_password else b""

    def unlock(self, path, password, keyfile="", yubikey="", no_password=False):
        with self._mutex:
            self.lock()
            self._cancelled.clear()
            self.path = Path(path).expanduser().resolve(strict=True)
            if not self.path.is_file():
                raise VaultError("Select a database file.")
            if "\n" in password or "\r" in password or "\0" in password:
                raise VaultError("This CLI backend cannot unlock a password containing a newline or NUL.")
            if yubikey and not re.fullmatch(r"[12](?::[0-9]+)?", yubikey):
                raise VaultError("Use hardware key slot 1 or 2, optionally followed by :serial.")
            self._password = bytearray(password.encode("utf-8"))
            self._keyfile, self._yubikey, self._no_password = keyfile, yubikey, no_password
            try:
                return self.refresh()
            except Exception:
                self.lock()
                raise

    def refresh(self):
        with self._mutex:
            before = fingerprint(self.path)
            xml = self._run(["export", *self._auth(), "-f", "xml", "--", self.path], self._password_input())
            snapshot = parse_snapshot(xml)
            if fingerprint(self.path) != before:
                raise VaultError("The database changed while being read. Refresh to try again.")
            self.snapshot, self._fingerprint = snapshot, before
            return snapshot

    def _entry(self, entry: Entry):
        if not self.unlocked or entry not in self.snapshot.entries:
            raise VaultError("Refresh and select the entry again.")
        if not entry.addressable:
            raise VaultError("This entry has an ambiguous path. Use KeePassXC to rename it before editing or copying it here.")
        if fingerprint(self.path) != self._fingerprint:
            raise VaultError("Another application changed this database. Refresh before continuing.")

    def attribute(self, entry, name="Password", totp=False):
        with self._mutex:
            self._entry(entry)
            args = ["show", *self._auth(), "-t"] if totp else ["show", *self._auth(), "-s", "-a", name]
            data = self._run([*args, "--", self.path, entry.path], self._password_input())
            return data.decode("utf-8").removesuffix("\n")

    def create(self, path, password, keyfile=""):
        with self._mutex:
            if not password or any(c in password for c in "\n\r\0"):
                raise VaultError("Choose a nonempty master password without newlines or NUL.")
            target = Path(path).expanduser().absolute()
            if target.exists():
                raise VaultError("A file already exists at that location.")
            self._cancelled.clear()
            with tempfile.TemporaryDirectory(prefix=".keyslot-", dir=target.parent) as directory:
                stage = Path(directory) / "new.kdbx"
                args = ["db-create", "-q", "-p"]
                if keyfile:
                    if not Path(keyfile).is_file():
                        raise VaultError("Choose an existing key file.")
                    args += ["--set-key-file", keyfile]
                self._run([*args, "--", stage], (password + "\n" + password + "\n").encode())
                stage.chmod(0o600)
                os.link(stage, target)  # Atomic no-clobber creation.
            return self.unlock(target, password, keyfile)

    def _interactive(self, path, tokens, password=None):
        command = " ".join(cli_token(str(t)) for t in tokens) + "\n"
        if len(command.encode()) > 3000:
            raise VaultError("This CLI backend supports at most 3000 bytes per edit.")
        name = self.snapshot.name or path.name
        cli_token(name)
        prompt = (name + "> ").encode()
        p = self._spawn(["open", *self._auth(), "--", path], bufsize=0)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(p.stdout, selectors.EVENT_READ, "out")
                selector.register(p.stderr, selectors.EVENT_READ, "err")

                def wait_for(suffix, channel="out"):
                    buffers = {"out": bytearray(), "err": bytearray()}
                    deadline = time.monotonic() + 120
                    while time.monotonic() < deadline:
                        if self._cancelled.is_set():
                            raise VaultError("The database is locked.")
                        for key, _ in selector.select(0.1):
                            data = os.read(key.fd, 65536)
                            if not data:
                                raise VaultError("KeePassXC closed before completing the operation.")
                            buffers[key.data].extend(data)
                        if buffers[channel].endswith(suffix):
                            return bytes(buffers["out"])
                        if sum(map(len, buffers.values())) > 8 * 1024 * 1024:
                            raise VaultError("KeePassXC returned too much data.")
                    raise VaultError("KeePassXC timed out. Check your hardware key.")

                if not self._no_password:
                    p.stdin.write(self._password_input())
                wait_for(prompt)
                p.stdin.write(command.encode())
                if password is not None:
                    if any(c in password for c in "\n\r\0"):
                        raise VaultError("Entry passwords containing newlines or NUL are not supported by this backend.")
                    wait_for(b"Enter password for new entry: " if tokens[0] == "add" else b"Enter new password for entry: ")
                    p.stdin.write((password + "\n").encode())
                out = wait_for(prompt)
                p.stdin.write(b"exit\n")
                p.wait(timeout=5)
                # Interactive CLI discards command exit codes; require its positive acknowledgement.
                if not any(line.startswith(b"Successfully ") for line in out.splitlines()):
                    raise VaultError("KeePassXC did not confirm this change. The original database was not modified.")
        finally:
            self._finish(p)

    def _mutate(self, tokens, password=None):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            if not os.access(self.path, os.W_OK):
                raise VaultError("The database is read-only.")
            if fingerprint(self.path) != self._fingerprint:
                raise VaultError("Another application changed this database. Refresh before saving.")
            original_mode = stat.S_IMODE(self.path.stat().st_mode)
            with tempfile.TemporaryDirectory(prefix=".keyslot-", dir=self.path.parent) as directory:
                stage = Path(directory) / self.path.name
                shutil.copyfile(self.path, stage)
                stage.chmod(0o600)
                self._interactive(stage, tokens, password)
                xml = self._run(["export", *self._auth(), "-f", "xml", "--", stage], self._password_input())
                snapshot = parse_snapshot(xml)
                if fingerprint(self.path) != self._fingerprint or self._cancelled.is_set():
                    raise VaultError("The database changed or was locked during this operation. The original was not replaced.")
                backup = Path(directory) / "backup.kdbx"
                shutil.copyfile(self.path, backup)
                backup.chmod(0o600)
                with backup.open("rb") as stream:
                    os.fsync(stream.fileno())
                os.replace(backup, str(self.path) + ".keyslot.bak")
                stage.chmod(original_mode & 0o777)
                with stage.open("rb") as stream:
                    os.fsync(stream.fileno())
                if fingerprint(self.path) != self._fingerprint or self._cancelled.is_set():
                    raise VaultError("The database changed or was locked before saving. Refresh to continue.")
                os.replace(stage, self.path)
                dir_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            self.snapshot, self._fingerprint = snapshot, fingerprint(self.path)
            return snapshot

    def save_entry(self, group, title, username, url, notes, password=None, entry=None):
        with self._mutex:
            if not title.strip() or "/" in title:
                raise VaultError("Choose a title without a slash.")
            target = next((g for g in self.snapshot.groups if g.path == group and g.addressable), None)
            if target is None or target.recycled:
                raise VaultError("Choose a regular, uniquely named group.")
            tokens = ["edit" if entry else "add"]
            if entry:
                self._entry(entry)
                if group != entry.group:
                    raise VaultError("Move entries separately from editing them.")
            if any(e.path == group + title and (not entry or e.uuid != entry.uuid)
                   for e in self.snapshot.entries):
                raise VaultError("An entry with this title already exists in the group.")
            for flag, value, old in [("--username", username, entry.username if entry else None),
                                     ("--url", url, entry.url if entry else None),
                                     ("--notes", notes, entry.notes if entry else None)]:
                if value != old:
                    if entry and not value:
                        raise VaultError("KeePassXC's CLI cannot clear username, URL, or notes. Clear this field in KeePassXC until the native engine bridge is available.")
                    if flag == "--notes":
                        if "\\n" in value:
                            raise VaultError("This CLI backend cannot preserve literal backslash-n in edited notes.")
                        value = value.replace("\n", "\\n")
                    tokens.append(flag + "=" + value)
            if entry and title != entry.title:
                tokens.append("--title=" + title)
            if password is not None:
                tokens.append("-p")
            if entry and len(tokens) == 1:
                return self.snapshot
            tokens += ["--", entry.path if entry else group + title]
            return self._mutate(tokens, password)

    def add_group(self, parent, name):
        with self._mutex:
            if not name.strip() or "/" in name:
                raise VaultError("Choose a group name without a slash.")
            if not any(g.path == parent and g.addressable and not g.recycled for g in self.snapshot.groups):
                raise VaultError("Choose a regular parent group.")
            return self._mutate(["mkdir", "--", parent + name])

    def delete_entry(self, entry):
        with self._mutex:
            self._entry(entry)
            if entry.recycled or not self.snapshot.recycle_bin_enabled:
                raise VaultError("The recycle bin is disabled or this entry is already recycled. Permanent deletion is available in KeePassXC.")
            return self._mutate(["rm", "--", entry.path])

    def move_entry(self, entry, destination):
        with self._mutex:
            self._entry(entry)
            if not any(g.path == destination and g.addressable and not g.recycled for g in self.snapshot.groups):
                raise VaultError("Choose a regular destination group.")
            if any(e.path == destination + entry.title for e in self.snapshot.entries):
                raise VaultError("An entry with this title already exists at the destination.")
            return self._mutate(["mv", "--", entry.path, destination])

    def import_attachment(self, entry, source):
        with self._mutex:
            self._entry(entry)
            source = Path(source).resolve(strict=True)
            if source.name in entry.attachments:
                raise VaultError("An attachment with this name already exists.")
            return self._mutate(["attachment-import", "--", entry.path, source.name, str(source)])

    def export_attachment(self, entry, name, destination):
        with self._mutex:
            self._entry(entry)
            if name not in entry.attachments:
                raise VaultError("Select an attachment from this entry.")
            destination = Path(destination).absolute()
            # Export only after an explicit file chooser; never overwrite an existing file.
            with tempfile.TemporaryDirectory(prefix=".keyslot-", dir=destination.parent) as directory:
                stage = Path(directory) / "attachment"
                self._run(["attachment-export", *self._auth(), "--", self.path,
                           entry.path, name, stage], self._password_input())
                stage.chmod(0o600)
                os.link(stage, destination)

    def generate(self, length=24, passphrase=False):
        with self._mutex:
            if not self.unlocked:
                self._cancelled.clear()
            args = ["diceware", "-W", str(length)] if passphrase else ["generate", "-L", str(length), "-l", "-U", "-n", "-s", "--every-group"]
            if not 4 <= length <= (20 if passphrase else 128):
                raise VaultError("Choose a supported password length.")
            return self._run(args).decode().removesuffix("\n")
