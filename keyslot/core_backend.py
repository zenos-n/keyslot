"""Private pipe protocol to a helper linked to the actual KeePassXC core.

Only the helper keeps the composite unlock key. The public Shell D-Bus API
exposes aggregate lock/background state and Show/Lock/Quit/AutoType actions.
"""
from __future__ import annotations

from dataclasses import fields
from contextlib import contextmanager
import json
import os
import re
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import threading
import time

from .backend import Entry, Group, Snapshot, VaultError
from . import CORE_VERSION

MAX_FRAME = 64 * 1024 * 1024


def _icon_bytes(raw):
    if len(raw) > 8 * 1024 * 1024:
        raise VaultError("Choose an icon file smaller than 8 MiB.")
    if b"<svg" in raw[:4096].lower():
        import gi
        gi.require_version("GdkPixbuf", "2.0")
        from gi.repository import GdkPixbuf
        # A byte loader has no base URI, so SVG cannot load adjacent files.
        loader = GdkPixbuf.PixbufLoader.new_with_type("svg")
        def prepared(loader, width, height):
            scale = min(1, 128 / max(1, width, height))
            loader.set_size(max(1, round(width * scale)), max(1, round(height * scale)))
        loader.connect("size-prepared", prepared)
        try:
            loader.write(raw)
            loader.close()
            pixbuf = loader.get_pixbuf()
            ok, raw = pixbuf.save_to_bufferv("png", [], [])
            if not ok:
                raise ValueError()
        except Exception as exc:
            raise VaultError("This SVG icon could not be decoded.") from exc
    return raw


class Vault:
    def __init__(self, executable=None, timeout=120):
        candidate = executable or os.environ.get("KEYSLOT_ENGINE") or "keyslot-engine"
        self.executable = shutil.which(str(candidate))
        if not self.executable:
            raise VaultError("Build and install Keyslot's native KeePassXC engine. The CLI-only backend cannot provide the required editing compatibility.")
        self.timeout = timeout
        self.path = None
        self.snapshot = None
        self._mutex = threading.RLock()
        self._process_mutex = threading.Lock()
        self._cancelled = threading.Event()
        self._process = None
        self._runtime = None
        self._preserve_runtime = False
        self._request_id = 0
        self._generation = 0
        self._operation = threading.local()
        self._owner = object()
        self.capabilities = frozenset()
        self.ssh_manager = None
        self._ssh_configuration = None
        self.ssh_warning = None
        self.auto_save = self.auto_save_on_exit = True
        self.backup_before_save = False
        self.backup_path_pattern = "{DB_FILENAME}.old.kdbx"
        self.backup_settings = None
        self.discard_on_stop = False
        self.recovery_warning = ""
        self.finishing = False
        self.auth_manager = None
        self.system_token = None
        self.system_path = None

    @property
    def unlocked(self):
        return self.snapshot is not None and not self._cancelled.is_set()

    def cancel(self):
        with self._process_mutex:
            self.finishing = True
            self._generation += 1
            self._cancelled.set()
            if self._process and self._process.poll() is None:
                self._process.kill()

    @property
    def generation(self):
        with self._process_mutex:
            return self._generation

    @property
    def identity(self):
        """In-process identity of the current helper; never serialized or exposed on D-Bus."""
        return self._owner

    @contextmanager
    def operation(self, generation):
        previous = getattr(self._operation, "generation", None)
        self._operation.generation = generation
        try:
            yield
        finally:
            self._operation.generation = previous

    def _stop(self):
        with self._process_mutex:
            process, self._process = self._process, None
            runtime, self._runtime = self._runtime, None
            preserve_runtime, self._preserve_runtime = self._preserve_runtime, False
        try:
            if process:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdin.close()
                process.stdout.close()
                if self.auth_manager and self.auth_manager.process is not None:
                    try:
                        self.auth_manager.unregister(process.pid)
                    except VaultError:
                        self.auth_manager.close()
                if self.ssh_manager:
                    if self.ssh_manager.process is not None:
                        try:
                            self.ssh_manager.unregister(process.pid)
                        except VaultError as exc:
                            self.ssh_warning = str(exc)
                    elif not self.ssh_manager.cleanup_ok:
                        self.ssh_warning = "SSH key cleanup was not confirmed. Review your SSH agent."
            if runtime:
                self._finish_manual(runtime)
        finally:
            try:
                if runtime and not preserve_runtime:
                    runtime.cleanup()
            finally:
                self.finishing = False

    def _finish_manual(self, runtime):
        discard, self.discard_on_stop = self.discard_on_stop, False
        pointer = Path(runtime.name) / "manual.json"
        if not pointer.exists():
            return
        try:
            manifest = json.loads(pointer.read_text())["manifest"]
            if not Path(manifest).exists():
                return
            if discard:
                self.recovery_action("discard", manifest, self.path)
            elif self.auto_save_on_exit:
                self.recovery_action("commit", manifest, self.path)
            else:
                raise VaultError("Unsaved changes were kept in an encrypted recovery copy.")
            try:
                Path(manifest).parent.rmdir()
            except OSError:
                pass
        except (VaultError, OSError, ValueError, KeyError, TypeError) as exc:
            name = self.path.name if self.path else "Vault"
            self.recovery_warning = f"{name}: {exc}\nOpen this vault again to review its unsaved recovery copy."

    def recovery_action(self, action, manifest=None, source=None, **options):
        client = Vault(executable=self.executable, timeout=self.timeout)
        client.backup_before_save = self.backup_before_save
        client.backup_path_pattern = self.backup_path_pattern
        client.backup_settings = self.backup_settings
        try:
            client._start()
            return client._rpc("recovery." + action, source=str(source or self.path),
                               **({"manifest": str(manifest)} if manifest else {}), **options)
        finally:
            client.lock()

    def _recovery_files(self):
        if self._cancelled.is_set() or self._runtime is None:
            return []
        try:
            return list(Path(self._runtime.name).glob("recovery-*/database.kdbx"))
        except OSError:
            return []

    def lock(self):
        self.cancel()
        self.finish_lock()

    def finish_lock(self):
        with self._mutex:
            self._stop()
            self.snapshot = None

    def _start(self):
        with self._process_mutex:
            expected = getattr(self._operation, "generation", None)
            if expected is not None and expected != self._generation:
                raise VaultError("The operation was cancelled before the native engine started.")
            self._cancelled.clear()
            self._owner = object()
            self._runtime = tempfile.TemporaryDirectory(prefix="keyslot-engine-", delete=False)
            state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
            environment = os.environ | {"KEYSLOT_ENGINE_CONFIG_DIRECTORY": self._runtime.name,
                                        "KEYSLOT_RECOVERY_DIRECTORY": str(state / "keyslot/recovery")}
            try:
                self._process = subprocess.Popen([self.executable], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, env=environment)
            except Exception:
                self._runtime.cleanup()
                self._runtime = None
                raise
        try:
            hello = self._rpc("hello")
            if not isinstance(hello, dict) or hello.get("protocol") != 1 or hello.get("engine") != "keepassxc-core" or hello.get("upstream") != CORE_VERSION:
                raise VaultError("The native engine protocol is incompatible with this client.")
            self.capabilities = frozenset(hello.get("capabilities", []))
            if "backup-policy" not in self.capabilities:
                raise VaultError("Update the native engine before configuring database backups.")
            self._rpc("backup.policy", enabled=self.backup_before_save, pattern=self.backup_path_pattern)
            if not self.auto_save:
                if "manual-save" not in self.capabilities:
                    raise VaultError("Update the native engine before disabling automatic saving.")
                self._rpc("save.policy", auto_save=False)
        except Exception:
            self._stop()
            raise

    def _rpc(self, method, _timeout=None, **params):
        if self._cancelled.is_set() or self._process is None:
            raise VaultError("The database is locked.")
        if method not in ("hello", "backup.policy") and "backup-policy" in self.capabilities and self.backup_settings is not None:
            # Read one committed pair even when a window opens during a preference update.
            chosen = self.backup_settings.backup_policy_value
            if chosen != (self.backup_before_save, self.backup_path_pattern):
                self.backup_policy(*chosen)
        self._request_id += 1
        identifier = self._request_id
        request = (json.dumps({"id": identifier, "method": method, "params": params},
                              ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode()
        if len(request) > MAX_FRAME:
            raise VaultError("This operation exceeds the engine's 64 MiB message limit.")
        process = self._process
        try:
            deadline = time.monotonic() + (self.timeout if _timeout is None else _timeout)
            # Nonblocking stdin keeps cancellation responsive even for a large attachment.
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin, selectors.EVENT_WRITE)
                selector.register(process.stdout, selectors.EVENT_READ)
                sent = 0
                response = bytearray()
                while time.monotonic() < deadline:
                    if self._cancelled.is_set():
                        raise VaultError("The database is locked.")
                    for key, _events in selector.select(0.1):
                        if key.fileobj is process.stdin:
                            try:
                                sent += os.write(key.fd, memoryview(request)[sent:sent + 65536])
                            except BlockingIOError:
                                continue
                            if sent == len(request):
                                selector.unregister(process.stdin)
                                request = b""
                        else:
                            try:
                                data = os.read(key.fd, 65536)
                            except BlockingIOError:
                                continue
                            if not data:
                                raise VaultError("The native engine closed. Unlock the database again.")
                            response.extend(data)
                            if len(response) > MAX_FRAME:
                                raise VaultError("The native engine response exceeds its message limit.")
                            if b"\n" in response:
                                if not response.endswith(b"\n") or response.count(b"\n") != 1:
                                    raise VaultError("The native engine returned an invalid response frame.")
                                value = json.loads(response)
                                if not isinstance(value, dict) or type(value.get("id")) is not int or value["id"] != identifier:
                                    raise VaultError("The native engine returned an invalid request ID.")
                                if value.get("unlocked") is False:
                                    self.snapshot = None
                                if "error" in value:
                                    error = value["error"]
                                    if not isinstance(error, dict) or not isinstance(error.get("message"), str):
                                        raise ValueError("invalid error response")
                                    # Recovery metadata can name encrypted files, never credential field values.
                                    code = error.get("code", "engine_error")
                                    if code == "recovery_error" and error.get("retain_runtime") is True:
                                        self._preserve_runtime = True
                                    if code == "internal_error" and (recovery := self._recovery_files()):
                                        self._preserve_runtime = True
                                        error = error | {"recovery_path": str(recovery[0]), "retain_runtime": True,
                                            "message": error["message"] + "\nAn encrypted recovery copy remains at:\n" + str(recovery[0])}
                                    raise EngineError(code, error["message"], details=error)
                                if "result" not in value:
                                    raise ValueError("missing result")
                                return value["result"]
                raise VaultError("The native engine timed out. Check your hardware key, then unlock again.")
        except EngineError:
            raise
        except (OSError, ValueError, UnicodeError, VaultError) as exc:
            runtime = self._runtime
            recovery = self._recovery_files()
            if recovery:
                self._preserve_runtime = True
            self._stop()
            self.snapshot = None
            kept = next((path for path in recovery if path.is_file()), None)
            if kept:
                raise VaultError("The native operation stopped. An encrypted recovery copy remains at:\n"
                                 + str(kept) + "\nOpen it with the original vault credentials.") from exc
            if recovery and runtime:
                runtime.cleanup()
            if isinstance(exc, VaultError):
                raise
            raise VaultError("Communication with the native engine failed. Unlock the database again.") from exc

    def _set_snapshot(self, value):
        if not isinstance(value, dict) or not isinstance(value.get("groups"), list) or not isinstance(value.get("entries"), list):
            self.lock()
            raise VaultError("The native engine returned invalid database metadata.")
        try:
            entry_keys = {f.name for f in fields(Entry)} - {"_owner"}
            group_keys = {f.name for f in fields(Group)}
            entries = [Entry(**{k: v for k, v in item.items() if k in entry_keys}, _owner=self._owner) for item in value["entries"]]
            groups = [Group(**{k: v for k, v in item.items() if k in group_keys}) for item in value["groups"]]
            self.snapshot = Snapshot(value.get("name", ""), value.get("recycle_bin_enabled", True), groups,
                                     entries, value.get("root", ""), value.get("default_username", ""), value.get("secret_group", ""),
                                     value.get("modified") is True, value.get("recovery_path", ""), value.get("recovery_copy") is True,
                                     value.get("recycle_bin", ""))
        except (TypeError, AttributeError) as exc:
            self.lock()
            raise VaultError("The native engine returned invalid database metadata.") from exc
        return self.snapshot

    def _snapshot_call(self, method, **params):
        return self._set_snapshot(self._rpc(method, **params))

    def _entry(self, entry):
        if not self.unlocked or entry not in self.snapshot.entries:
            raise VaultError("The entry changed. Refresh and select it again.")

    def unlock(self, path, password, keyfile="", yubikey="", no_password=False, allow_recovery=False):
        with self._mutex:
            self._stop()
            self.snapshot = None
            self.path = Path(path).expanduser().resolve(strict=True)
            self._start()
            try:
                return self._snapshot_call("open", path=str(self.path), password=password,
                    keyfile=keyfile, yubikey=yubikey, no_password=no_password, allow_recovery=allow_recovery)
            except Exception:
                self.lock()
                raise

    def create(self, path, password, keyfile="", yubikey="", no_password=False):
        with self._mutex:
            if not password and not no_password:
                raise VaultError("Choose a nonempty master password.")
            self._stop()
            self.snapshot = None
            self.path = Path(path).expanduser().resolve()
            self._start()
            try:
                return self._snapshot_call("create", path=str(self.path), password=password,
                    keyfile=keyfile, yubikey=yubikey, no_password=no_password)
            except Exception:
                self.lock()
                raise

    def refresh(self):
        with self._mutex:
            return self._snapshot_call("refresh")

    def save(self):
        with self._mutex:
            return self._snapshot_call("database.save")

    def inspect_output(self, destination):
        with self._mutex:
            return self._rpc("output.inspect", path=str(Path(destination).expanduser().absolute()))

    def save_as(self, destination, revision, expected_hash="", overwrite=False):
        with self._mutex:
            previous = self.path
            data = self._rpc("database.save_as", path=str(destination), revision=revision,
                             expected_hash=expected_hash, overwrite=overwrite)
            self.path = Path(data["path"])
            if self.path != previous:
                self.forget_system_auth()
            return self._set_snapshot(data["snapshot"])

    def save_policy(self, auto_save, on_exit):
        with self._mutex:
            if auto_save and not self.auto_save and self.unlocked and self.snapshot.modified:
                self._snapshot_call("database.save")
            if self.unlocked:
                self._snapshot_call("save.policy", auto_save=auto_save)
            self.auto_save, self.auto_save_on_exit = auto_save, on_exit

    def backup_policy(self, enabled, pattern):
        if type(enabled) is not bool or not isinstance(pattern, str) or len(pattern) > 16384 or "\0" in pattern:
            raise VaultError("Choose a supported backup switch and file path pattern.")
        with self._mutex:
            if self._process is not None and not self._cancelled.is_set():
                self._rpc("backup.policy", enabled=enabled, pattern=pattern)
            self.backup_before_save, self.backup_path_pattern = enabled, pattern

    def reconcile(self, merge=False, discard=False, overwrite=False, review=None):
        with self._mutex:
            return self._snapshot_call("database.reconcile", same_credentials=True, merge=merge, discard=discard,
                                       overwrite=overwrite, **(review or {}))

    def reopen(self, password, keyfile="", yubikey="", no_password=False, merge=False, discard=False, review=None):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            result = self._snapshot_call("database.reopen", password=password, keyfile=keyfile,
                                       yubikey=yubikey, no_password=no_password, merge=merge, discard=discard, **(review or {}))
            self.forget_system_auth()
            return result

    def watch_file(self, reload=True):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            if "file-watch" not in self.capabilities:
                raise VaultError("Update the native engine before using automatic vault reload.")
            data = self._rpc("database.watch", reload=reload)
            if data["state"] == "reloaded":
                data["snapshot"] = self._set_snapshot(data["snapshot"])
            return data

    def verify_credentials(self, password, keyfile="", yubikey="", no_password=False):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock the vault before configuring login unlock.")
            if self._rpc("database.key.verify", password=password, keyfile=keyfile,
                         yubikey=yubikey, no_password=no_password) is not True:
                raise VaultError("The native engine did not verify the vault credential.")

    def seal_quick_unlock(self, credentials, short_password):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock the vault before configuring quick unlock.")
            return self._rpc("quick.seal", **credentials, short_password=short_password)

    def has_system_auth(self, path):
        with self._process_mutex:
            manager = self.auth_manager
            process = manager.process if manager else None
            return bool(self.system_token and self.system_path == Path(path).expanduser().resolve()
                        and process and process.poll() is None)

    def forget_system_auth(self):
        with self._process_mutex:
            manager, token = self.auth_manager, self.system_token
            self.system_token = self.system_path = None
        if token and manager and manager.process is not None:
            try:
                manager.forget(token)
            except VaultError:
                # A failed revocation must not leave an unreachable credential broker running.
                manager.close()

    def _configure_system_auth(self, manager):
        if "polkit-unlock" not in self.capabilities:
            raise VaultError("Update the native engine before using system authentication.")
        if not self._process or self._process.poll() is not None:
            raise VaultError("The native vault helper stopped.")
        manager.register(self._process.pid)
        process = manager.process
        if process is None or process.poll() is not None:
            raise VaultError("The system-authentication broker stopped.")
        self._rpc("auth.configure", socket=str(manager.path), pid=process.pid)
        self.auth_manager = manager

    def enroll_system_auth(self, manager, credentials):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock this vault with its master credential first.")
            generation = self.generation
            old_manager, old_token = self.auth_manager, self.system_token
            self._configure_system_auth(manager)
            token = self._rpc("auth.enroll", **credentials)
            if not isinstance(token, str) or len(token) != 36:
                raise VaultError("The system-authentication enrollment response is invalid.")
            try:
                manager.commit(token)
                with self._process_mutex:
                    if self._cancelled.is_set() or generation != self._generation:
                        raise VaultError("System-authentication enrollment was cancelled.")
                    self.system_token, self.system_path = token, self.path
            except Exception:
                manager.forget(token)
                raise
            if old_token and old_manager and old_manager.process is not None:
                try:
                    old_manager.forget(old_token)
                except VaultError:
                    old_manager.close()
            return True

    def system_unlock(self, path, allow_recovery=False):
        with self._mutex:
            if not self.has_system_auth(path):
                raise VaultError("System authentication is unavailable. Use the master password.")
            manager, token = self.auth_manager, self.system_token
            self._stop(); self.snapshot = None
            self.path = Path(path).expanduser().resolve(strict=True)
            self._start()
            try:
                self._configure_system_auth(manager)
                return self._snapshot_call("auth.unlock", path=str(self.path), token=token,
                                           allow_recovery=allow_recovery, _timeout=135)
            except Exception as exc:
                self.lock()
                if isinstance(exc, EngineError) and exc.code in {"key_error", "auth_missing"}:
                    self.forget_system_auth()
                raise

    def quick_unlock(self, path, blob, short_password, allow_recovery=False):
        with self._mutex:
            self._stop()
            self.snapshot = None
            self.path = Path(path).expanduser().resolve()
            self._start()
            try:
                return self._snapshot_call("quick.unlock", path=str(self.path), blob=blob, short_password=short_password, allow_recovery=allow_recovery)
            except Exception:
                self.lock()
                raise

    def import_database(self, path, source, source_format, password, keyfile="", yubikey="", no_password=False,
                        source_password="", source_keyfile="", csv_options=None, source_fingerprint=None):
        with self._mutex:
            if source_format not in {"keepass1", "xml", "bitwarden", "1pux", "opvault", "protonpass", "csv"}:
                raise VaultError("Choose a supported import format.")
            if not password and not no_password:
                raise VaultError("Choose a nonempty master password for the imported database.")
            requested_target = Path(path).expanduser().absolute()
            if requested_target.exists() or requested_target.is_symlink():
                raise VaultError("Choose a new file for the imported database. Existing files cannot be replaced.")
            target = requested_target.resolve()
            source = Path(source).expanduser().resolve(strict=True)
            if target.exists() or target == source:
                raise VaultError("Choose a new file for the imported database. Existing files cannot be replaced.")
            if (source_format == "opvault" and not source.is_dir()) or (source_format != "opvault" and not source.is_file()):
                raise VaultError("Select the source file, or the directory for an OPVault import.")
            extra = {}
            if csv_options is not None:
                if not isinstance(csv_options, dict):
                    raise VaultError("CSV options must be an object.")
                extra["csv_options"] = csv_options
            if source_fingerprint is not None:
                extra["source_fingerprint"] = source_fingerprint
            self._stop()
            self.snapshot = None
            self.path = target
            self._start()
            try:
                return self._snapshot_call("import.create", path=str(target), source=str(source), source_format=source_format,
                    password=password, keyfile=keyfile, yubikey=yubikey, no_password=no_password,
                    source_password=source_password, source_keyfile=source_keyfile, **extra)
            except Exception:
                self.lock()
                raise

    def inspect_csv(self, source, csv_options=None, row_start=None, column_start=0, reveal=False, source_fingerprint=None):
        with self._mutex:
            source = Path(source).expanduser().resolve(strict=True)
            if not source.is_file():
                raise VaultError("Choose a CSV source file.")
            params = {"source": str(source), "csv_options": csv_options if csv_options is not None else {},
                      "column_start": column_start, "reveal": reveal}
            if row_start is not None:
                params["row_start"] = row_start
            if source_fingerprint is not None:
                params["source_fingerprint"] = source_fingerprint
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            return self._rpc("import.csv.inspect", **params)

    def inspect_import(self, source, source_format, source_password="", source_keyfile="", csv_options=None,
                       source_fingerprint=None, row_start=0):
        with self._mutex:
            params = {"source": str(Path(source).expanduser().resolve(strict=True)), "source_format": source_format,
                      "source_password": source_password, "source_keyfile": source_keyfile, "row_start": row_start}
            if csv_options is not None:
                params["csv_options"] = csv_options
            if source_fingerprint is not None:
                params["source_fingerprint"] = source_fingerprint
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            return self._rpc("import.inspect", **params)

    def settings(self):
        with self._mutex:
            return self._rpc("database.settings")

    def browser_info(self):
        with self._mutex:
            return self._rpc("browser.info")

    def browser_prepare_passkey(self, identifier, key, mode, public_key, origin, group_name=""):
        with self._mutex:
            return self._rpc("browser.passkey.prepare", id=identifier, key=key, mode=mode,
                             public_key=public_key, origin=origin, group_name=group_name)

    def passkey_info(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._rpc("passkey.info", entry=entry.uuid)

    def ssh_configure(self, manager=None, socket="", provider=""):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock the vault before configuring SSH integration.")
            configuration = manager, self.identity, socket, provider
            if configuration == self._ssh_configuration:
                return
            previous, pid = self.ssh_manager, self._process.pid
            if manager:
                manager.register(pid)
            try:
                self._rpc("ssh.configure", relay=str(manager.path) if manager else "", socket=socket, provider=provider)
            except Exception:
                if manager:
                    try:
                        manager.unregister(pid)
                    except VaultError:
                        pass
                raise
            self.ssh_manager = manager
            self._ssh_configuration = configuration
            if previous and previous is not manager and previous.process is not None:
                try:
                    previous.unregister(pid)
                except VaultError as exc:
                    self.ssh_warning = str(exc)

    def _ssh_ready(self):
        if not self.unlocked or self._process is None or self.ssh_manager is None:
            raise VaultError("Enable SSH-agent integration for this unlocked vault first.")
        self.ssh_manager.register(self._process.pid)

    def ssh_settings(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._rpc("ssh.settings", entry=entry.uuid)

    def autotype_settings(self, entry=None, group=None):
        with self._mutex:
            if entry is not None:
                self._entry(entry)
                return self._rpc("autotype.settings", entry=entry.uuid)
            return self._rpc("autotype.group.settings", group=group)

    def autotype_fields(self, entry):
        with self._mutex:
            self._entry(entry)
            if "autotype-fields" not in self.capabilities:
                raise VaultError("Update the native engine before using field-only Auto-Type actions.")
            data = self._rpc("autotype.fields", entry=entry.uuid)
            if (not isinstance(data, dict) or set(data) != {"eligible", "username", "password", "totp", "url"}
                    or any(type(value) is not bool for value in data.values())):
                raise VaultError("The engine returned invalid Auto-Type field information.")
            return data

    def save_autotype_settings(self, entry=None, group=None, **options):
        with self._mutex:
            if entry is not None:
                self._entry(entry)
                return self._snapshot_call("autotype.settings.save", entry=entry.uuid, **options)
            return self._snapshot_call("autotype.group.save", group=group, **options)

    def autotype_targets(self):
        with self._mutex:
            return self._rpc("autotype.targets")["windows"]

    def autotype_matches(self, title, match_title=True, match_url=True, hide_expired=False):
        with self._mutex:
            return self._rpc("autotype.matches", title=title, match_title=match_title,
                             match_url=match_url, hide_expired=hide_expired)["matches"]

    def autotype_search(self, query, title, *, all_entries=False, match_title=True, match_url=True, hide_expired=False):
        with self._mutex:
            if not {"autotype-search", "autotype-display"} <= self.capabilities:
                raise VaultError("Update the native engine before displaying Auto-Type search results.")
            data = self._rpc("autotype.search", query=query, title=title, all=all_entries,
                             match_title=match_title, match_url=match_url, hide_expired=hide_expired)
            if (not isinstance(data, dict) or set(data) != {"matches"} or not isinstance(data["matches"], list)
                    or any(not isinstance(item, dict) or set(item) != {"entry", "sequence", "group", "title", "username"}
                           or any(not isinstance(value, str) for value in item.values()) for item in data["matches"])):
                raise VaultError("The engine returned invalid Auto-Type search results.")
            return data["matches"]

    def autotype_prepare(self, entry, target, sequence="", delay=25, start_delay=500, *, field=None):
        with self._mutex:
            self._entry(entry)
            if field is not None and "autotype-fields" not in self.capabilities:
                raise VaultError("Update the native engine before using field-only Auto-Type actions.")
            return self._rpc("autotype.prepare", entry=entry.uuid, sequence=sequence, delay=delay,
                             start_delay=start_delay, **({"field": field} if field is not None else {}), **target)

    def autotype_finish(self, token, pick=(), approved=False):
        with self._mutex:
            return self._rpc("autotype.finish", token=token, pick=list(pick), approved=approved)

    def keeshare_identity(self, path, operation="read", revision="", signer=""):
        with self._mutex:
            if self.unlocked:
                raise VaultError("Use a separate helper for KeeShare identity settings.")
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if "keeshare-identity" not in self.capabilities:
                raise VaultError("Update the native engine before managing the KeeShare identity.")
            data = self._rpc("keeshare.identity", identity=str(path), operation=operation,
                             revision=revision, signer=signer, _timeout=120)
            if (not isinstance(data, dict) or set(data) != {"exists", "signer", "fingerprint", "revision"}
                    or type(data["exists"]) is not bool
                    or any(not isinstance(data[key], str) for key in ("signer", "fingerprint", "revision"))
                    or (data["exists"] and (not data["fingerprint"] or not re.fullmatch("[0-9a-f]{64}", data["revision"])))
                    or (not data["exists"] and (data["revision"] != "missing" or data["signer"] or data["fingerprint"]))):
                raise VaultError("The engine returned invalid KeeShare identity information.")
            return data

    def keeshare_configure(self, directory, options):
        with self._mutex:
            return self._rpc("keeshare.configure", identity=str(Path(directory) / "keyslot" / "keeshare-identity.xml"), **options)

    def keeshare_settings(self, group):
        with self._mutex:
            return self._rpc("keeshare.settings", group=group)

    def save_keeshare_settings(self, group, **options):
        with self._mutex:
            return self._snapshot_call("keeshare.settings.save", group=group, **options)

    def keeshare_sync(self, force=False):
        with self._mutex:
            result = self._rpc("keeshare.sync", force=force)
            self._set_snapshot(result.pop("snapshot"))
            return result

    def secret_settings(self):
        with self._mutex:
            return self._rpc("secret.settings")

    def save_secret_settings(self, group):
        with self._mutex:
            return self._snapshot_call("secret.settings.save", group=group)

    def secret_request(self, operation, **params):
        """Private provider adapter; native code checks the exposed group and peer grants."""
        if operation not in {"configure", "drop-peer", "info", "search", "get", "prepare", "finish", "mutate"}:
            raise VaultError("Unknown Secret Service operation.")
        with self._mutex:
            result = self._rpc("secret." + operation, **params)
            if isinstance(result, dict) and "snapshot" in result:
                self._set_snapshot(result.pop("snapshot"))
            return result

    def ssh_key_info(self, entry, decrypt=False):
        with self._mutex:
            self._entry(entry)
            return self._rpc("ssh.key_info", entry=entry.uuid, decrypt=decrypt)

    def ssh_generation_info(self, entry):
        with self._mutex:
            self._entry(entry)
            if "ssh-key-generation" not in self.capabilities:
                raise VaultError("Update the native engine before generating SSH keys.")
            return self._rpc("ssh.generate.info", entry=entry.uuid)

    def generate_ssh_key(self, entry, **options):
        with self._mutex:
            self._entry(entry)
            if "ssh-key-generation" not in self.capabilities:
                raise VaultError("Update the native engine before generating SSH keys.")
            return self._rpc("ssh.generate.prepare", entry=entry.uuid, **options)

    def save_generated_ssh_key(self, entry, token):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("ssh.generate.save", entry=entry.uuid, token=token)

    def cancel_generated_ssh_key(self, token):
        with self._mutex:
            return self._rpc("ssh.generate.cancel", token=token)

    def save_ssh_settings(self, entry, **options):
        with self._mutex:
            self._entry(entry)
            result = self._rpc("ssh.settings.save", entry=entry.uuid, **options)
            self.ssh_warning = result.get("ssh_warning")
            return self._set_snapshot(result)

    def ssh_prepare(self, entry):
        with self._mutex:
            self._entry(entry)
            self._ssh_ready()
            return self._rpc("ssh.prepare", entry=entry.uuid)

    def ssh_add(self, token, approved=False):
        with self._mutex:
            self._ssh_ready()
            return self._rpc("ssh.add", token=token, approved=approved)

    def ssh_owned(self):
        with self._mutex:
            self._ssh_ready()
            return self._rpc("ssh.owned")["keys"]

    def ssh_remove(self, fingerprint, socket):
        with self._mutex:
            self._ssh_ready()
            return self._rpc("ssh.remove", fingerprint=fingerprint, socket=socket)

    def ssh_agent_keys(self):
        with self._mutex:
            self._ssh_ready()
            return self._rpc("ssh.agent.list")

    def ssh_review_removal(self, fingerprints=(), clear=False):
        with self._mutex:
            self._ssh_ready()
            return self._rpc("ssh.removal.prepare", fingerprints=list(fingerprints), clear=clear)

    def ssh_finish_removal(self, token, approved=False):
        with self._mutex:
            self._ssh_ready()
            return self._rpc("ssh.removal.finish", token=token, approved=approved)

    def passkey_list(self):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            return [(entry, self.passkey_info(entry)) for entry in self.snapshot.entries if entry.passkey and not entry.recycled]

    def inspect_passkey(self, source):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            return self._rpc("passkey.inspect", source=str(Path(source).expanduser().resolve(strict=True)))

    def import_passkey(self, source, source_fingerprint, entry=None, group="", replace=False):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            if entry:
                self._entry(entry)
            return self._snapshot_call("passkey.import", source=str(Path(source).expanduser().resolve(strict=True)),
                source_fingerprint=source_fingerprint, entry=entry.uuid if entry else "", group=group, replace=replace)

    def remove_passkey(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("passkey.remove", entry=entry.uuid)

    def export_passkey(self, entry, destination, overwrite=False):
        with self._mutex:
            self._entry(entry)
            if Path(destination).expanduser().resolve() == self.path:
                raise VaultError("An unencrypted passkey cannot replace the database.")
            self._commit_output(destination, lambda stage: self._rpc("passkey.export", entry=entry.uuid, path=str(stage)), overwrite)

    def plan_passkey_exports(self, entries, folder):
        with self._mutex:
            folder = Path(folder).expanduser().resolve(strict=True)
            if not folder.is_dir() or not entries or len({entry.uuid for entry in entries}) != len(entries):
                raise VaultError("Choose passkeys and an export folder.")
            used, plan = set(), []
            for entry in entries:
                name = Path(self.passkey_info(entry)["filename"]).name
                candidate, suffix = name, 1
                while candidate.casefold() in used:
                    suffix += 1
                    candidate = Path(name).stem + f" ({suffix}).passkey"
                used.add(candidate.casefold())
                plan.append((entry, folder / candidate))
            return plan

    def export_passkeys(self, plan, overwrite=False):
        with self._mutex:
            if not plan or len({Path(path).expanduser().absolute() for _, path in plan}) != len(plan):
                raise VaultError("Choose distinct destinations for the selected passkeys.")
            # Preflight every source/destination before publishing any private-key files.
            for entry, path in plan:
                self._entry(entry)
                if not entry.passkey or Path(path).expanduser().resolve() == self.path or (os.path.lexists(path) and not overwrite):
                    raise VaultError("An export destination already exists or would replace the database.")
            saved = 0
            try:
                for entry, path in plan:
                    self.export_passkey(entry, path, overwrite)
                    saved += 1
            except (OSError, VaultError) as exc:
                raise VaultError(f"Exported {saved} of {len(plan)} passkeys. Completed export files remain in the chosen folder. {exc}") from exc
            return saved

    def browser_finish_passkey(self, token, approved=False, entry="", group="", replace=False):
        with self._mutex:
            result = self._rpc("browser.passkey.finish", token=token, approved=approved, entry=entry, group=group, replace=replace)
            self._snapshot_call("snapshot")
            return result

    def browser_totp(self, identifier, key, entry):
        with self._mutex:
            return self._rpc("browser.totp", id=identifier, key=key, entry=entry)

    def browser_prepare_delete(self, identifier, key, entry):
        with self._mutex:
            return self._rpc("browser.prepare_delete", id=identifier, key=key, entry=entry)

    def browser_delete(self, token, approved=False):
        with self._mutex:
            changed = self._rpc("browser.delete", token=token, approved=approved)
            if changed:
                self._snapshot_call("snapshot")
            return changed

    def browser_groups(self, identifier, key):
        with self._mutex:
            return self._rpc("browser.groups", id=identifier, key=key)

    def browser_entries(self, identifier, key, *, allowed=False):
        with self._mutex:
            if "browser-entry-list" not in self.capabilities:
                raise EngineError("listing_denied", "Update the native engine before listing browser entries.")
            return self._rpc("browser.entries", id=identifier, key=key, allowed=allowed)

    def browser_prepare_group(self, identifier, key, name):
        with self._mutex:
            return self._rpc("browser.prepare_group", id=identifier, key=key, name=name)

    def browser_create_group(self, token, approved=False):
        with self._mutex:
            result = self._rpc("browser.create_group", token=token, approved=approved)
            self._snapshot_call("snapshot")
            return result

    def browser_associations(self):
        with self._mutex:
            return self._rpc("browser.associations")

    def _browser_options_target(self, entry, group):
        if not self.unlocked or "browser-options" not in self.capabilities:
            raise VaultError("Unlock a vault with the updated native engine before editing browser settings.")
        if (entry is None) == (group is None):
            raise VaultError("Choose an entry or group for browser settings.")
        if entry is not None:
            self._entry(entry)
            return {"entry": entry.uuid}
        if not any(item.identity == group and item.addressable and not item.recycled for item in self.snapshot.groups):
            raise VaultError("The selected group is unavailable.")
        return {"group": group}

    def browser_options(self, entry=None, group=None):
        with self._mutex:
            return self._rpc("browser.options", **self._browser_options_target(entry, group))

    def save_browser_options(self, entry=None, group=None, *, revision, values, restriction=None):
        with self._mutex:
            params = dict(revision=revision, values=values, **self._browser_options_target(entry, group))
            if restriction is not None:
                params["restriction"] = restriction
            return self._snapshot_call("browser.options.save", **params)

    def browser_authenticate(self, identifier, key):
        with self._mutex:
            return self._rpc("browser.authenticate", id=identifier, key=key)

    def browser_associate(self, identifier, key, replace=False):
        with self._mutex:
            return self._snapshot_call("browser.associate", id=identifier, key=key, replace=replace)

    def browser_revoke(self, identifier):
        with self._mutex:
            return self._snapshot_call("browser.revoke", id=identifier)

    def browser_trust(self, identifier, revision, trusted):
        with self._mutex:
            return self._snapshot_call("browser.trust", id=identifier, revision=revision, trusted=trusted)

    def browser_prepare_save(self, identifier, key, url, login, password, submit_url="", entry="", group_uuid=""):
        with self._mutex:
            return self._rpc("browser.prepare_save", id=identifier, key=key, url=url, login=login, password=password,
                             submit_url=submit_url, entry=entry, group_uuid=group_uuid)

    def browser_save(self, token, approved=False, group=""):
        with self._mutex:
            changed = self._rpc("browser.save", token=token, approved=approved, group=group)
            if changed:
                self._snapshot_call("snapshot")
            return changed

    def browser_save_details(self, token, approved=False, group=""):
        with self._mutex:
            if "browser-save-result" not in self.capabilities:
                raise VaultError("Update the native engine before using browser-requested icons.")
            result = self._rpc("browser.save.details", token=token, approved=approved, group=group)
            if result["changed"]:
                self._snapshot_call("snapshot")
            return result

    def browser_lookup(self, identifier, key, url, submit_url="", **options):
        with self._mutex:
            return self._rpc("browser.lookup", id=identifier, key=key, url=url, submit_url=submit_url, **options)

    def browser_release(self, token, entries, approved=False, remember=False, trust=False):
        with self._mutex:
            if trust and "browser-trust" not in self.capabilities:
                raise VaultError("Update the native engine before trusting a browser connection.")
            result = self._rpc("browser.release", token=token, entries=entries, approved=approved, remember=remember, trust=trust)
            if remember or trust:
                self._snapshot_call("snapshot")
            return result

    def browser_deny(self, token, entries, remember=False):
        with self._mutex:
            result = self._rpc("browser.release", token=token, entries=entries, deny=True, remember=remember)
            if remember:
                self._snapshot_call("snapshot")
            return result

    def save_settings(self, **changes):
        with self._mutex:
            return self._snapshot_call("database.settings.save", **changes) if changes else self.snapshot

    def benchmark_kdf(self, milliseconds=1000, **parameters):
        with self._mutex:
            return self._rpc("database.kdf.benchmark", milliseconds=milliseconds, **parameters)

    def change_key(self, **changes):
        with self._mutex:
            if not changes:
                return self.snapshot
            result = self._snapshot_call("database.key.change", **changes)
            self.forget_system_auth()
            return result

    def merge(self, source, password="", keyfile="", yubikey="", no_password=False, same_credentials=False):
        with self._mutex:
            return self._snapshot_call("database.merge", path=str(Path(source).expanduser().resolve(strict=True)),
                password=password, keyfile=keyfile, yubikey=yubikey, no_password=no_password,
                same_credentials=same_credentials)

    def remote_locations(self, name=None):
        with self._mutex:
            if "remote-sync" not in self.capabilities:
                raise VaultError("Update the native engine before configuring remote synchronization.")
            return self._rpc("remote.list") if name is None else self._rpc("remote.get", name=name)

    def object_properties(self, target, query="", offset=0):
        with self._mutex:
            if "object-properties" not in self.capabilities:
                raise VaultError("Update the native engine before inspecting entry or group properties.")
            return self._rpc("properties.info", **target, query=query, offset=offset)

    def plugin_value(self, target, name, revision, path=None):
        with self._mutex:
            value = self._rpc("properties.value", **target, name=name, revision=revision,
                              **({"path": str(path)} if path is not None else {}))
            return value.get("value", "") if path is None else value

    def review_plugin_removal(self, target, names, revision):
        with self._mutex:
            return self._rpc("properties.review", **target, names=list(names), revision=revision)

    def remove_plugin_data(self, token):
        with self._mutex:
            return self._snapshot_call("properties.remove", token=token, approved=True)

    def cancel_plugin_removal(self, token):
        with self._mutex:
            return self._rpc("properties.cancel", token=token)

    def remote_edit(self, original, revision, profile=None):
        with self._mutex:
            return self._snapshot_call("remote.remove" if profile is None else "remote.save",
                                       original=original, revision=revision, **({"profile": profile} if profile is not None else {}))

    def remote_prepare(self, name, revision):
        with self._mutex:
            return self._rpc("remote.prepare", name=name, revision=revision)

    def remote_step(self, operation, token, **options):
        with self._mutex:
            try:
                result = self._rpc("remote." + operation, token=token, **options)
            except EngineError as exc:
                if operation == "merge" and options.get("credentials") and exc.code in {"key_error", "invalid_request"}:
                    return {"state": "credentials_required", "message": str(exc)}
                if operation == "merge":
                    # A transfer can fail after the local merge has already been durably saved.
                    self._snapshot_call("snapshot")
                raise
            if "snapshot" in result:
                self._set_snapshot(result.pop("snapshot"))
            return result

    def report(self, excluded=False):
        with self._mutex:
            return self._rpc("database.report", excluded=excluded)

    def edit_report(self, entries, action, revision):
        with self._mutex:
            return self._snapshot_call("database.report.edit", entries=list(entries), action=action, revision=revision)

    def prepare_hibp(self, mode, path="", excluded=False):
        with self._mutex:
            if "hibp" not in self.capabilities:
                raise VaultError("Update the native engine before checking for exposed passwords.")
            return self._rpc("report.hibp.prepare", mode=mode, path=str(path), excluded=excluded)

    def step_hibp(self, token):
        with self._mutex:
            return self._rpc("report.hibp.step", token=token)

    def cancel_hibp(self, token):
        with self._mutex:
            if self.unlocked:
                self._rpc("report.hibp.cancel", token=token)

    def _commit_output(self, destination, producer, overwrite=False):
        destination = Path(destination).expanduser().absolute()
        # The parent owns staging so lock/cancellation cleans up even if the helper is killed.
        with tempfile.TemporaryDirectory(prefix=".keyslot-output-", dir=destination.parent) as directory:
            stage = Path(directory) / "output"
            if producer(stage) is not True:
                raise VaultError("The engine did not confirm that the output was written completely.")
            if self._cancelled.is_set():
                raise VaultError("The operation was cancelled before saving its output.")
            stage.chmod(0o600)
            with stage.open("rb") as stream:
                os.fsync(stream.fileno())
            if overwrite:
                os.replace(stage, destination)
            else:
                os.link(stage, destination)
            descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def export_database(self, destination, format="xml", overwrite=False):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            if Path(destination).expanduser().resolve() == self.path:
                raise VaultError("An unencrypted export cannot replace the database.")
            self._commit_output(destination, lambda stage: self._rpc("database.export", path=str(stage), format=format), overwrite)

    def save_copy(self, destination, overwrite=False):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            if Path(destination).expanduser().resolve() == self.path:
                raise VaultError("Choose a different destination for the database copy.")
            self._commit_output(destination, lambda stage: self._rpc("database.copy", path=str(stage)), overwrite)

    def generate_keyfile(self, destination):
        with self._mutex:
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            self._commit_output(destination, lambda stage: self._rpc("keyfile.generate", path=str(stage)))

    def attribute(self, entry, name="Password", totp=False):
        with self._mutex:
            self._entry(entry)
            return self._rpc("attribute", entry=entry.uuid, name=name, totp=totp)

    def preview_fields(self, entry, fields=()):
        with self._mutex:
            self._entry(entry)
            if "entry-preview" not in self.capabilities:
                raise VaultError("Update the native engine before loading entry previews.")
            return self._rpc("entry.preview", entry=entry.uuid, fields=list(fields))

    def editable_fields(self, entry):
        with self._mutex:
            self._entry(entry)
            return {key: self._rpc("attribute", entry=entry.uuid, name=key, resolve=False)
                    for key in ("UserName", "URL", "Notes")}

    def attribute_info(self, entry, name, *, review=False):
        with self._mutex:
            self._entry(entry)
            return self._rpc("attribute.info", entry=entry.uuid, name=name, **({"review": True} if review else {}))

    def attribute_suggestions(self, entry, query="", offset=0):
        with self._mutex:
            self._entry(entry)
            if "attribute-suggestions" not in self.capabilities:
                raise VaultError("Update the native engine before using attribute-name suggestions.")
            return self._rpc("attribute.suggestions", entry=entry.uuid, query=query, offset=offset)

    def totp_settings(self, entry, revision=None):
        with self._mutex:
            self._entry(entry)
            return self._rpc("totp.settings", entry=entry.uuid, **({"revision": revision} if revision is not None else {}))

    def totp_config(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._rpc("totp.config", entry=entry.uuid)

    def save_totp(self, entry, revision, **settings):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("totp.save", entry=entry.uuid, revision=revision, **settings)

    def remove_totp(self, entry, revision):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("totp.remove", entry=entry.uuid, revision=revision)

    def totp_sample(self, entry, at=None):
        with self._mutex:
            self._entry(entry)
            return self._rpc("totp.sample", entry=entry.uuid, **({"at": at} if at is not None else {}))

    def copy_totp(self, entry, combined=False):
        with self._mutex:
            self._entry(entry)
            return self._rpc("totp.copy", entry=entry.uuid, combined=combined)

    def totp_qr(self, entry):
        import base64
        with self._mutex:
            self._entry(entry)
            result = self._rpc("totp.qr", entry=entry.uuid)
            result["png"] = base64.b64decode(result["png"], validate=True)
            return result

    def export_totp_qr(self, entry, revision, destination):
        with self._mutex:
            self._entry(entry)
            if Path(destination).expanduser().resolve() == self.path:
                raise VaultError("Choose an output file different from the open database.")
            self._commit_output(destination, lambda stage: self._rpc("totp.qr", entry=entry.uuid,
                revision=revision, path=str(stage)))

    def set_totp(self, entry, uri):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("entry.save", entry=entry.uuid, group=entry.group, fields={}, totp=uri)

    def save_entry(self, group, title, username, url, notes, password=None, entry=None, **advanced):
        with self._mutex:
            values = {"Title": title, "UserName": username, "URL": url, "Notes": notes}
            if password is not None:
                values["Password"] = password
            params = {"group": group, "fields": values, **advanced}
            if entry:
                self._entry(entry)
                params["entry"] = entry.uuid
            return self._snapshot_call("entry.save", **params)

    def add_group(self, parent, name):
        with self._mutex:
            return self._snapshot_call("group.save", parent=parent, name=name)

    def save_group(self, group, name, notes, parent=None, **advanced):
        with self._mutex:
            params = {"group": group, "name": name, "notes": notes, **advanced}
            if parent:
                params["parent"] = parent
            return self._snapshot_call("group.save", **params)

    def review_group_icons(self, group, scope, icon, custom_icon):
        with self._mutex:
            if "group-icon-propagation" not in self.capabilities:
                raise VaultError("Update the native engine before applying group icons to their contents.")
            return self._rpc("icons.group.review", group=group, icon_scope=scope, icon=icon, custom_icon=custom_icon)

    def cancel_group_icons(self, token):
        with self._mutex:
            return self._rpc("icons.group.cancel", token=token)

    def icons(self, offset=0):
        with self._mutex:
            return self._rpc("icons.list", offset=offset)

    def icon(self, icon=0, custom_icon=""):
        import base64
        with self._mutex:
            return base64.b64decode(self._rpc("icons.get", icon=icon, custom_icon=custom_icon), validate=True)

    def import_icon(self, source):
        source = Path(source)
        with source.open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        return self.import_icon_data(raw, source.stem)

    def import_icon_data(self, raw, name):
        import base64
        raw = _icon_bytes(raw)
        with self._mutex:
            result = self._rpc("icons.import", data=base64.b64encode(raw).decode("ascii"), name=name)
            self._set_snapshot(result["snapshot"])
            return result["icon"]

    def remove_icon(self, custom_icon):
        with self._mutex:
            return self._snapshot_call("icons.remove", custom_icon=custom_icon)

    def review_unused_icons(self, keep=()):
        with self._mutex:
            if "unused-icons" not in self.capabilities:
                raise VaultError("Update the native engine before cleaning the icon library.")
            return self._rpc("icons.unused.review", keep=list(keep))

    def remove_unused_icons(self, token):
        with self._mutex:
            return self._snapshot_call("icons.unused.remove", token=token)

    def prepare_favicon(self, url, fallback=False, path=False, timeout=10, entry="", reservation=""):
        with self._mutex:
            if "favicon" not in self.capabilities:
                raise VaultError("Update the native engine before downloading website icons.")
            if entry and "favicon-entry" not in self.capabilities:
                raise VaultError("Update the native engine before assigning downloaded entry icons.")
            parameters = dict(url=url, fallback=fallback, path=path, timeout=timeout)
            if entry:
                parameters["entry"] = entry
            if reservation:
                parameters["reservation"] = reservation
            return self._rpc("icons.favicon.prepare", **parameters)

    def step_favicon(self, token, network):
        import base64
        with self._mutex:
            result = self._rpc("icons.favicon.step", token=token, approved=True)
        if "request" not in result:
            return result
        response = network._rpc("network.icon", url=result["url"], timeout=result["timeout"])
        raw = b""
        if not response["failed"] and response["status"] == 200:
            try:
                raw = _icon_bytes(base64.b64decode(response["data"], validate=True))
            except VaultError:
                raw = b""
        with self._mutex:
            return self._rpc("icons.favicon.accept", token=token, request=result["request"],
                status=response["status"], redirect=response["redirect"], failed=response["failed"],
                data=base64.b64encode(raw).decode("ascii"))

    def finish_favicon(self, token):
        with self._mutex:
            result = self._rpc("icons.favicon.finish", token=token)
            self._set_snapshot(result["snapshot"])
            return result["icon"]

    def cancel_icon_operation(self, token):
        with self._mutex:
            if self.unlocked:
                self._rpc("icons.favicon.cancel", token=token)

    def export_icon(self, custom_icon, destination, overwrite=False):
        with self._mutex:
            if Path(destination).expanduser().resolve() == self.path:
                raise VaultError("Choose an output file different from the open database.")
            self._commit_output(destination, lambda stage: self._rpc("icons.export", custom_icon=custom_icon, path=str(stage)), overwrite)

    def recycle_group(self, group):
        with self._mutex:
            return self._snapshot_call("group.recycle", group=group)

    def review_trash(self, action, entries=(), groups=()):
        with self._mutex:
            entries = list(entries)
            for entry in entries:
                self._entry(entry)
            if "trash-review" not in self.capabilities:
                raise VaultError("Update the native engine before managing the recycle bin.")
            return self._rpc("trash.review", action=action, entries=[entry.uuid for entry in entries], groups=list(groups))

    def entry_actions_info(self):
        with self._mutex:
            if not self.unlocked or "entry-actions" not in self.capabilities:
                raise VaultError("Unlock a vault with the updated native engine before using entry actions.")
            return self._rpc("entries.actions.info")

    def review_entry_action(self, entries, **options):
        with self._mutex:
            entries = list(entries)
            for entry in entries:
                self._entry(entry)
            if "entry-actions" not in self.capabilities:
                raise VaultError("Update the native engine before using these entry actions.")
            return self._rpc("entries.actions.review", entries=[entry.uuid for entry in entries], **options)

    def apply_entry_action(self, token):
        with self._mutex:
            result = self._rpc("entries.actions.apply", token=token, approved=True)
            return self._set_snapshot(result["snapshot"]), result["created"]

    def cancel_entry_action(self, token):
        with self._mutex:
            if self.unlocked:
                self._rpc("entries.actions.cancel", token=token)

    def apply_trash(self, token, destination=""):
        with self._mutex:
            return self._snapshot_call("trash.apply", token=token, destination=destination)

    def cancel_trash(self, token):
        with self._mutex:
            if self.unlocked:
                self._rpc("trash.cancel", token=token)

    def delete_entry(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("entry.recycle", entry=entry.uuid)

    def move_entry(self, entry, destination):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("entry.restore" if entry.recycled else "entry.move", entry=entry.uuid, group=destination)

    def prepare_transfer(self, entries, move=False):
        with self._mutex:
            entries = list(entries)
            for entry in entries:
                self._entry(entry)
            if any(entry.recycled for entry in entries) and "transfer-recycled" not in self.capabilities:
                raise VaultError("Update the native engine before copying or moving recycled items.")
            return self._rpc("transfer.prepare", entries=[entry.uuid for entry in entries], move=move)

    def url_prepare(self, entry, override=False):
        with self._mutex:
            self._entry(entry)
            if "entry-urls" not in self.capabilities:
                raise VaultError("Update the native engine before opening entry URLs.")
            return self._rpc("url.prepare", entry=entry.uuid, override=override)

    def url_finish(self, token, approved=False, remember=False, destination=None):
        with self._mutex:
            value = self._rpc("url.finish", token=token, approved=approved, remember=remember, destination=destination or {})
            if "snapshot" in value:
                self._set_snapshot(value.pop("snapshot"))
            return value

    def url_cancel(self, token):
        with self._mutex:
            return self._rpc("url.cancel", token=token)

    def url_forget(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("url.forget", entry=entry.uuid)

    def url_offer(self, ticket):
        with self._mutex:
            if self.unlocked:
                raise VaultError("The destination vault is already unlocked.")
            self._stop()
            self.snapshot = None
            self.path = Path(ticket["path"])
            self._start()
            try:
                return self._rpc("url.offer", **ticket)
            except Exception:
                self.lock()
                raise

    def url_accept(self, envelope):
        with self._mutex:
            if self.unlocked:
                raise VaultError("The destination vault is already unlocked.")
            try:
                return self._snapshot_call("url.accept", token=envelope["token"], message=envelope["message"])
            except Exception:
                self.lock()
                raise

    def prepare_group_transfer(self, group, move=False):
        with self._mutex:
            if not self.unlocked:
                raise VaultError("Unlock a database first.")
            matches = [item for item in self.snapshot.groups if item.identity == group]
            if len(matches) != 1:
                raise VaultError("The selected group is unavailable.")
            if matches[0].recycled and "transfer-recycled" not in self.capabilities:
                raise VaultError("Update the native engine before copying or moving recycled groups.")
            return self._rpc("transfer.prepare", source_group=group, move=move)

    def recycle_entries(self, entries):
        with self._mutex:
            entries = list(entries)
            for entry in entries:
                self._entry(entry)
            return self._snapshot_call("entries.recycle", entries=[entry.uuid for entry in entries])

    def listen_transfer(self, source, group, position=-1):
        with self._mutex:
            if any(item.identity == group and item.recycled for item in self.snapshot.groups) and "transfer-recycled" not in self.capabilities:
                raise VaultError("Update the native engine before transferring into the recycle bin.")
            if position >= 0 and "transfer-position" not in self.capabilities:
                raise VaultError("Update the native engine before choosing a group insertion position.")
            return self._rpc("transfer.listen", source_pid=source["pid"], source_token=source["token"],
                             source_path=source["path"], entries=source["ids"], groups=source["groups"],
                             source_group=source["source_group"], group=group, position=position)

    def transfer_request(self, operation, **params):
        if operation not in ("send", "receive", "finish", "local", "cancel"):
            raise ValueError("Unknown entry transfer operation")
        with self._mutex:
            result = self._rpc("transfer." + operation, _timeout=360 if operation in ("send", "receive") else None, **params)
            if isinstance(result, dict) and "snapshot" in result:
                self._set_snapshot(result.pop("snapshot"))
            return result

    def set_attribute(self, entry, name, value, protected=True, *, original_name=None, revision=None):
        with self._mutex:
            self._entry(entry)
            options = {}
            if original_name is not None:
                options["original_name"] = original_name
            if revision is not None:
                options["revision"] = revision
            return self._snapshot_call("attribute.save", entry=entry.uuid, name=name, value=value, protected=protected, **options)

    def remove_attribute(self, entry, name, *, revision=None):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("attribute.remove", entry=entry.uuid, name=name,
                                       **({"revision": revision} if revision is not None else {}))

    def history(self, entry):
        with self._mutex:
            self._entry(entry)
            return self._rpc("history", entry=entry.uuid)

    def compare_history(self, entry, left, right, revision):
        with self._mutex:
            self._entry(entry)
            return self._rpc("history.compare", entry=entry.uuid, left=left, right=right, revision=revision)

    def history_value(self, entry, index, revision, section, key):
        with self._mutex:
            self._entry(entry)
            return self._rpc("history.value", entry=entry.uuid, index=index, revision=revision, section=section, key=key)

    def export_history_attachment(self, entry, index, revision, name, destination):
        with self._mutex:
            self._entry(entry)
            if Path(destination).expanduser().resolve() == self.path:
                raise VaultError("Choose a different destination for the attachment.")
            self._commit_output(destination, lambda stage: self._rpc("history.attachment", entry=entry.uuid,
                index=index, revision=revision, name=name, path=str(stage)))

    def clear_history(self, entry, revision):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("history.clear", entry=entry.uuid, revision=revision)

    def restore_history(self, entry, index, revision):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("history.restore", entry=entry.uuid, index=index, revision=revision)

    def remove_history(self, entry, index, revision):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("history.remove", entry=entry.uuid, index=index, revision=revision)

    def search(self, query, group="", recursive=True, case_sensitive=False, protected=False, recycled=False, force=False):
        with self._mutex:
            if (group or not recursive or case_sensitive or protected or recycled or force) and "search-options" not in self.capabilities:
                raise VaultError("Update the native engine before using search options.")
            params = dict(query=query, recursive=recursive, case_sensitive=case_sensitive,
                          protected=protected, recycled=recycled, force=force)
            if group:
                params["group"] = group
            return self._rpc("search", **params)

    def import_attachment(self, entry, source, replace=False):
        with self._mutex:
            self._entry(entry)
            name = Path(source).name
            source = Path(source).resolve(strict=True)
            if not source.is_file():
                raise VaultError("Choose a regular attachment file.")
            return self._snapshot_call("attachment.import", entry=entry.uuid, name=name, source=str(source), replace=replace)

    def inspect_attachment_files(self, identifier, files):
        with self._mutex:
            if "attachment-files" not in self.capabilities:
                raise VaultError("Update the native engine before importing dropped attachment files.")
            return self._rpc("attachment.files.inspect", entry=identifier,
                             files=[{"path": str(path), "name": Path(path).name} for path in files])

    def import_attachment_files(self, identifier, review, replace=False):
        with self._mutex:
            return self._snapshot_call("attachment.files.import", entry=identifier, files=review["files"],
                                       revision=review["revision"], replace=replace)

    def remove_attachment(self, entry, name):
        with self._mutex:
            self._entry(entry)
            return self._snapshot_call("attachment.remove", entry=entry.uuid, name=name)

    def export_attachment(self, entry, name, destination):
        with self._mutex:
            self._entry(entry)
            self._commit_output(destination, lambda stage: self._rpc("attachment.export",
                entry=entry.uuid, name=name, path=str(stage)))

    def configuration(self, write, files):
        with self._mutex:
            if self.unlocked:
                raise VaultError("Use a separate helper for application configuration.")
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if "configuration" not in self.capabilities:
                raise VaultError("Update the native engine before using custom configuration files.")
            if write and any(item.get("remove") for item in files) and "configuration-reset" not in self.capabilities:
                raise VaultError("Update the native engine before resetting keyboard shortcuts.")
            return self._rpc("configuration.write" if write else "configuration.read", files=files)

    def generator_info(self):
        with self._mutex:
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if "generator-details" not in self.capabilities:
                raise VaultError("Update the native engine before using the extended password generator.")
            return self._rpc("generator.info")

    def shortcut_sequences(self, values):
        with self._mutex:
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if "shortcut-codec" not in self.capabilities:
                raise VaultError("Update the native engine before editing shared keyboard shortcuts.")
            return self._rpc("shortcuts.decode", values=list(values))

    def inspect_wordlist(self, path):
        with self._mutex:
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if "wordlist-library" not in self.capabilities:
                raise VaultError("Update the native engine before importing word lists.")
            return self._rpc("generator.wordlist.inspect", path=path)

    def password_health(self, value):
        with self._mutex:
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if "generator-details" not in self.capabilities:
                raise VaultError("Update the native engine before estimating password strength.")
            return self._rpc("password.health", value=value)

    def generate(self, length=24, passphrase=False, **options):
        with self._mutex:
            allowed = {"lowercase", "uppercase", "numbers", "symbols", "braces", "punctuation", "quotes", "dashes",
                       "math", "logograms", "extended_ascii", "every_group", "exclude_lookalike", "additional", "excluded",
                       "word_case", "separator", "wordlist", "details"}
            if set(options) - allowed:
                raise VaultError("An unsupported password generator option was supplied.")
            if self._process is None or self._process.poll() is not None:
                self._stop()
                self._start()
            if options and "generator-options" not in self.capabilities:
                raise VaultError("Update the native engine before choosing password character types.")
            if set(options) & {"word_case", "separator", "wordlist", "details"} and "generator-details" not in self.capabilities:
                raise VaultError("Update the native engine before using the extended password generator.")
            return self._rpc("generate", length=length, passphrase=passphrase, **options)


class EngineError(VaultError):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})
