"""Peer-owned Secret Service prompts, presented one at a time in GTK."""
from .i18n import tr as _tr
import time
import uuid
from pathlib import Path
from gi.repository import Adw, GLib
from .backend import VaultError
from .secret_interfaces import PREFIX, ROOT


class SecretPrompt:
    def __init__(self, service, peer, kind, values):
        self.service, self.peer, self.kind, self.values = service, peer, kind, values
        self.path = ROOT + "/prompt/" + uuid.uuid4().hex
        self.peer_identity = service.peers[peer]
        self.policy = service.instance
        self.expires = time.monotonic() + 120
        self.started = self.finished = self.busy = False
        self.stage = "new"
        self.dialog = self.waiting = None
        self.prepared = []
        self.contexts = []
        self.unlock_queue = []
        self.after_unlock = None
        self.created_session = None

    def valid(self):
        return (not self.finished and not self.service.closed and self.service.instance == self.policy
                and self.service.peers.get(self.peer) is self.peer_identity
                and time.monotonic() < self.expires)

    def start(self):
        if self.started or self.finished:
            return
        self.started = True
        if getattr(self.service, "active_prompt", None) is None:
            self.service.active_prompt = self
            self._begin()

    def check(self):
        if self.finished:
            return
        if not self.valid():
            self.complete(True)
            return
        if not self.started or self.busy or getattr(self.service, "active_prompt", None) is not self:
            return
        try:
            for collection, context in self.contexts:
                self.service._valid_vault(collection, context)
        except VaultError:
            self.complete(True)
            return
        if self.waiting:
            session = self.waiting
            if session.jobs.closed or session not in self.service.app.sessions:
                self.complete(True)
            elif not session.jobs.busy:
                if session.vault.unlocked:
                    self.waiting = None
                    self._unlock_next()
                elif not session.dialogs and not session.file_requests:
                    self.complete(True)
        elif self.stage in ("new-database", "open-database"):
            session = self.created_session
            if session not in self.service.app.sessions or session.jobs.closed:
                self.complete(True)
            elif not session.jobs.busy:
                if session.vault.unlocked:
                    if self.stage == "new-database":
                        self._expose_created()
                    else:
                        self._search_ready()
                elif not session.dialogs and not session.file_requests:
                    self.complete(True)

    def _parent(self, collection=None):
        app = self.service.app
        session = collection.session if collection else (app.active_session or app.new_window())
        if session.jobs.closed or session not in app.sessions:
            raise VaultError("The Secret Service vault was closed.")
        app.select_session(session)
        return session

    def _review(self, heading, body, callback, *, access=False, destructive=False, collection=None):
        if not self.valid():
            self.complete(True)
            return
        session = self._parent(collection)
        dialog = Adw.AlertDialog(heading=heading, body=body, body_use_markup=False)
        self.dialog = dialog
        dialog.add_response("deny", _tr("Deny"))
        dialog.add_response("allow", _tr("Allow Once") if access else _tr("Continue"))
        if access:
            dialog.add_response("remember", _tr("Allow Until Client Disconnects"))
        dialog.set_default_response("deny")
        dialog.set_close_response("deny")
        dialog.set_response_appearance("allow", Adw.ResponseAppearance.DESTRUCTIVE if destructive else Adw.ResponseAppearance.SUGGESTED)
        def response(_dialog, choice):
            if self.dialog is dialog:
                self.dialog = None
            if not self.valid():
                self.complete(True)
            elif choice == "deny":
                self.complete(True)
            else:
                callback(choice == "remember")
        dialog.connect("response", response)
        session.present_dialog(dialog)

    def _job(self, operation, done):
        if not self.valid():
            self.complete(True)
            return
        self.busy = True
        contexts = list(self.contexts)
        created = self.created_session if self.stage == "new-database" else None
        created_context = (created.epoch, created.vault.identity, created.vault.generation) if created else None
        def valid():
            if not self.valid():
                raise VaultError("This Secret Service prompt was cancelled.")
            for collection, context in contexts:
                self.service._valid_vault(collection, context)
            if created and (created.jobs.closed or not created.vault.unlocked
                    or created_context != (created.epoch, created.vault.identity, created.vault.generation)):
                raise VaultError("The new collection was locked or closed before setup completed.")
            wire_session = self.values.get("wire_session")
            if wire_session and self.service.sessions.get(wire_session.path) is not wire_session:
                raise VaultError("The client closed its Secret Service session.")
        def perform():
            valid()
            return operation()
        future = self.service.executor.submit(perform)
        def completed():
            self.busy = False
            if not self.valid():
                self.complete(True)
                return False
            try:
                valid()
                done(future.result())
            except Exception as exc:
                self._failed(exc)
            return False
        future.add_done_callback(lambda *_: GLib.idle_add(completed))

    def _failed(self, error):
        message = str(error) if isinstance(error, VaultError) else "The Secret Service operation could not be completed."
        session = self.values.get("collection")
        session = session.session if session else self.service.app.active_session
        self.complete(True)
        if session and not session.jobs.closed:
            session.error(message)

    def _begin(self):
        try:
            self.stage = "running"
            if self.kind == "create-collection":
                label = self.values["label"][:160]
                self._review("Create Password Collection?", self.service.peer_label(self.peer)
                    + f" wants a new encrypted vault named {label}. Choose its file and master credential next.",
                    lambda _: self._new_database())
            elif self.kind == "close-collection":
                collection = self.values["collection"]
                self._review("Close Password Collection?", self.service.peer_label(self.peer)
                    + " wants to close this vault. Its encrypted database file will be kept.",
                    lambda _: self._close_collection(collection), destructive=True, collection=collection)
            elif self.kind == "unlock":
                collections = []
                for _, kind, target in self.values["targets"]:
                    collection = target if kind == "collection" else target[0]
                    if collection not in collections:
                        collections.append(collection)
                self._ensure_unlocked(collections, self._prepare_access)
            elif self.kind == "search":
                collection = self.values["collection"]
                collection = collection or self.service.collections.get(self.service.app.active_session) or next(iter(self.service.collections.values()), None)
                if collection:
                    self._ensure_unlocked([collection], self._search_ready)
                else:
                    self.created_session = self.service.app.new_window()
                    self.stage = "open-database"
                    self.created_session.choose_database()
            else:
                self._ensure_unlocked([self.values["collection"]], self._prepare_change)
        except Exception as exc:
            self._failed(exc)

    def _ensure_unlocked(self, collections, callback):
        self.unlock_queue = list(collections)
        self.after_unlock = callback
        self._unlock_next()

    def _unlock_next(self):
        if not self.valid():
            self.complete(True)
            return
        try:
            while self.unlock_queue:
                collection = self.unlock_queue[0]
                session = collection.session
                if self.service.collections.get(session) is not collection or session.jobs.closed:
                    raise VaultError("The Secret Service collection was closed or is no longer exposed.")
                if session.vault.unlocked:
                    self.unlock_queue.pop(0)
                    continue
                self._parent(collection)
                session._unlock_dialog(str(session.path))
                # Opening the form locks first and emits state before it exists.
                self.waiting = session
                return
            self.after_unlock()
        except Exception as exc:
            self._failed(exc)

    def _prepare_access(self):
        groups = {}
        for path, kind, target in self.values["targets"]:
            if kind == "item":
                collection, identifier = target
                groups.setdefault(collection, []).append(identifier)
        self.contexts = [(collection, self.service._context(collection)) for collection in groups]
        if not groups:
            self.complete(False, GLib.Variant("ao", [path for path, _, _ in self.values["targets"]]))
            return
        def prepare():
            result = []
            for collection, context in self.contexts:
                value = self.service._vault(collection, context, "prepare", peer=self.peer, kind="authorize", entries=groups[collection])
                result.append((collection, context, value))
            return result
        def ready(prepared):
            self.prepared = prepared
            if not self.service.options["confirm_access"]:
                self._finish_access(True)
                return
            names = [Path(collection.session.path).name[:160] + ": " + item["title"][:160]
                     for collection, _, data in prepared for item in data["items"]]
            summary = "\n".join(names[:20]) + (f"\n…and {len(names) - 20} more" if len(names) > 20 else "")
            self._review("Allow Password Access?", self.service.peer_label(self.peer) + " wants to use these exposed items:\n\n"
                         + summary + "\n\nAllow Once permits one password read and one one-time code read per item.",
                         self._finish_access, access=True, collection=prepared[0][0])
        self._job(prepare, ready)

    def _finish_access(self, remember):
        def finish():
            result = [path for path, kind, _ in self.values["targets"] if kind == "collection"]
            for collection, context, data in self.prepared:
                value = self.service._vault(collection, context, "finish", peer=self.peer, token=data["token"],
                                           approved=True, remember=remember)
                result.extend(collection.item_path(identifier) for identifier in value["entries"])
            return result
        def done(paths):
            self.prepared.clear()
            for collection, _ in self.contexts:
                for path in paths:
                    if path.startswith(collection.path + "/"):
                        self.service._notify(path, "item", {"Locked": GLib.Variant("b", False)}, self.peer)
            self.complete(False, GLib.Variant("ao", paths))
        self._job(finish, done)

    def _prepare_change(self):
        collection = self.values["collection"]
        context = self.service._context(collection)
        self.contexts = [(collection, context)]
        def prepare():
            if self.kind == "delete-item":
                args = dict(kind="delete", entry=self.values["entry"])
            else:
                secret = self.service._decode(self.values["wire"], self.values["wire_session"])
                args = dict(kind="create", label=self.values["label"], attributes=self.values["attributes"],
                    replace=self.values["replace"], value=secret["value"], content_type=secret["content_type"])
            return self.service._vault(collection, context, "prepare", peer=self.peer, **args)
        def ready(data):
            self.prepared = [(collection, context, data)]
            delete = self.kind == "delete-item"
            if not self.service.options["confirm_delete" if delete else "confirm_access"]:
                self._finish_change()
                return
            title = data["items"][0]["title"][:160]
            if delete:
                permanent = not collection.session.vault.snapshot.recycle_bin_enabled
                body = self.service.peer_label(self.peer) + f" wants to {'permanently delete' if permanent else 'recycle'} {title}."
                heading = "Delete Password Item?"
            else:
                replacing = bool(data["items"][0]["entry"])
                body = self.service.peer_label(self.peer) + f" wants to {'update' if replacing else 'create'} {title} in this exposed group."
                if replacing and data["items"][0]["new_label"] != data["items"][0]["title"]:
                    body += "\nNew label: " + data["items"][0]["new_label"][:160]
                heading = "Update Password Item?" if replacing else "Create Password Item?"
            body += "\nVault: " + Path(collection.session.path).name[:160]
            self._review(heading, body, lambda _: self._finish_change(), destructive=delete, collection=collection)
        self._job(prepare, ready)

    def _finish_change(self):
        collection, context, data = self.prepared[0]
        def finish():
            return self.service._vault(collection, context, "finish", peer=self.peer, token=data["token"], approved=True)
        def done(result):
            self.prepared.clear()
            collection.session.window.show_vault(collection.session.vault.snapshot)
            self.service.state_changed()
            value = GLib.Variant("b", True) if self.kind == "delete-item" else GLib.Variant("o", collection.item_path(result["entry"]))
            self.complete(False, value)
        self._job(finish, done)

    def _new_database(self):
        if not self.valid():
            self.complete(True)
            return
        self.created_session = self.service.app.new_window()
        self.stage = "new-database"
        self.created_session.new_database()

    def _expose_created(self):
        session = self.created_session
        generation = session.vault.generation
        def expose():
            if not self.valid() or session.jobs.closed or not session.vault.unlocked:
                raise VaultError("Collection creation was cancelled.")
            with session.vault.operation(generation):
                session.vault.save_settings(name=self.values["label"])
                return session.vault.save_secret_settings(session.vault.snapshot.root)
        def done(snapshot):
            session.window.show_vault(snapshot)
            self.service.state_changed()
            collection = self.service.collections.get(session)
            if not collection:
                raise VaultError("The new Secret Service collection could not be exposed.")
            if self.values["alias"]:
                self.service._set_alias(self.values["alias"], collection)
            self.complete(False, GLib.Variant("o", collection.path))
        self._job(expose, done)

    def _close_collection(self, collection):
        self.complete(False, GLib.Variant("b", True))
        session = collection.session
        self.service.app.close_session(session)
        session.host_window.destroy()
        self.service.state_changed()

    def _search_ready(self):
        collection, values, invocation = self.values["collection"], self.values["attributes"], self.values.pop("invocation")
        self.complete(False)
        if collection and self.service.collections.get(collection.session) is not collection:
            invocation.return_value(GLib.Variant("(ao)", ([],)))
            return
        self.service._search(self.peer, collection, values, invocation, after_unlock=True)

    def complete(self, dismissed, result=None):
        if self.finished:
            return
        self.finished = True
        if self.dialog:
            self.dialog.force_close()
            self.dialog = None
        if result is None:
            # libsecret validates the operation's result type even on dismissal.
            if self.kind == "unlock":
                result = GLib.Variant("ao", [])
            elif self.kind in ("create-item", "create-collection"):
                result = GLib.Variant("o", "/")
            else:
                result = GLib.Variant("b", False)
        self.service._emit(self.path, PREFIX + "Prompt", "Completed", "(bv)",
                           (dismissed, result), self.peer)
        self.service.prompts.pop(self.path, None)
        self.service._remove(self.path)
        invocation = self.values.pop("invocation", None)
        if invocation:
            invocation.return_value(GLib.Variant("(ao)", ([],)) if self.values.get("collection") else GLib.Variant("(aoao)", ([], [])))
        prepared, self.prepared = self.prepared, []
        if prepared and not self.service.closed:
            def cancel_prepared():
                for collection, context, data in prepared:
                    try:
                        self.service._vault(collection, context, "finish", peer=self.peer, token=data["token"], approved=False)
                    except VaultError:
                        pass
            self.service.executor.submit(cancel_prepared)
        self.values.clear()
        if getattr(self.service, "active_prompt", None) is self:
            self.service.active_prompt = None
            if not self.service.closed:
                for prompt in self.service.prompts.values():
                    if prompt.started and not prompt.finished:
                        self.service.active_prompt = prompt
                        GLib.idle_add(lambda prompt=prompt: (prompt._begin(), False)[1])
                        break
