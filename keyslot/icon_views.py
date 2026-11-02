"""Reviewed icon-library cleanup and cancellable, previewed website icon downloads."""
from .i18n import ntrf as _ntrf, tr as _tr, trf as _trf
import base64
from concurrent.futures import ThreadPoolExecutor
from gi.repository import Adw, Gdk, GdkPixbuf, GLib, Gtk
from .backend import VaultError
from .core_backend import Vault
from .database_views import _dialog


def _release(session, token):
    if not token:
        return
    epoch, identity = session.epoch, session.vault.identity
    def release():
        if (session.jobs.closed or not session.vault.unlocked or session.epoch != epoch
                or session.vault.identity is not identity):
            return False
        return not session.jobs.run(lambda: session.vault.cancel_icon_operation(token), failed=lambda _message: None, interactive=False)
    if release():
        GLib.timeout_add(100, release)


def cleanup(session, keep, done):
    if session.busy or not session.vault.unlocked:
        return
    def reviewed(data):
        token = data["token"]
        if not data["count"]:
            _release(session, token)
            session.toast(_tr("No unused icons"))
            return
        body = f"Remove {data['count']} icons unused by entries, groups, saved versions and the recycle bin? Icons selected in open editors are kept."
        if data["names"]:
            body += "\n\n" + "\n".join(name or "Custom Icon" for name in data["names"])
        if not session.vault.auto_save:
            body += "\n\nThese changes remain unsaved until you save the vault."
        alert = Adw.AlertDialog(heading=_tr("Remove Unused Icons?"), body=body, body_use_markup=False)
        alert.add_response("cancel", _tr("Cancel"))
        alert.add_response("remove", _tr("Remove"))
        alert.set_default_response("cancel")
        alert.set_close_response("cancel")
        alert.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        state = {"applied": False}
        def cancel():
            if not state["applied"]:
                _release(session, token)
            return False
        def response(_alert, answer):
            if answer == "remove":
                state["applied"] = True
                if not session.run_job(lambda: session.vault.remove_unused_icons(token), done):
                    _release(session, token)
        alert.connect("response", response)
        alert.connect("closed", lambda *_: GLib.idle_add(cancel))
        if not session.present_dialog(alert):
            cancel()
    session.run_job(lambda: session.vault.review_unused_icons(keep), reviewed)


def download(session, callback, website=""):
    if session.busy or not session.vault.unlocked:
        return
    storage = getattr(session.application.startup, "storage", None)
    try:
        settings = storage.read_icon_options() if storage else {"timeout": 10, "fallback": False}
    except (OSError, ValueError, VaultError) as error:
        session.error(str(error))
        return
    Favicon(session, callback, website, settings)


class IconWorker:
    def __init__(self, session):
        self.session, self.network, self.closed, self.serial = session, None, False, 0
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="favicon")

    def step(self, token, ready, failed):
        if self.closed:
            return
        self.serial += 1
        serial = self.serial
        network = Vault(executable=self.session.vault.executable, timeout=30)
        self.network = network
        generation, network_generation = self.session.vault.generation, network.generation
        def perform():
            try:
                with self.session.vault.operation(generation), network.operation(network_generation):
                    return self.session.vault.step_favicon(token, network)
            finally:
                network.lock()
        future = self.executor.submit(perform)
        def deliver():
            if self.network is network:
                self.network = None
            if self.closed or serial != self.serial:
                return False
            try:
                ready(future.result())
            except (VaultError, OSError, ValueError) as error:
                if not self.session.vault.unlocked:
                    self.session.jobs.lock()
                    self.session.error(str(error))
                else:
                    failed(str(error))
            except Exception:
                failed("The icon download could not be completed. Start a new download.")
            return False
        future.add_done_callback(lambda _future: GLib.idle_add(deliver))

    def cancel(self):
        self.serial += 1
        if self.network:
            self.network.cancel()

    def close(self):
        self.cancel()
        self.closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)


class Favicon:
    def __init__(self, session, callback, website, settings):
        self.session, self.callback = session, callback
        self.token, self.serial, self.closed, self.phase = "", 0, False, "idle"
        self.worker = IconWorker(session)
        self.dialog, header, box = _dialog(_tr("Download Website Icon"), width=500, height=460)
        self.options = Adw.PreferencesGroup(description=_tr("Download an icon without browser cookies or saved login credentials."))
        self.website = Adw.EntryRow(title=_tr("Website"), text=website)
        self.website.connect("entry-activated", lambda *_: self.prepare())
        self.path = Adw.SwitchRow(title=_tr("Use Website Path"), subtitle=_tr("Also try favicon.ico beside this URL's path"))
        self.fallback = Adw.SwitchRow(title=_tr("Use DuckDuckGo Icon Service"), active=settings["fallback"],
                                      subtitle=_tr("Also send the website's domain to this service"))
        self.timeout = Adw.SpinRow.new_with_range(1, 300, 1)
        self.timeout.set_title(_tr("Timeout (Seconds)"))
        self.timeout.set_value(settings["timeout"])
        for row in (self.website, self.path, self.fallback, self.timeout):
            self.options.add(row)
        box.append(self.options)
        self.preview = Gtk.Image(pixel_size=96, visible=False, halign=Gtk.Align.CENTER)
        box.append(self.preview)
        self.status = Gtk.Label(xalign=0, wrap=True)
        box.append(self.status)
        self.stop_button = Gtk.Button(label=_tr("Cancel Download"), visible=False, halign=Gtk.Align.CENTER)
        self.stop_button.connect("clicked", lambda *_: self.stop())
        box.append(self.stop_button)
        self.action = Gtk.Button(label=_tr("Review Download…"), css_classes=["suggested-action"], valign=Gtk.Align.CENTER)
        self.action.connect("clicked", lambda *_: self.finish() if self.phase == "preview" else self.prepare())
        header.pack_end(self.action)
        self.dialog._clear_sensitive_fields = self.close
        self.dialog.connect("closed", self.close)
        session.icons.manual_downloads.add(self)
        for operation in list(session.icons.downloads):
            if operation.phase != "queued":
                operation.close()
        session.present_dialog(self.dialog)

    def release(self, token=None):
        if token is None:
            token, self.token = self.token, ""
        _release(self.session, token)

    def state(self, phase):
        self.phase = phase
        self.options.set_sensitive(phase == "idle")
        self.action.set_sensitive(phase in ("idle", "preview"))
        self.action.set_label(_tr("Use Icon") if phase == "preview" else _tr("Review Download…"))
        self.stop_button.set_visible(phase in ("preparing", "review", "downloading", "preview"))
        self.stop_button.set_label(_tr("Choose Another Website") if phase == "preview" else _tr("Cancel Download"))

    def prepare(self):
        if self.closed or self.session.busy or self.phase != "idle":
            return
        self.release()
        self.serial += 1
        serial = self.serial
        self.preview.clear()
        self.preview.set_visible(False)
        self.state("preparing")
        self.status.set_label(_tr("Preparing download review…"))
        url, path, fallback, timeout = self.website.get_text(), self.path.get_active(), self.fallback.get_active(), int(self.timeout.get_value())
        def ready(data):
            if self.closed or serial != self.serial:
                self.release(data["token"])
                return
            self.token = data["token"]
            self.state("review")
            body = ("The following addresses may be contacted, along with their redirects. Embedded login details, "
                    "the entered query string and fragment are removed. The sites receive your IP address.\n\n" + "\n".join(data["urls"]))
            if data["insecure"]:
                body += "\n\nThe selected HTTP website is unencrypted."
            alert = Adw.AlertDialog(heading=_tr("Download Website Icon?"), body=body, body_use_markup=False)
            alert.add_response("cancel", _tr("Cancel"))
            alert.add_response("download", _tr("Download"))
            alert.set_default_response("cancel")
            alert.set_close_response("cancel")
            alert.set_response_appearance("download", Adw.ResponseAppearance.SUGGESTED)
            answered = {"value": False}
            def response(_alert, choice):
                answered["value"] = True
                if self.closed or serial != self.serial:
                    return
                if choice == "download":
                    self.state("downloading")
                    self.next(serial)
                else:
                    self.stop()
            def dismissed():
                if not answered["value"] and not self.closed and serial == self.serial:
                    self.stop()
                return False
            alert.connect("response", response)
            alert.connect("closed", lambda *_: GLib.idle_add(dismissed))
            if not self.session.present_dialog(alert):
                self.stop()
        def failed(message):
            if not self.closed and serial == self.serial:
                self.release()
                self.state("idle")
                self.status.set_label(message)
        if not self.session.run_job(lambda: self.session.vault.prepare_favicon(url, fallback, path, timeout), ready, failed):
            failed("The vault is busy. Try again.")

    def next(self, serial):
        if self.closed or serial != self.serial or self.phase != "downloading":
            return False
        if self.session.busy:
            GLib.timeout_add(150, self.next, serial)
            return False
        token = self.token
        def ready(data):
            if self.closed or serial != self.serial:
                return
            if data["ready"]:
                try:
                    loader = GdkPixbuf.PixbufLoader.new_with_type("png")
                    loader.write(base64.b64decode(data["preview"], validate=True))
                    loader.close()
                    self.preview.set_from_paintable(Gdk.Texture.new_for_pixbuf(loader.get_pixbuf()))
                except (ValueError, GLib.Error):
                    failed("The downloaded icon could not be previewed.")
                    return
                self.preview.set_visible(True)
                self.state("preview")
                self.status.set_label(_tr("Preview the icon, then choose Use Icon to add it to the vault. The entry or group changes when you save its editor."))
            else:
                self.status.set_label(_ntrf('Trying website icons… {count} request attempted.', 'Trying website icons… {count} requests attempted.', data['attempts']))
                GLib.idle_add(self.next, serial)
        def failed(message):
            if not self.closed and serial == self.serial:
                self.release()
                self.state("idle")
                self.status.set_label(message)
        self.status.set_label(_tr("Downloading website icon…"))
        self.worker.step(token, ready, failed)
        return False

    def finish(self):
        if self.closed or self.session.busy or self.phase != "preview":
            return
        self.state("saving")
        token = self.token
        def done(identifier):
            if self.closed:
                return
            self.token = ""
            self.session.icons.clear()
            self.session.window.show_vault(self.session.vault.snapshot)
            self.callback(identifier)
            self.dialog.close()
        def failed(message):
            if not self.closed:
                self.release()
                self.state("idle")
                self.preview.clear()
                self.preview.set_visible(False)
                self.status.set_label(message)
        if not self.session.run_job(lambda: self.session.vault.finish_favicon(token), done, failed):
            self.state("preview")

    def stop(self):
        self.serial += 1
        self.worker.cancel()
        self.release()
        self.state("idle")
        self.preview.clear()
        self.preview.set_visible(False)
        self.status.set_label(_tr("Download cancelled."))

    def close(self, *_):
        if self.closed:
            return
        self.closed = True
        self.serial += 1
        self.worker.close()
        self.session.icons.manual_downloads.discard(self)
        self.release()
        self.preview.clear()
        self.website.set_text("")
        self.status.set_label("")


class BrowserFavicon:
    """Optional post-save work; never delays or rolls back the browser's credential reply."""
    def __init__(self, session, entry, options, reservation):
        self.session, self.entry, self.options = session, entry, options
        self.reservation = reservation
        self.epoch, self.identity = session.epoch, session.vault.identity
        self.closed, self.phase, self.token = False, "queued", ""
        self.worker = IconWorker(session)
        self.timer = GLib.timeout_add(200, self.tick)
        session.icons.downloads.append(self)

    def valid(self):
        return (not self.closed and not self.session.jobs.closed and self.session.vault.unlocked
                and self.epoch == self.session.epoch and self.identity is self.session.vault.identity
                and self.session.application.startup.browser)

    def tick(self):
        if not self.valid():
            self.close()
            return False
        icons = self.session.icons
        if icons.manual_downloads or not icons.downloads or icons.downloads[0] is not self:
            return True
        if self.session.busy or self.session.dialogs or self.session.file_requests:
            return True
        if self.phase == "queued":
            self.phase = "preparing"
            def ready(data):
                if not self.valid():
                    _release(self.session, data["token"])
                    return
                self.reservation = ""
                self.token, self.phase = data["token"], "next"
            if not self.session.jobs.run(lambda: self.session.vault.prepare_favicon("", entry=self.entry, reservation=self.reservation, **self.options),
                                         ready, self.failed, interactive=False):
                self.phase = "queued"
        elif self.phase == "next":
            self.phase = "downloading"
            self.worker.step(self.token, self.received, self.failed)
        elif self.phase == "ready":
            self.phase = "saving"
            token = self.token
            if not self.session.jobs.run(lambda: self.session.vault.finish_favicon(token), self.saved, self.failed, interactive=False):
                self.phase = "ready"
        return True

    def received(self, data):
        if not self.valid():
            self.close()
            return
        self.phase = "ready" if data["ready"] else "next"

    def saved(self, _identifier):
        self.token = ""
        self.close()
        if (not self.session.jobs.closed and self.session.vault.unlocked
                and self.session.epoch == self.epoch and self.session.vault.identity is self.identity):
            self.session.icons.clear()
            self.session.window.show_vault(self.session.vault.snapshot)

    def failed(self, _message):
        if self.closed:
            return
        self.close()
        self.session.toast("Login saved; its website icon could not be downloaded")

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        self.worker.close()
        if self in self.session.icons.downloads:
            self.session.icons.downloads.remove(self)
        _release(self.session, self.token)
        _release(self.session, self.reservation)
        self.reservation = ""
        self.token = ""
