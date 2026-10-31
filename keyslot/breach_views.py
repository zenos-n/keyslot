"""User-initiated HIBP checks; cancellation and failures retain clearly partial findings."""
from gi.repository import Adw, GLib, Gtk
from .core_backend import EngineError
from .reports_views import _clear


class BreachReport:
    def __init__(self, owner):
        self.owner, self.session = owner, owner.session
        self.token, self.running, self.serial, self.closed = "", False, 0, False
        self.rows = {}
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.box.append(Gtk.Label(wrap=True, xalign=0, label=(
            "Check active, nonempty passwords against Have I Been Pwned. Excluded entries follow the filter above. "
            "A match means the password appeared in breach data; it does not identify which account was breached.")))
        self.box.append(Gtk.LinkButton(uri="https://haveibeenpwned.com/Passwords", label="Have I Been Pwned", halign=Gtk.Align.START))
        actions = Gtk.Box(spacing=12, homogeneous=True)
        self.online = Gtk.Button(label="Check Online…", css_classes=["suggested-action"])
        self.offline = Gtk.Button(label="Check Offline File…")
        self.online.connect("clicked", self.confirm_online)
        self.offline.connect("clicked", lambda *_: self.session.choose_file(lambda path: self.start("offline", path)))
        actions.append(self.online)
        actions.append(self.offline)
        self.box.append(actions)
        self.box.append(Gtk.Label(wrap=True, xalign=0, css_classes=["dim-label"], label=(
            "Offline checks read an extracted HIBP SHA-1 corpus (HASH:COUNT), without connecting to the internet. "
            "The file may be sorted by hash or by count.")))
        self.status = Gtk.Label(label="No check has been run.", wrap=True, xalign=0)
        self.progress = Gtk.ProgressBar(visible=False)
        self.box.append(self.status)
        self.box.append(self.progress)
        controls = Gtk.Box(spacing=12)
        self.cancel = Gtk.Button(label="Cancel Check", visible=False)
        self.retry = Gtk.Button(label="Retry Remaining Requests", visible=False)
        self.cancel.connect("clicked", lambda *_: self.stop())
        self.retry.connect("clicked", self.resume)
        controls.append(self.cancel)
        controls.append(self.retry)
        self.box.append(controls)
        self.findings = Adw.PreferencesGroup(title="Exposed Passwords")
        self.box.append(self.findings)
        self.result_rows = []

    def set_running(self, running):
        self.running = running
        for control in (self.online, self.offline, self.owner.refresh, self.owner.excluded, self.owner.content):
            control.set_sensitive(not running)
        self.cancel.set_visible(running)
        self.progress.set_visible(running)
        if running:
            self.retry.set_visible(False)

    def confirm_online(self, *_):
        if self.closed or self.session.busy or self.running:
            return
        alert = Adw.AlertDialog(heading="Check Passwords Online?", body=(
            "Keyslot will contact api.pwnedpasswords.com over HTTPS. The service receives your IP address and the first five "
            "characters of each password's SHA-1 hash. Padded responses are matched inside the native vault helper. "
            "Passwords, full hashes, usernames and entry URLs are not sent. This permission applies only to this check."))
        alert.add_response("cancel", "Cancel")
        alert.add_response("check", "Check Online")
        alert.set_default_response("cancel")
        alert.set_close_response("cancel")
        alert.set_response_appearance("check", Adw.ResponseAppearance.SUGGESTED)
        alert.connect("response", lambda _alert, response: self.start("online") if response == "check" else None)
        self.session.present_dialog(alert)

    def start(self, mode, path=""):
        if self.closed or self.session.busy or self.running:
            return
        self.release()
        self.serial += 1
        serial = self.serial
        self.rows.clear()
        self.render()
        self.progress.set_fraction(0)
        self.status.set_label("Preparing password check…")
        self.set_running(True)
        excluded = self.owner.excluded.get_active()
        def ready(data):
            if self.closed or serial != self.serial:
                self.release(data["token"])
                return
            self.token = data["token"]
            self.next(serial)
        def failed(message):
            if not self.closed and serial == self.serial:
                self.set_running(False)
                self.status.set_label("Check not completed. " + message)
        if not self.session.run_job(lambda: self.session.vault.prepare_hibp(mode, path, excluded), ready, failed):
            self.set_running(False)
            self.status.set_label("The vault is busy. Start the check again.")

    def next(self, serial):
        if self.closed or serial != self.serial or not self.running:
            return False
        if self.session.busy:
            GLib.timeout_add(150, self.next, serial)
            return False
        token = self.token
        def operation():
            try:
                return self.session.vault.step_hibp(token)
            except EngineError as error:
                return {"error": str(error), "retryable": error.code == "report_network"}
        def ready(data):
            if self.closed or serial != self.serial:
                return
            if "error" in data:
                self.set_running(False)
                self.status.set_label("Incomplete check. " + data["error"])
                self.retry.set_visible(data["retryable"])
                return
            for item in data["rows"]:
                self.rows[item["uuid"]] = item
            self.render()
            fraction = data["position"] / data["bytes"] if data["bytes"] else data["done"] / data["total"] if data["total"] else 1
            self.progress.set_fraction(min(1, fraction))
            if data["complete"]:
                self.token = ""
                self.set_running(False)
                result = ("No eligible passwords were checked." if not data["checked"] else
                    f"{len(self.rows)} entries have exposed passwords." if self.rows else "No exposed passwords found among the checked entries.")
                result += f" Checked {data['checked']} entries."
                if data["skipped"]:
                    result += f" {data['skipped']} entries could not be checked because of unresolved references or ambiguous identifiers."
                self.status.set_label(result)
            else:
                self.status.set_label(f"Checking… {fraction:.0%} complete. {len(self.rows)} exposed entries found so far; results are incomplete.")
                GLib.idle_add(self.next, serial)
        def failed(message):
            if not self.closed and serial == self.serial:
                self.set_running(False)
                self.status.set_label("Incomplete check. " + message)
        if not self.session.jobs.run(operation, ready, failed, interactive=False):
            GLib.timeout_add(150, self.next, serial)
        return False

    def resume(self, *_):
        if self.closed or self.running or not self.token:
            return
        self.session.touch()
        self.set_running(True)
        self.status.set_label("Continuing incomplete check…")
        self.next(self.serial)

    def release(self, token=None):
        if token is None:
            token, self.token = self.token, ""
        if token and not self.session.jobs.closed and self.session.vault.unlocked:
            self.session.jobs.run(lambda: self.session.vault.cancel_hibp(token), failed=lambda _message: None, interactive=False)

    def stop(self):
        self.serial += 1
        self.release()
        self.set_running(False)
        self.retry.set_visible(False)
        self.status.set_label("Cancelled. Any findings shown are partial; the check was not completed.")

    def reset(self):
        self.stop()
        self.rows.clear()
        self.render()
        self.status.set_label("No check has been run for this report.")

    def close(self):
        if self.closed:
            return
        self.stop()
        self.closed = True
        self.rows.clear()
        self.status.set_label("")
        self.render()
        _clear(self.box)

    def render(self):
        for row in self.result_rows:
            self.findings.remove(row)
        self.result_rows.clear()
        for item in sorted(self.rows.values(), key=lambda value: value["count"], reverse=True):
            row = Adw.ActionRow(title=item["title"] or "Untitled Entry", subtitle=f"{int(item['count']):,} recorded exposures · {item['group']}",
                                use_markup=False, activatable=True)
            row.connect("activated", lambda *_args, item=item: self.owner.open_entry(item))
            self.findings.add(row)
            self.result_rows.append(row)
