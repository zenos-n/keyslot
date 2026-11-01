"""Native TOTP setup, short-lived QR export and live views that do not reset idle lock."""
import math
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk
from .database_views import _dialog, _spin
from .passkey_views import _confirm


class LiveCode:
    def __init__(self, controller, entry, label, progress, remaining, clear=None):
        self.controller, self.session, self.entry = controller, controller.session, entry
        self.label, self.progress, self.remaining = label, progress, remaining
        self.closed, self.pending = False, False
        self.epoch, self.generation = self.session.epoch, self.session.vault.generation
        self.deadline, self.next_poll, self.period = 0, 0, 30
        self.clear_callback = clear
        self.timer = GLib.timeout_add(100, self.tick)
        controller.views.add(self)
        self.tick()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        self.label.set_label("")
        self.remaining.set_label("")
        self.progress.set_fraction(0)
        self.controller.views.discard(self)
        if self.clear_callback:
            self.clear_callback()

    def tick(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        if not self.session.active or self.session.epoch != self.epoch or self.session.vault.generation != self.generation:
            self.close()
            return GLib.SOURCE_REMOVE
        now = time.monotonic()
        left = max(0, self.deadline - now)
        self.progress.set_fraction(min(1, left / self.period))
        self.remaining.set_label(f"{math.ceil(left)} seconds remaining" if left else "Refreshing…")
        if not left:
            self.label.set_label("—")
        if not self.pending and now >= self.next_poll and not self.session.jobs.busy:
            started = time.monotonic()
            self.pending = True
            def done(data):
                self.pending = False
                if self.closed:
                    return
                self.period = data["period"]
                # Subtract the complete request round-trip conservatively; never prolong an expired code.
                self.deadline = started + data["remaining_ms"] / 1000
                self.next_poll = time.monotonic() + min(1, max(.05, self.deadline - time.monotonic()))
                if self.deadline > time.monotonic():
                    code = data["code"]
                    self.label.set_label(code[:len(code)//2] + " " + code[len(code)//2:])
            def failed(message):
                if not self.closed:
                    self.close()
                    self.session.error(message)
            # Background polling deliberately bypasses run_job/touch so inactivity still locks the vault.
            if not self.session.jobs.run(lambda: self.session.vault.totp_sample(self.entry), done, failed, interactive=False):
                self.pending = False
        return GLib.SOURCE_CONTINUE


class TotpController:
    def __init__(self, session):
        self.session = session
        self.epoch = 0
        self.views, self.dialogs = set(), set()
        if session.host_window:
            session.host_window.connect("notify::visible", lambda window, _prop: self.clear() if not window.get_visible() else None)

    def clear(self):
        self.epoch += 1
        for view in list(self.views):
            view.close()
        from .application import clear_dialog_fields
        for dialog in list(self.dialogs):
            clear_dialog_fields(dialog)
            dialog.force_close()
        self.dialogs.clear()

    def register(self, dialog, cleanup=lambda: None):
        state = {"closed": False}
        epoch, session_epoch = self.epoch, self.session.epoch
        self.dialogs.add(dialog)
        def clear():
            state["closed"] = True
            cleanup()
        dialog._clear_sensitive_fields = clear
        def closed(*_):
            from .application import clear_dialog_fields
            self.dialogs.discard(dialog)
            clear_dialog_fields(dialog)
        dialog.connect("closed", closed)
        return lambda: not state["closed"] and self.epoch == epoch and self.session.epoch == session_epoch and self.session.active

    def copy(self, entry, combined=False):
        if not entry.totp:
            self.setup(entry)
        else:
            self.session.run_job(lambda: self.session.vault.copy_totp(entry, combined), self.session.copy_entry)

    def row(self, entry):
        row = Adw.ActionRow(title="One-Time Password", subtitle="Reveal or copy the current verification code", activatable=True)
        row.connect("activated", lambda *_: self.show_code(entry))
        preview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, valign=Gtk.Align.CENTER, visible=False)
        code = Gtk.Label(css_classes=["monospace", "title-4"])
        progress = Gtk.ProgressBar(width_request=100)
        remaining = Gtk.Label(css_classes=["caption", "dim-label"])
        for widget in (code, progress, remaining):
            preview.append(widget)
        row.add_suffix(preview)
        reveal = Gtk.Button(icon_name="view-reveal-symbolic", tooltip_text="Reveal One-Time Password", valign=Gtk.Align.CENTER)
        state = {"view": None}
        def hide():
            preview.set_visible(False)
            reveal.set_icon_name("view-reveal-symbolic")
            reveal.set_tooltip_text("Reveal One-Time Password")
            row.set_subtitle("Reveal or copy the current verification code")
            state["view"] = None
        def toggle(*_):
            if state["view"]:
                state["view"].close()
                return
            if self.session.busy:
                return
            self.session.touch()
            preview.set_visible(True)
            row.set_subtitle("")
            reveal.set_icon_name("view-conceal-symbolic")
            reveal.set_tooltip_text("Hide One-Time Password")
            state["view"] = LiveCode(self, entry, code, progress, remaining, hide)
        reveal.connect("clicked", toggle)
        row.add_suffix(reveal)
        copy = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copy One-Time Password", valign=Gtk.Align.CENTER)
        copy.connect("clicked", lambda *_: self.copy(entry))
        row.add_suffix(copy)
        row.connect("unmap", lambda *_: state["view"].close() if state["view"] else None)
        return row

    def show_code(self, entry):
        session = self.session
        if session.busy or not session.vault.unlocked:
            return
        session.touch()
        dialog, header, box = _dialog("One-Time Password", width=440, height=360)
        box.append(Gtk.Label(label=entry.title, wrap=True, css_classes=["title-2"]))
        code = Gtk.Label(label="—", selectable=True, css_classes=["title-1", "numeric"])
        progress = Gtk.ProgressBar()
        remaining = Gtk.Label(css_classes=["dim-label"])
        for widget in (code, progress, remaining):
            box.append(widget)
        actions = Gtk.Box(spacing=12, homogeneous=True)
        for label, combined in (("Copy Code", False), ("Copy Password and Code", True)):
            copy = Gtk.Button(label=label, valign=Gtk.Align.CENTER,
                              css_classes=["suggested-action"] if not combined else [])
            copy.connect("clicked", lambda _button, include=combined: self.copy(entry, include) if current() else None)
            actions.append(copy)
        box.append(actions)
        state = {"live": None}
        current = self.register(dialog, lambda: state["live"].close() if state["live"] else None)
        session.present_dialog(dialog)
        if current():
            state["live"] = LiveCode(self, entry, code, progress, remaining)

    def setup(self, entry, data=None):
        session = self.session
        if session.busy or not session.vault.unlocked:
            return
        if data is None:
            epoch = self.epoch
            session.run_job(lambda: session.vault.totp_config(entry),
                            lambda value: self.setup(entry, value) if self.epoch == epoch and session.active else None)
            return
        data = dict(data)
        dialog, header, box = _dialog("Set Up One-Time Password", width=480, height=620)
        current = self.register(dialog)
        source = Adw.PreferencesGroup()
        method = Adw.ComboRow(title="Setup Method", model=Gtk.StringList.new(["Secret Key", "Setup Link"]))
        key = Adw.PasswordEntryRow(title="Secret Key", text=data.pop("key"))
        uri = Adw.PasswordEntryRow(title="Setup Link", text=data.pop("uri"), visible=False)
        for widget in (method, key, uri):
            source.add(widget)
        box.append(source)
        options = Adw.PreferencesGroup(title="Code Settings")
        modes = ["standard", "steam", "custom"]
        mode = Adw.ComboRow(title="Type", model=Gtk.StringList.new(["Standard", "Steam", "Custom"]))
        mode.set_selected(modes.index(data["mode"]))
        algorithm = Adw.ComboRow(title="Algorithm", model=Gtk.StringList.new(["SHA-1", "SHA-256", "SHA-512"]))
        algorithms = ["SHA-1", "SHA-256", "SHA-512"]
        algorithm.set_selected(algorithms.index(data["algorithm"]))
        period = _spin("Period (Seconds)", max(1, data["period"]), 1, 86400)
        digits = _spin("Code Length", min(10, max(1, data["digits"])), 1, 10)
        for widget in (mode, algorithm, period, digits):
            options.add(widget)
        box.append(options)
        message = Gtk.Label(label="Paste the Base32 secret or an otpauth://totp/ setup link from your account.",
                            wrap=True, xalign=0, css_classes=["dim-label"])
        box.append(message)
        def changed(*_):
            link = method.get_selected() == 1
            key.set_visible(not link)
            uri.set_visible(link)
            options.set_visible(not link)
            custom = mode.get_selected() == 2
            for widget in (algorithm, period, digits):
                widget.set_visible(custom)
        method.connect("notify::selected", changed)
        mode.connect("notify::selected", changed)
        changed()
        def saved(snapshot):
            if current():
                dialog.close()
                session.window.show_vault(snapshot)
        def save(*_):
            if not current() or session.busy:
                return
            values = dict(uri=uri.get_text()) if method.get_selected() else dict(key=key.get_text(),
                mode=modes[mode.get_selected()], algorithm=algorithms[algorithm.get_selected()],
                period=int(period.get_value()), digits=int(digits.get_value()))
            session.run_job(lambda: session.vault.save_totp(entry, data["revision"], **values), saved)
        save_button = Gtk.Button(label="Save", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        save_button.connect("clicked", save)
        header.pack_end(save_button)
        if data["configured"]:
            remove = Gtk.Button(label="Remove One-Time Password…", css_classes=["destructive-action"], halign=Gtk.Align.CENTER)
            def remove_clicked(*_):
                if current():
                    _confirm(session, "Remove One-Time Password?", "This removes the authenticator setup from the entry. Older history versions may still contain it.",
                        "Remove", lambda: session.run_job(lambda: session.vault.remove_totp(entry, data["revision"]), saved) if current() else None)
            remove.connect("clicked", remove_clicked)
            box.append(remove)
        session.present_dialog(dialog)

    def show_qr(self, entry, data=None):
        session = self.session
        if session.busy or not session.vault.unlocked:
            return
        if data is None:
            epoch = self.epoch
            session.run_job(lambda: session.vault.totp_qr(entry),
                            lambda value: self.show_qr(entry, value) if self.epoch == epoch and session.active else None)
            return
        dialog, header, box = _dialog("Authenticator QR Code", width=440, height=660)
        box.append(Gtk.Label(label=entry.title, wrap=True, css_classes=["title-2"]))
        box.append(Gtk.Label(label="Scan this setup secret with another authenticator to add the account.", wrap=True))
        picture = Gtk.Picture(can_shrink=True, width_request=280, height_request=280,
                              halign=Gtk.Align.CENTER, content_fit=Gtk.ContentFit.CONTAIN)
        picture.set_paintable(Gdk.Texture.new_from_bytes(GLib.Bytes.new(data.pop("png"))))
        box.append(picture)
        if data["custom"]:
            box.append(Gtk.Label(label="These custom or Steam settings may not be supported by every authenticator.", wrap=True, css_classes=["dim-label"]))
        remaining = Gtk.Label(css_classes=["dim-label"])
        box.append(remaining)
        state = {"timer": 0}
        def cleanup():
            if state["timer"]:
                GLib.source_remove(state["timer"])
                state["timer"] = 0
            picture.set_paintable(None)
        current = self.register(dialog, cleanup)
        until = time.monotonic() + 45
        def tick():
            if not current():
                return GLib.SOURCE_REMOVE
            left = math.ceil(until - time.monotonic())
            if left <= 0:
                state["timer"] = 0
                dialog.close()
                return GLib.SOURCE_REMOVE
            remaining.set_label(f"Closes in {left} seconds")
            return GLib.SOURCE_CONTINUE
        state["timer"] = GLib.timeout_add(250, tick)
        tick()
        actions = Gtk.Box(spacing=12, homogeneous=True)
        copy = Gtk.Button(label="Copy Setup Link", valign=Gtk.Align.CENTER)
        copy.connect("clicked", lambda *_: session.run_job(lambda: session.vault.totp_settings(entry, data["revision"]),
            lambda value: session.copy(value) if current() else None) if current() else None)
        actions.append(copy)
        export = Gtk.Button(label="Save QR Code…", valign=Gtk.Align.CENTER)
        def choose(*_):
            if current():
                session.choose_file(lambda path: session.run_job(lambda: session.vault.export_totp_qr(entry, data["revision"], path),
                    lambda _value: session.toast("QR code saved")) if current() else None, save=True, name="Authenticator.svg")
        export.connect("clicked", choose)
        actions.append(export)
        box.append(actions)
        session.present_dialog(dialog)
