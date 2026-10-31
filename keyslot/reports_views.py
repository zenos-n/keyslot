"""Database report browsing and revision-bound changes, without retrieving passwords."""
from gi.repository import Adw, GLib, Gtk
from .database_views import _dialog


def _clear(box):
    while child := box.get_first_child():
        box.remove(child)


def _button(icon, label, callback):
    widget = Gtk.Button(icon_name=icon, tooltip_text=label, valign=Gtk.Align.CENTER)
    widget.connect("clicked", lambda *_: callback())
    return widget


def show(session, data=None):
    if session.busy or not session.vault.unlocked:
        return
    if data is None:
        session.run_job(session.vault.report, lambda value: show(session, value))
        return
    Reports(session, data)


class Reports:
    def __init__(self, session, data):
        from .breach_views import BreachReport
        self.session, self.data, self.closed = session, data, False
        self.dialog, header, box = _dialog("Database Reports", width=660, height=700)
        self.refresh = _button("view-refresh-symbolic", "Refresh Reports", self.reload)
        header.pack_start(self.refresh)
        options = Adw.PreferencesGroup()
        self.page = Adw.ComboRow(title="Report", model=Gtk.StringList.new(
            ["Statistics", "Password Health", "Reused Passwords", "Browser Access", "Exposed Passwords"]))
        self.excluded = Adw.SwitchRow(title="Show Excluded Entries")
        self.expired = Adw.SwitchRow(title="Show Expired Entries", active=True)
        self.urls_only = Adw.SwitchRow(title="Only Entries with URLs", active=True)
        self.settings_only = Adw.SwitchRow(title="Only Entries with Saved Browser Permissions")
        for row in (self.page, self.excluded, self.expired, self.urls_only, self.settings_only):
            options.add(row)
        box.append(options)
        box.append(Gtk.Label(label="Reports describe the vault at the last refresh. Refresh after editing entries.",
                             wrap=True, xalign=0, css_classes=["dim-label"]))
        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.append(self.content)
        self.breach = BreachReport(self)
        box.append(self.breach.box)
        self.page.connect("notify::selected", self.render)
        self.excluded.connect("notify::active", lambda *_: self.reload())
        for control in (self.expired, self.urls_only, self.settings_only):
            control.connect("notify::active", self.render)
        self.dialog._clear_sensitive_fields = self.close
        self.dialog.connect("closed", self.close)
        self.render()
        session.present_dialog(self.dialog)

    def close(self, *_):
        if self.closed:
            return
        self.closed = True
        self.breach.close()
        self.data = {}
        _clear(self.content)

    def reload(self):
        if self.closed or self.session.busy or self.breach.running:
            return
        self.breach.reset()
        self.refresh.set_sensitive(False)
        self.excluded.set_sensitive(False)
        excluded = self.excluded.get_active()
        def ready(data):
            if self.closed:
                return
            self.data = data
            self.refresh.set_sensitive(True)
            self.excluded.set_sensitive(True)
            self.render()
        def failed(message):
            if not self.closed:
                self.refresh.set_sensitive(True)
                self.excluded.set_sensitive(True)
                self.session.error(message)
        if not self.session.run_job(lambda: self.session.vault.report(excluded), ready, failed):
            self.refresh.set_sensitive(True)
            self.excluded.set_sensitive(True)

    def open_entry(self, item):
        if self.session.busy or self.closed:
            return
        if not any(entry.uuid == item["uuid"] and not entry.recycled for entry in self.session.vault.snapshot.entries):
            self.session.error("The report entry changed. Refresh the report.")
            return
        window = self.session.window
        window.search.set_text("")
        window.search_matches = None
        window.groups.select_row(window.groups.get_first_child())
        window.render_entries(item["uuid"])
        window.inner.set_show_content(True)
        self.dialog.close()

    def change(self, items, action):
        if self.closed or self.session.busy or self.breach.running or not items:
            return
        reset = action == "browser_reset"
        label = "Clear Permissions" if reset else "Exclude" if action == "exclude" else "Include"
        heading = "Clear Saved Browser Permissions?" if reset else "Exclude Entries from Reports?" if action == "exclude" else "Include Entries in Reports?"
        body = "\n".join(item["title"] or "Untitled Entry" for item in items[:10])
        if len(items) > 10:
            body += f"\n…and {len(items) - 10} more"
        if reset:
            body += ("\n\nThis clears saved Allow and Deny lists for these entries. Future browser requests may ask for permission again. "
                     "Entry URLs and paired browser connections are kept.")
        else:
            body += "\n\nThis changes the entries' saved report-exclusion setting."
        if not self.session.vault.auto_save:
            body += "\n\nThe changes will remain unsaved until you save the vault."
        revision = self.data["revision"]
        alert = Adw.AlertDialog(heading=heading, body=body, body_use_markup=False)
        alert.add_response("cancel", "Cancel")
        alert.add_response("apply", label)
        alert.set_default_response("cancel")
        alert.set_close_response("cancel")
        alert.set_response_appearance("apply", Adw.ResponseAppearance.DESTRUCTIVE if reset else Adw.ResponseAppearance.SUGGESTED)
        def response(_alert, answer):
            if answer != "apply" or self.closed:
                return
            def done(snapshot):
                self.session.apply_refreshed(snapshot)
                if not self.closed:
                    self.reload()
            self.session.run_job(lambda: self.session.vault.edit_report([item["uuid"] for item in items], action, revision), done)
        alert.connect("response", response)
        self.session.present_dialog(alert)

    def row(self, item, subtitle=None):
        suffix = " · Excluded" if item.get("excluded") else ""
        if item.get("expired"):
            suffix += " · Expired"
        row = Adw.ActionRow(title=item["title"] or "Untitled Entry", subtitle=(subtitle or item["group"]) + suffix,
                            use_markup=False, activatable=True)
        row.connect("activated", lambda *_: self.open_entry(item))
        excluded = item.get("excluded", False)
        row.add_suffix(_button("list-add-symbolic" if excluded else "list-remove-symbolic",
            "Include in Reports…" if excluded else "Exclude from Reports…",
            lambda: self.change([item], "include" if excluded else "exclude")))
        return row

    def visible(self, item):
        return self.expired.get_active() or not item.get("expired")

    def render(self, *_):
        if self.closed:
            return
        _clear(self.content)
        page = self.page.get_selected()
        self.breach.box.set_visible(page == 4)
        self.excluded.set_visible(page != 0)
        self.expired.set_visible(page not in (0, 4))
        self.urls_only.set_visible(page == 3)
        self.settings_only.set_visible(page == 3)
        if page == 4:
            return
        if page == 0:
            group = Adw.PreferencesGroup(title="Statistics", description="Active database entries; recycled items are excluded.")
            for title, key in [("Groups", "groups"), ("Entries", "entries"), ("Expired Entries", "expired"),
                ("Excluded Entries", "excluded"), ("Weak Passwords", "weak"), ("Short Passwords", "short"),
                ("Reused Passwords", "reused"), ("Unique Passwords", "unique"), ("Average Password Length", "average_length"),
                ("Passkeys", "passkeys"), ("One-Time Passwords", "totp")]:
                row = Adw.ActionRow(title=title)
                row.add_suffix(Gtk.Label(label=str(self.data.get(key, 0)), css_classes=["numeric"]))
                group.add(row)
            self.content.append(group)
            return
        if page == 1:
            group = Adw.PreferencesGroup(title="Password Health")
            self.content.append(group)
            qualities = ["Bad", "Poor", "Weak", "Good", "Excellent"]
            items = [item for item in sorted(self.data["health"], key=lambda value: value["score"]) if self.visible(item)]
            for item in items:
                quality = item["quality"]
                name = qualities[quality] if 0 <= quality < len(qualities) else "Unknown"
                subtitle = f"{name} · {item['entropy']:.0f} bits · Score {item['score']}\n{item['group']}"
                row = self.row(item, subtitle)
                def details(item=item):
                    alert = Adw.AlertDialog(heading=item["title"] or "Untitled Entry", body_use_markup=False,
                        body="\n\n".join(value for value in (item.get("reason"), item.get("details")) if value) or "No problems detected.")
                    alert.add_response("close", "Close")
                    self.session.present_dialog(alert)
                row.add_suffix(_button("dialog-information-symbolic", "Health Details", details))
                group.add(row)
            if not items:
                group.add(Adw.ActionRow(title="No Entries Match These Filters"))
        elif page == 2:
            count = 0
            for reused in sorted(self.data["duplicates"], key=len, reverse=True):
                items = [item for item in reused if self.visible(item)]
                if not items:
                    continue
                count += 1
                group = Adw.PreferencesGroup(title=f"Password Used by {len(reused)} Entries")
                for item in items:
                    group.add(self.row(item))
                self.content.append(group)
            if not count:
                self.content.append(Adw.StatusPage(title="No Reused Passwords Shown", icon_name="dialog-information-symbolic"))
        elif page == 3:
            group = Adw.PreferencesGroup(title="Browser Access", description="Stored URL fields and saved browser decisions. Protected URL values remain hidden.")
            self.content.append(group)
            items = [item for item in self.data["browser"] if self.visible(item)
                and (not self.urls_only.get_active() or item["urls"] or item["hidden_urls"])
                and (not self.settings_only.get_active() or item["has_settings"])]
            for item in sorted(items, key=lambda value: value["title"].casefold()):
                row = Adw.ExpanderRow(title=item["title"] or "Untitled Entry", subtitle=item["group"], use_markup=False)
                row.add_suffix(_button("document-open-symbolic", "Open Entry", lambda item=item: self.open_entry(item)))
                for title, values in (("URLs", item["urls"]), ("Allowed URLs", item["Allow"]), ("Denied URLs", item["Deny"])):
                    row.add_row(Adw.ActionRow(title=title, subtitle="\n".join(values) or "None", use_markup=False))
                if item["hidden_urls"]:
                    row.add_row(Adw.ActionRow(title="Protected URLs", subtitle=f"{item['hidden_urls']} values hidden"))
                if item["invalid_settings"]:
                    row.add_row(Adw.ActionRow(title="Invalid Saved Browser Permissions", css_classes=["warning"]))
                if item["has_settings"]:
                    reset = Adw.ActionRow(title="Clear Saved Permissions…", activatable=True)
                    reset.connect("activated", lambda *_args, item=item: self.change([item], "browser_reset"))
                    row.add_row(reset)
                excluded = item["excluded"]
                inclusion = Adw.ActionRow(title="Include in Reports…" if excluded else "Exclude from Reports…", activatable=True)
                inclusion.connect("activated", lambda *_args, item=item, excluded=excluded: self.change([item], "include" if excluded else "exclude"))
                row.add_row(inclusion)
                group.add(row)
            if not items:
                group.add(Adw.ActionRow(title="No Entries Match These Filters"))
            saved = [item for item in items if item["has_settings"]]
            if saved:
                clear = Gtk.Button(label=f"Clear Permissions for {len(saved)} Shown Entries…", css_classes=["destructive-action"])
                clear.connect("clicked", lambda *_: self.change(saved, "browser_reset"))
                self.content.append(clear)
