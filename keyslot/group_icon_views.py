"""Reviewed child icon updates share the group editor's single encrypted save."""
from gi.repository import Adw


class Changes:
    def __init__(self, session, dialog, box, save):
        self.session, self.dialog, self.box, self.save = session, dialog, box, save
        self.epoch, self.identity = session.epoch, session.vault.identity
        self.phase, self.token = "editing", None
        self.pending = None
        self.review_dialog = None
        dialog.connect("closed", self.closed)
        dialog.connect("close-attempt", self.close_attempt)
        dialog._clear_sensitive_fields = self.cancel

    def closed(self, dialog):
        self.cancel()
        from .application import clear_dialog_fields
        clear_dialog_fields(dialog)

    def current(self, active=True):
        return (self.phase != "closed" and not self.session.jobs.closed
                and self.session.epoch == self.epoch and self.session.vault.identity is self.identity
                and (not active or self.session.active))

    def busy(self, value):
        self.box.set_sensitive(not value)
        self.save.set_sensitive(not value)
        self.dialog.set_can_close(not value)

    def release(self, token):
        if token and self.session.epoch == self.epoch and self.session.vault.identity is self.identity:
            self.session.jobs.run(lambda: self.session.vault.cancel_group_icons(token),
                                  failed=lambda _message: None, interactive=False)

    def cancel(self):
        self.phase = "closed"
        token, self.token = self.token, None
        self.pending = None
        self.release(token)
        if self.review_dialog:
            self.review_dialog.force_close()
            self.review_dialog = None

    def close_attempt(self, *_):
        if self.phase == "preparing":
            self.cancel()
            self.dialog.force_close()
        elif self.phase == "saving":
            self.session.toast("Wait for the group changes to finish saving")

    def failed(self, message):
        if not self.current(False):
            return
        self.release(self.token)
        self.token = self.pending = None
        self.phase = "editing"
        self.busy(False)
        self.session.error(message)

    def start(self, values, advanced, scope):
        if not self.current() or self.phase != "editing" or self.session.busy:
            return
        self.pending = (values, dict(advanced), scope)
        self.phase = "preparing"
        self.busy(True)
        def reviewed(data):
            if not self.current():
                self.release(data["token"])
                if self.current(False):
                    self.phase, self.pending = "editing", None
                    self.busy(False)
                return
            self.token, self.phase = data["token"], "review"
            self.busy(False)
            body = (f'Save this group and replace icons on {data["groups"]} child groups '
                    f'and {data["entries"]} entries, including nested groups.\n\n'
                    "Changed entries follow the vault’s history limits. Groups have no history.")
            if data["recycled_groups"] or data["recycled_entries"]:
                body += (f'\n\nIncludes {data["recycled_groups"]} recycled groups and '
                         f'{data["recycled_entries"]} recycled entries.')
            alert = Adw.AlertDialog(heading="Apply Group Icon to Its Contents?", body=body)
            alert.add_response("cancel", "Cancel")
            alert.add_response("apply", "Save and Apply")
            alert.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
            def closed(*_):
                if self.review_dialog is not alert:
                    return
                self.review_dialog = None
                if self.phase == "review" and self.token == data["token"]:
                    self.release(self.token)
                    self.token = self.pending = None
                    self.phase = "editing"
            def response(_dialog, answer):
                if (answer != "apply" or not self.current() or self.phase != "review"
                        or self.review_dialog is not alert or self.token != data["token"]):
                    return
                self.phase = "saving"
                self.busy(True)
                values, options, scope = self.pending
                token, self.token = self.token, None
                def saved(snapshot):
                    self.pending = None
                    if self.current(False):
                        self.busy(False)
                        self.dialog.close()
                        self.session.window.show_vault(snapshot)
                def failed(message):
                    self.release(token)
                    self.failed(message)
                if not self.session.run_job(lambda: self.session.vault.save_group(
                        *values, **options, icon_scope=scope, icon_review=token, icons_approved=True), saved, failed):
                    self.release(token)
                    self.failed("The vault is busy. Review the icon changes again.")
            alert.connect("response", response)
            alert.connect("closed", closed)
            self.review_dialog = alert
            if not self.session.present_dialog(alert):
                closed()
        group, icon, custom_icon = values[0], advanced["icon"], advanced["custom_icon"]
        if not self.session.run_job(lambda: self.session.vault.review_group_icons(
                group, scope, icon, custom_icon), reviewed, self.failed):
            self.failed("The vault is busy. Try saving again.")
