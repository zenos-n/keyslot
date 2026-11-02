"""Secret Service exposure and provider preferences."""
from .i18n import mark as _mark, tr as _tr
from .database_views import Adw, Gtk, _dialog, _save
from .passkey_views import _lifetime
from .application import group_labels
from .backend import VaultError
from gi.repository import GLib


def settings(session, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        session.run_job(session.vault.secret_settings, lambda value: settings(session, value))
        return
    dialog, header, box = _dialog(_tr("Secret Service"), height=400)
    current = _lifetime(session, dialog)
    groups = [group for group in session.vault.snapshot.groups if not group.recycled]
    section = Adw.PreferencesGroup(title=_tr("Exposed Group"),
        description=_tr("Applications can use entries in this group and its subgroups when Secret Service is enabled in Preferences."))
    selected = Adw.ComboRow(title=_tr("Group"), model=Gtk.StringList.new([_tr("None")] + group_labels(groups)))
    selected.set_selected(next((index + 1 for index, group in enumerate(groups) if group.uuid == data["group"]), 0))
    section.add(selected)
    box.append(section)
    box.append(Gtk.Label(label=_tr("Passwords stay protected by the vault’s unlock key. Locking the vault ends application access. "
        "Protected custom attributes are not exposed as lookup metadata."), wrap=True, xalign=0, css_classes=["dim-label"]))
    def save(*_):
        if not current() or session.busy:
            return
        index = selected.get_selected()
        identifier = groups[index - 1].uuid if index else ""
        def done(snapshot):
            if current():
                dialog.close()
                session.window.show_vault(snapshot)
                session.toast(_tr("Secret Service exposure saved"))
        session.run_job(lambda: session.vault.save_secret_settings(identifier), done)
    _save(header, save)
    session.present_dialog(dialog)


def add_preferences(session, page):
    app = session.application
    options = app.startup.secret_service
    group = Adw.PreferencesGroup(title=_tr("Secret Service"),
        description=_tr("Let applications store passwords in selected vault groups. Keyslot can start this service when no other password service is running."))
    rows = {}
    for key, title, subtitle in (
        ("enabled", _mark("Provide Secret Service"), _mark("Use Keyslot as the desktop’s password service")),
        ("confirm_access", _mark("Confirm Application Access"), _mark("Approve applications before they can use exposed entries")),
        ("confirm_delete", _mark("Confirm Item Deletion"), _mark("Ask before applications recycle or delete an entry")),
        ("notify", _mark("Notify When a Password Is Used"), _mark("Show which application retrieved a secret")),
        ("unlock_before_search", _mark("Prompt to Unlock Before Searching"), _mark("Offer to unlock a vault when an application searches while all vaults are locked"))):
        rows[key] = Adw.SwitchRow(title=_tr(title), subtitle=_tr(subtitle), active=options[key])
        group.add(rows[key])
    status = Adw.ActionRow(title=_tr("Status"), subtitle_lines=3, use_markup=False)
    retry = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_tr("Retry Secret Service"), valign=Gtk.Align.CENTER)
    status.add_suffix(retry)
    def refresh():
        running = app.secrets is not None and not app.secrets.closed
        status.set_subtitle(_tr("Running") if running else (app.secret_service_error or _tr("Not Running")))
        retry.set_sensitive(app.startup.secret_service["enabled"] and not running)
        for key, row in rows.items():
            if key != "enabled":
                row.set_sensitive(rows["enabled"].get_active())
    def changed(*_):
        values = {key: row.get_active() for key, row in rows.items()}
        try:
            app.set_secret_service(values)
        except (OSError, ValueError, VaultError, GLib.Error) as exc:
            # A conflicting provider remains running; keep the configured preference and show its actual status.
            app.secret_service_error = str(exc)
        refresh()
    for row in rows.values():
        row.connect("notify::active", changed)
    retry.connect("clicked", changed)
    group.add(status)
    expose = Adw.ActionRow(title=_tr("Configure This Vault’s Exposed Group…"), activatable=True, sensitive=session.vault.unlocked)
    expose.connect("activated", lambda *_: settings(session))
    group.add(expose)
    refresh()
    page.add(group)
