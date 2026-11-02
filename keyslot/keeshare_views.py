"""KeeShare group references and explicit synchronization controls."""
from .i18n import tr as _tr, trf as _trf
from . import CORE_VERSION
from .database_views import Adw, Gtk, _dialog, _save
from .passkey_views import _lifetime
from .backend import VaultError


def configure(session):
    settings = session.application.startup
    session.vault.keeshare_configure(settings.directory, settings.keeshare)


def settings(session, group, data=None):
    if not session.vault.unlocked or session.busy:
        return
    if data is None:
        def read():
            configure(session)
            return session.vault.keeshare_settings(group)
        session.run_job(read, lambda value: settings(session, group, value))
        return
    dialog, header, box = _dialog(_tr("KeeShare"), height=600)
    current = _lifetime(session, dialog)
    reference = Adw.PreferencesGroup(title=_tr("Shared Group"),
        description=_tr("Share files are encrypted with their own password. Changes are checked every 30 seconds while this vault is unlocked."))
    mode = Adw.ComboRow(title=_tr("Sharing Mode"), model=Gtk.StringList.new([_tr("Disabled"), _tr("Import"), _tr("Export"), _tr("Synchronize")]))
    mode.set_selected(data["mode"])
    path = Adw.EntryRow(title=_tr("Share File"), text=data["path"])
    choose = Gtk.Button(icon_name="document-open-symbolic", tooltip_text=_tr("Choose Share File"), valign=Gtk.Align.CENTER)
    def choose_path(*_):
        def selected(value):
            if current():
                path.set_text(value)
        session.choose_file(selected, save=mode.get_selected() == 2)
    choose.connect("clicked", choose_path)
    path.add_suffix(choose)
    password = Adw.PasswordEntryRow(title=_tr("New Share Password") if data["has_password"] else _tr("Share Password"))
    dirty = [False]
    password.connect("changed", lambda *_: dirty.__setitem__(0, True))
    keep_groups = Adw.SwitchRow(title=_tr("Include Subgroups When Exporting"), active=data["keep_groups"])
    for row in (mode, path, password, keep_groups):
        reference.add(row)
    box.append(reference)
    if data["has_password"]:
        box.append(Gtk.Label(label=_tr("Leave the password unchanged to keep the saved share password."), xalign=0, wrap=True,
                            css_classes=["dim-label"]))
    global_settings = session.application.startup.keeshare
    if not all(global_settings.values()):
        box.append(Gtk.Label(label=_tr("KeeShare imports and exports also need to be enabled in Preferences."), wrap=True, xalign=0))
    box.append(Gtk.Label(label=_trf('Use .kdbx for standard encrypted shares. Legacy .kdbx.share containers are supported; KeePassXC {arg0} ignores their signatures when importing.', arg0=CORE_VERSION), wrap=True, xalign=0, css_classes=["dim-label"]))
    sync = Gtk.Button(label=_tr("Synchronize Saved Settings Now"))
    sync.connect("clicked", lambda *_: synchronize(session) if current() else None)
    box.append(sync)
    def save(*_):
        if not current() or session.busy:
            return
        values = dict(mode=mode.get_selected(), path=path.get_text(), keep_groups=keep_groups.get_active())
        if dirty[0]:
            values["password"] = password.get_text()
        def saved(snapshot):
            if current():
                dialog.close()
                session.window.show_vault(snapshot)
                session.toast(_tr("KeeShare settings saved"))
        session.run_job(lambda: session.vault.save_keeshare_settings(group, **values), saved)
    _save(header, save)
    dialog.connect("closed", lambda *_: password.set_text(""))
    session.present_dialog(dialog)


def synchronize(session):
    if not session.vault.unlocked or session.busy:
        return
    def perform():
        configure(session)
        return session.vault.keeshare_sync(force=True)
    def completed(result):
        if result["imports"]:
            session.window.show_vault(session.vault.snapshot)
        if result["warnings"]:
            session.error("\n".join(dict.fromkeys(result["warnings"])))
        else:
            session.toast(_trf('KeeShare: {arg0} imports, {arg1} exports', arg0=result['imports'], arg1=result['exports']))
    session.run_job(perform, completed)


def add_preferences(session, page):
    settings = session.application.startup
    group = Adw.PreferencesGroup(title=_tr("KeeShare"),
        description=_tr("Configure share files in each group’s KeeShare settings. Background synchronization runs while vaults are unlocked."))
    incoming = Adw.SwitchRow(title=_tr("Allow KeeShare Imports"), active=settings.keeshare["import"],
        subtitle=_tr("Merge changed encrypted share files into configured groups"))
    outgoing = Adw.SwitchRow(title=_tr("Allow KeeShare Exports"), active=settings.keeshare["export"],
        subtitle=_tr("Configured groups may create and replace their encrypted share files"))
    changing = [False]
    def changed(*_):
        if changing[0]:
            return
        try:
            settings.save(settings.remember, settings.login, settings.vault,
                          keeshare={"import": incoming.get_active(), "export": outgoing.get_active()})
            session.application.keeshare.state_changed()
        except (OSError, ValueError, VaultError) as exc:
            changing[0] = True
            incoming.set_active(settings.keeshare["import"])
            outgoing.set_active(settings.keeshare["export"])
            changing[0] = False
            session.error(str(exc))
    for row in (incoming, outgoing):
        row.connect("notify::active", changed)
        group.add(row)
    identity = Adw.ActionRow(title=_tr("Signing Identity…"), subtitle=_tr("Signer name, fingerprint and certificate regeneration"),
                             activatable=True)
    identity.add_suffix(Gtk.Image(icon_name="go-next-symbolic", valign=Gtk.Align.CENTER))
    from .keeshare_identity_views import show as show_identity
    identity.connect("activated", lambda *_: show_identity(session))
    group.add(identity)
    sync = Adw.ActionRow(title=_tr("Synchronize Now"), activatable=True, sensitive=session.vault.unlocked)
    sync.connect("activated", lambda *_: synchronize(session))
    group.add(sync)
    page.add(group)
