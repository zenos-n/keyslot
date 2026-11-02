"""Per-application language preference."""
from .i18n import tr as _tr
from .application import Adw, Gtk
from .backend import VaultError


_LANGUAGES = ("system", "en", "pl", "ro")


def _language_choice(language):
    code = language.split("_", 1)[0].split("-", 1)[0] if isinstance(language, str) else ""
    return code if code in {"en", "pl", "ro"} else "system"


def add_preferences(session, page):
    settings = session.application.startup
    group = Adw.PreferencesGroup(title=_tr("Language"))
    row = Adw.ComboRow(title=_tr("Application Language"), subtitle=_tr("Restart Keyslot to apply the language change."),
        model=Gtk.StringList.new([_tr("System Language"), _tr("English"), _tr("Polish"), _tr("Romanian")]))
    current = _language_choice(settings.language)
    row.set_selected(_LANGUAGES.index(current))
    group.add(row)
    restoring = [False]

    def changed(*_):
        if restoring[0]:
            return
        language = _LANGUAGES[row.get_selected()]
        if language == settings.language:
            return
        try:
            settings.save(settings.remember, settings.login, settings.vault, language=language)
        except (OSError, ValueError, VaultError) as error:
            restoring[0] = True
            try:
                row.set_selected(_LANGUAGES.index(_language_choice(settings.language)))
            finally:
                restoring[0] = False
            session.error(str(error))
            return
        session.toast(_tr("Restart Keyslot to apply the language change."))

    row.connect("notify::selected", changed)
    page.add(group)
