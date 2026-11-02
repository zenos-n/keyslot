"""Keyslot-only gettext; interpolate values after catalog lookup, never translate vault data."""
import gettext
from collections import Counter
from pathlib import Path
from string import Formatter

_localedir = Path(__file__).resolve().parents[2] / "locale"
_catalog = gettext.translation("keyslot", localedir=_localedir, fallback=True)
_formatter = Formatter()


def mark(message):
    """Mark a code-owned caption without changing its stored/internal value."""
    return message


def select_language(language="system"):
    """Select an explicit supported language, or defer to the desktop locale."""
    global _catalog
    code = language.split("_", 1)[0].split("-", 1)[0] if isinstance(language, str) else ""
    languages = [code] if code in {"en", "pl", "ro"} else None
    _catalog = gettext.translation("keyslot", localedir=_localedir, languages=languages, fallback=True)


def tr(message):
    return _catalog.gettext(message)


def trc(context, message):
    return _catalog.pgettext(context, message)


def _signature(template):
    return Counter((name, spec, conversion) for _literal, name, spec, conversion in _formatter.parse(template)
                   if name is not None)


def _format(source, translated, values):
    try:
        if _signature(source) != _signature(translated):
            translated = source
        return translated.format(**values)
    except (KeyError, IndexError, ValueError, TypeError):
        return source.format(**values)


def trf(message, **values):
    return _format(message, tr(message), values)


def ntrf(singular, plural, count, **values):
    source = singular if count == 1 else plural
    return _format(source, _catalog.ngettext(singular, plural, count), values | {"count": count})
