"""Password-free browser approval through the optional GNOME companion."""
import json
import uuid

from gi.repository import Gio, GLib

SHELL = "org.gnome.Shell"
PATH = "/com/neg_zero/keyslot/Browser1"
INTERFACE = "com.neg_zero.keyslot.Browser1"
UNAVAILABLE = {
    "org.freedesktop.DBus.Error.UnknownMethod", "org.freedesktop.DBus.Error.UnknownObject",
    "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner",
}


def approve(session, data, done, fallback):
    from .browser_dialogs import website_origin
    connection = session.application.connection
    token = uuid.uuid4().hex
    state = {"closed": False, "answered": False, "owner": "", "fallback": None}
    cancellable = Gio.Cancellable()
    payload = json.dumps({"connection": data["connection"], "database": data["database"],
        "origin": website_origin(data["url"]),
        "destination": website_origin(data["submit_url"]) if data["submit_url"] else "",
        "http_auth": bool(data.get("http_auth")),
        "entries": [{key: entry[key] for key in ("uuid", "title", "username", "group", "allowed")}
                    for entry in data["entries"]]}, ensure_ascii=True)

    def complete(choice):
        if not state["closed"] and not state["answered"]:
            state["answered"] = True
            done(choice)

    def failed(error):
        if state["closed"] or state["answered"]:
            return
        # Only absence of the companion falls back. A dismissed or expired prompt denies access.
        if Gio.DBusError.get_remote_error(error) in UNAVAILABLE:
            state["fallback"] = fallback()
        else:
            complete(None)

    def replied(bus, result):
        try:
            value, = bus.call_finish(result).unpack()
            choice = json.loads(value) if len(value) <= 262144 else None
        except GLib.Error as error:
            failed(error)
            return
        except (ValueError, TypeError):
            choice = None
        complete(choice)

    def owned(bus, result):
        try:
            owner, = bus.call_finish(result).unpack()
        except GLib.Error as error:
            failed(error)
            return
        if state["closed"]:
            return
        state["owner"] = owner
        connection.call(owner, PATH, INTERFACE, "Approve", GLib.Variant("(ss)", (token, payload)),
            GLib.VariantType.new("(s)"), Gio.DBusCallFlags.NO_AUTO_START, 30000, cancellable, replied)

    if len(payload) > 262144:
        state["fallback"] = fallback()
    else:
        connection.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner",
            GLib.Variant("(s)", (SHELL,)), GLib.VariantType.new("(s)"),
            Gio.DBusCallFlags.NO_AUTO_START, 2000, cancellable, owned)

    def dismiss():
        if state["closed"]:
            return
        state["closed"] = True
        cancellable.cancel()
        if state["fallback"]:
            state["fallback"]()
        if state["owner"]:
            connection.call(state["owner"], PATH, INTERFACE, "Cancel", GLib.Variant("(s)", (token,)),
                None, Gio.DBusCallFlags.NO_AUTO_START, 1000, None, None)
    return dismiss
