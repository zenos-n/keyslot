"""Disposable real libsecret client used only by the private-bus acceptance test."""
import json
import sys
import gi
gi.require_version("Secret", "1")
from gi.repository import Gio, GLib, Secret

schema = Secret.Schema.new("com.neg_zero.keyslot.PublicFixture", Secret.SchemaFlags.NONE,
                          {"fixture": Secret.SchemaAttributeType.STRING})
connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
loop = GLib.MainLoop()
service = None
collections = {}

def emit(value):
    print(json.dumps(value), flush=True)

def failed(exc):
    emit({"error": Gio.DBusError.get_remote_error(exc) or exc.domain, "message": exc.message})

def loaded(service, result):
    try:
        items = service.search_finish(result)
        emit({"items": [{"path": item.get_object_path(), "attributes": item.get_attributes(),
                         "locked": item.get_locked(),
                         "value": item.get_secret().get_text() if item.get_secret() else None} for item in items]})
    except GLib.Error as exc:
        failed(exc)

def command_ready(_source, _condition):
    line = sys.stdin.readline()
    if not line:
        loop.quit()
        return False
    try:
        command = json.loads(line)
        operation = command["op"]
        attrs = {"fixture": command.get("fixture", "primary")}
        if operation == "store":
            payload = command.get("value", "public libsecret fixture")
            value = Secret.Value.new(payload, -1, "text/plain")
            result = {"stored": service.store_sync(schema, attrs, command.get("collection", "default"), command.get("label", "Public libsecret item"), value, None)}
        elif operation == "load":
            service.search(schema, attrs, Secret.SearchFlags.ALL | Secret.SearchFlags.UNLOCK | Secret.SearchFlags.LOAD_SECRETS, None, loaded)
            return True
        elif operation == "create_collection":
            collection = Secret.Collection.create_sync(service, command.get("label", "Public Fixture Collection"),
                command.get("alias", ""), Secret.CollectionCreateFlags.NONE, None)
            if collection:
                collections[collection.get_object_path()] = collection
            result = {"collection": collection.get_object_path() if collection else None}
        elif operation == "close_collection":
            collection = collections[command["path"]]
            result = {"closed": collection.delete_sync(None)}
        elif operation == "lookup":
            value = service.lookup_sync(schema, attrs, None)
            result = {"value": value.get_text() if value else None}
        elif operation == "clear":
            result = {"cleared": service.clear_sync(schema, attrs, None)}
        elif operation == "items":
            unlocked, locked = connection.call_sync("org.freedesktop.secrets", "/org/freedesktop/secrets", "org.freedesktop.Secret.Service",
                "SearchItems", GLib.Variant("(a{ss})", (attrs,)), None, Gio.DBusCallFlags.NONE, 15000, None).unpack()
            result = {"unlocked": list(unlocked), "locked": list(locked)}
        elif operation == "quit":
            emit({"quit": True})
            loop.quit()
            return False
        else:
            raise ValueError("Unknown fixture command")
        emit(result)
    except GLib.Error as exc:
        failed(exc)
    except Exception as exc:
        emit({"fixture_error": type(exc).__name__ + ": " + str(exc)})
        loop.quit()
    return True

def ready(_source, result):
    global service
    service = Secret.Service.get_finish(result)
    emit({"peer": connection.get_unique_name(), "algorithm": service.get_session_algorithms()})
    GLib.io_add_watch(sys.stdin, GLib.IO_IN | GLib.IO_HUP, command_ready)

Secret.Service.get(Secret.ServiceFlags.OPEN_SESSION | Secret.ServiceFlags.LOAD_COLLECTIONS, None, ready)
loop.run()
