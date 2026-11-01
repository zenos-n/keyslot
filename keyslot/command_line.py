"""KeePassXC-compatible GUI commands; passwords only arrive through stdin."""
import os
import platform
from pathlib import Path
import subprocess
import sys
import termios

from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from . import APP_ID, VERSION, CORE_VERSION
from .backend import VaultError


def configure(app):
    for name, short, description in [
        ("version", ord("v"), "Show application and core versions"),
        ("debug-info", 0, "Show runtime and build information"),
        ("lock", 0, "Lock all open databases and exit"),
        ("pw-stdin", 0, "Read one database password per line from standard input"),
        ("minimized", 0, "Open in the background"),
        ("allow-screencapture", 0, "Allow screen capture (Windows/macOS compatibility option)"),
    ]:
        app.add_main_option(name, short, GLib.OptionFlags.NONE, GLib.OptionArg.NONE, description, None)
    app.add_main_option("keyfile", 0, GLib.OptionFlags.NONE, GLib.OptionArg.STRING,
                        "Key file for the databases being opened", "PATH")
    for name, description in (("config", "KeePassXC global settings INI file (empty uses the default)"),
                              ("localconfig", "KeePassXC local settings INI file (empty uses the default)")):
        app.add_main_option(name, 0, GLib.OptionFlags.NONE, GLib.OptionArg.STRING, description, "PATH")
    app.add_main_option(GLib.OPTION_REMAINING, 0, GLib.OptionFlags.NONE, GLib.OptionArg.STRING_ARRAY,
                        "Databases to open", "FILE…")
    app.connect("handle-local-options", local_options)


def arguments(options):
    value = options.lookup_value(GLib.OPTION_REMAINING, None)
    return value.unpack() if value else []


def primary_profile(bus):
    from .application import INTERFACE, OBJECT_PATH
    try:
        return bus.call_sync(APP_ID, OBJECT_PATH, INTERFACE, "GetConfigurationProfile",
            None, GLib.VariantType.new("(s)"),
            Gio.DBusCallFlags.NO_AUTO_START, 5000, None).unpack()[0]
    except GLib.Error as exc:
        if (exc.matches(Gio.dbus_error_quark(), Gio.DBusError.SERVICE_UNKNOWN)
                or exc.matches(Gio.dbus_error_quark(), Gio.DBusError.NAME_HAS_NO_OWNER)):
            return None
        raise VaultError("The running Keyslot instance cannot verify configuration profiles. Quit it before using these configuration options.") from exc


def select_configuration(app, options, bus):
    from .configuration import IniProfile, default_paths
    from .startup import Startup
    profiles = {name: options.lookup_value(name, None) for name in ("config", "localconfig")}
    explicit = (any(value is not None for value in profiles.values())
                or any(name in os.environ for name in ("KPXC_CONFIG", "KPXC_CONFIG_LOCAL")))
    try:
        if not explicit:
            running = bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "NameHasOwner", GLib.Variant("(s)", (APP_ID,)), GLib.VariantType.new("(b)"),
                Gio.DBusCallFlags.NONE, 5000, None).unpack()[0]
            private = app.startup.path.parent
            if running or (private.exists() and any(path.name != "profiles" for path in private.iterdir())):
                return
        chosen = {}
        for name, value in profiles.items():
            if value is None:
                continue
            argument = value.unpack()
            if not argument:
                continue
            chosen[name] = Gio.File.new_for_commandline_arg(argument).get_path()
            if chosen[name] is None:
                raise VaultError("Choose local files for --config and --localconfig.")
        paths = default_paths(global_override=chosen.get("config"), local_override=chosen.get("localconfig"))
        if not explicit and not Path(paths[0]).is_file():
            return
        existing = primary_profile(bus)
        local = profiles["localconfig"]
        automatic_local = (local is None or not local.unpack()) and "KPXC_CONFIG_LOCAL" not in os.environ
        storage = IniProfile(*paths, automatic_local=automatic_local)
        if existing is not None and existing != storage.identity:
            raise VaultError("Keyslot is already running with a different configuration. Quit it before switching profiles.")
        selected = Startup(launcher=app.startup.launcher, storage=storage)
        app.startup = selected
        options.insert_value("keyslot-config-paths", GLib.Variant("as", list(storage.paths.values())))
    except (OSError, ValueError, VaultError) as exc:
        if explicit:
            raise
        # Keep an unreadable stock configuration intact and allow manual vault access.
        app.startup_error = f"KeePassXC settings could not be loaded. Keyslot is using its private defaults. {exc}"


def restore_echo(app):
    reader = getattr(app, "_stdin_reader", None)
    terminal = getattr(app, "_stdin_terminal", None)
    app._stdin_reader = None
    app._stdin_terminal = None
    try:
        if reader:
            try:
                if reader.poll() is None:
                    reader.terminate()
                reader.wait(timeout=.2)
            except subprocess.TimeoutExpired:
                try:
                    reader.kill()
                    reader.wait(timeout=.2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            except OSError:
                pass
    finally:
        if terminal:
            try:
                # Discard any unfinished password before handing the terminal back.
                termios.tcsetattr(terminal[0], termios.TCSAFLUSH, terminal[1])
            except (OSError, termios.error):
                print("Terminal echo could not be restored. Run 'stty echo' in this terminal.", file=sys.stderr)
            finally:
                os.close(terminal[0])


def local_options(app, options):
    if options.contains("version"):
        print(f"Keyslot {VERSION}\nKeePassXC core {CORE_VERSION}")
        return 0
    if options.contains("debug-info"):
        print(f"Keyslot: {VERSION}\nKeePassXC core (pinned): {CORE_VERSION}\n"
              f"Python: {platform.python_version()}\n"
              f"GTK: {Gtk.get_major_version()}.{Gtk.get_minor_version()}.{Gtk.get_micro_version()}\n"
              f"libadwaita: {Adw.get_major_version()}.{Adw.get_minor_version()}.{Adw.get_micro_version()}\n"
              f"GLib: {GLib.MAJOR_VERSION}.{GLib.MINOR_VERSION}.{GLib.MICRO_VERSION}\n"
              f"System: {platform.system()} {platform.release()} {platform.machine()}")
        return 0
    if options.contains("lock"):
        from .application import INTERFACE, OBJECT_PATH
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            bus.call_sync(APP_ID, OBJECT_PATH, INTERFACE, "Lock", None, None,
                          Gio.DBusCallFlags.NO_AUTO_START, 10000, None)
        except GLib.Error as exc:
            if (exc.matches(Gio.dbus_error_quark(), Gio.DBusError.SERVICE_UNKNOWN)
                    or exc.matches(Gio.dbus_error_quark(), Gio.DBusError.NAME_HAS_NO_OWNER)):
                return 0
            print("Keyslot could not lock the running application through the session D-Bus.", file=sys.stderr)
            return 1
        return 0
    if options.contains("pw-stdin") and not arguments(options):
        print("--pw-stdin requires at least one database filename.", file=sys.stderr)
        return 1
    if options.contains("pw-stdin") and options.contains("login"):
        print("Choose either login-keyring unlock or --pw-stdin.", file=sys.stderr)
        return 1
    keyfile = options.lookup_value("keyfile", None)
    profiles = {name: options.lookup_value(name, None) for name in ("config", "localconfig")}
    files = (arguments(options) + ([keyfile.unpack()] if keyfile else [])
             + [value.unpack() for value in profiles.values() if value is not None and value.unpack()])
    if any(Gio.File.new_for_commandline_arg(path).get_path() is None for path in files):
        print("Database, key-file and configuration arguments must refer to local files.", file=sys.stderr)
        return 1
    if Gdk.Display.get_default() is None:
        print("Keyslot requires a graphical session with GTK4 display access.", file=sys.stderr)
        return 1
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    except GLib.Error:
        print("Keyslot requires access to the session D-Bus.", file=sys.stderr)
        return 1
    try:
        select_configuration(app, options, bus)
    except (OSError, ValueError, VaultError, GLib.Error) as exc:
        print(f"Keyslot could not load the configuration: {exc}", file=sys.stderr)
        return 1
    if options.contains("pw-stdin"):
        try:
            fd = 0
            if os.isatty(fd):
                original = termios.tcgetattr(fd)
                terminal = os.dup(fd)
                app._stdin_terminal = (terminal, original)
                hidden = original.copy()
                hidden[3] &= ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSANOW, hidden)
                helper = os.environ.get("KEYSLOT_STDIN_READER", "")
                if not os.path.isabs(helper):
                    raise ValueError("The terminal input helper is unavailable.")
                # Read the controlling TTY in the invoking foreground process group.
                # Forward only a pipe: a background primary otherwise receives SIGTTIN.
                reader = subprocess.Popen([helper, "-n", str(len(arguments(options)))], stdin=terminal,
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                app._stdin_reader = reader
                os.dup2(reader.stdout.fileno(), fd)
                reader.stdout.close()
        except (OSError, ValueError, termios.error):
            restore_echo(app)
            print("Keyslot could not protect terminal password input.", file=sys.stderr)
            return 1
    return -1


class PasswordInput:
    """Hold a remote invocation until bounded asynchronous input is consumed."""
    MAX_PASSWORD_BYTES = 1024 * 1024

    def __init__(self, app, command, paths, keyfile, minimized):
        self.app, self.command = app, command
        self.paths, self.keyfile, self.minimized = list(paths), keyfile, minimized
        self.stream = command.get_stdin()
        self.buffer = bytearray()
        self.cancellable = Gio.Cancellable()
        self.eof, self.closed, self.status = False, False, 0
        self.session, self.epoch = None, None
        app.command_requests.add(self)
        app.hold()
        self.timer = GLib.timeout_add(100, self.check)
        GLib.idle_add(self.next)

    def check(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        if self.session and (self.session.jobs.closed or self.session.epoch != self.epoch):
            self.cancel()
            return GLib.SOURCE_REMOVE
        return GLib.SOURCE_CONTINUE

    def finish(self, status=None):
        if self.closed:
            return
        self.closed = True
        self.cancellable.cancel()
        self.buffer[:] = b"\0" * len(self.buffer)
        self.buffer.clear()
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        if not self.command.get_is_remote():
            restore_echo(self.app)
        if self.stream:
            self.stream.close_async(GLib.PRIORITY_DEFAULT, None, None)
        self.command.set_exit_status(self.status if status is None else status)
        self.command.done()
        self.app.command_requests.discard(self)
        self.app.release()
        self.session = self.command = self.stream = None

    def cancel(self):
        if not self.closed:
            self.command.printerr_literal("Password input was cancelled.\n")
            self.finish(1)

    def next(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        self.session = None
        if not self.paths:
            self.finish()
            return GLib.SOURCE_REMOVE
        if not self.stream:
            self.command.printerr_literal("Standard input is unavailable.\n")
            self.finish(1)
            return GLib.SOURCE_REMOVE
        self.path = self.paths.pop(0)
        try:
            self.session = self.app.open_database(self.path, keyfile=self.keyfile,
                                                  present=not self.minimized, defer_unlock=True)
        except (OSError, RuntimeError, ValueError):
            self.command.printerr_literal("The database path could not be opened.\n")
            self.finish(1)
            return GLib.SOURCE_REMOVE
        self.path = str(self.session.path)
        self.epoch = self.session.epoch
        self.command.printerr_literal("Database password: ")
        self.consume()
        return GLib.SOURCE_REMOVE

    def consume(self):
        if self.closed:
            return
        end = self.buffer.find(b"\n")
        if end > self.MAX_PASSWORD_BYTES or (end < 0 and len(self.buffer) > self.MAX_PASSWORD_BYTES):
            self.command.printerr_literal("Password input exceeds the 1 MiB limit.\n")
            self.finish(1)
            return
        if end >= 0 or self.eof:
            if self.eof and not self.buffer:
                self.command.printerr_literal("Standard input ended before a password was provided.\n")
                self.finish(1)
                return
            if end < 0:
                end = len(self.buffer)
            try:
                password = bytes(self.buffer[:end]).removesuffix(b"\r").decode("utf-8")
            except UnicodeDecodeError:
                self.command.printerr_literal("Password input must be UTF-8.\n")
                self.finish(1)
                return
            self.buffer[:end] = b"\0" * end
            del self.buffer[:end + 1]
            self.command.printerr_literal("\n")
            self.unlock(password)
        else:
            self.stream.read_bytes_async(4096, GLib.PRIORITY_DEFAULT, self.cancellable, self.received)

    def received(self, stream, result):
        try:
            data = stream.read_bytes_finish(result).get_data()
        except GLib.Error:
            if not self.closed:
                self.command.printerr_literal("Password input could not be read.\n")
                self.finish(1)
            return
        if self.closed:
            return
        self.eof = not data
        self.buffer.extend(data)
        self.consume()

    def unlock(self, password):
        session = self.session
        if session.vault.unlocked:
            GLib.idle_add(self.next)
            return
        if session.busy or session.dialogs or session.pending_unlock:
            self.command.printerr_literal("This database already has an unlock operation in progress.\n")
            self.status = 1
            GLib.idle_add(self.next)
            return
        components = {"keyfile": "", "yubikey": ""}
        storage = getattr(self.app.startup, "storage", None)
        try:
            if storage:
                components = storage.key_components(self.path)
        except (OSError, ValueError, VaultError) as exc:
            self.command.printerr_literal(f"Could not read remembered key components: {exc}\n")
            self.status = 1
            GLib.idle_add(self.next)
            return
        keyfile = components["keyfile"] if self.keyfile is None else self.keyfile
        hardware = components["yubikey"]
        key_only = not password and bool(keyfile or hardware)
        session.lock()
        self.epoch = session.epoch
        def perform():
            try:
                return session.vault.unlock(self.path, password, keyfile, hardware,
                                             no_password=key_only), None
            except (VaultError, OSError, ValueError) as exc:
                return None, str(exc)
        def completed(result):
            if self.closed:
                session.lock()
                return
            snapshot, error = result
            if error:
                self.status = 1
                self.command.printerr_literal(f"Could not unlock database: {error}\n")
                session.lock()
                session.pending_unlock = (str(self.path), False, None, keyfile)
                session.activate()
                self.epoch = session.epoch
            else:
                session.show_unlocked(snapshot)
                session.remember_unlocked({"password": password, "keyfile": keyfile,
                                           "yubikey": hardware, "no_password": key_only})
            GLib.idle_add(self.next)
        if not session.run_job(perform, completed):
            self.command.printerr_literal("This database is busy.\n")
            self.status = 1
            GLib.idle_add(self.next)
