{ pkgs, engine }:
pkgs.writeShellScript "keyslot-browser-proxy" ''
  # Native messaging inherits the browser wrapper's incompatible GUI libraries.
  unset LD_LIBRARY_PATH LD_PRELOAD GIO_EXTRA_MODULES GTK_PATH QT_PLUGIN_PATH QML2_IMPORT_PATH
  exec ${engine}/libexec/keyslot-browser-proxy "$@"
''
