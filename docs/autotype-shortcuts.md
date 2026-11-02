# Desktop Auto-Type shortcuts

On GNOME 50, the separately packaged Keyslot companion owns the desktop-wide
Auto-Type binding. Open Preferences → Auto-Type → Desktop Auto-Type Shortcuts,
or the same button under Keyboard Shortcuts. GNOME Extensions → Keyslot →
Settings opens the same native GTK4/libadwaita preferences window.

The default is Ctrl+Alt+K. Add aliases, change or remove individual bindings, or
reset this setting to its schema default. Removing every binding disables the
global shortcut. Changes apply through GNOME Shell’s existing GSettings binding
without restarting the extension. Application/entry shortcuts remain staged in
Keyslot’s own shortcut editor and are saved separately.

The recorder accepts function keys or a combination with Ctrl, Alt, Super, Meta
or Hyper. Escape or Cancel closes it without saving. Lock/NumLock state is not
stored. Newly recorded duplicate aliases are rejected. Existing unsupported
values are displayed and preserved until explicitly changed or removed. A
concurrent settings change detected before a write is refused; GSettings does
not provide an atomic compare-and-swap operation here. Desktop policy can make
the setting read-only. This editor does not enumerate/conflict-check every
other GNOME shortcut: choose another combination if the desktop reserves it.
Reset affects only `org.gnome.shell.extensions.keyslot` → `auto-type`.

Recording requests `Gdk.Toplevel.inhibit_system_shortcuts`; no binding is accepted
until the compositor confirms `shortcuts-inhibited`. Cleanup restores shortcuts
on success, cancellation or window closure. A desktop that denies/ignores the
request cannot record a shortcut; cancel and keep the existing binding. The
Shell hotkey handler also suppresses Auto-Type when GNOME extension preferences
owns the focused window. It checks the preferences service PID, ignores missing
window PID metadata while that service is running, and cancels on metadata
errors, intervening focus changes, newer shortcut requests or extension disable.
It never starts the preferences service for this check. This covers the period
before shortcut inhibition is granted or after it is revoked. Auto-Type from a
global shortcut is conservatively unavailable while any GNOME extension’s
preferences window has focus. The extension still receives no credential or
keystroke payload, and the existing app-side destination/approval guards remain.

The app opens the standard `org.gnome.Shell.Extensions.OpenExtensionPrefs` method
only when this control is used. Install companion package0.3.0/metadata version3
or newer. Missing/older companions or GNOME’s already-open preferences dialog
produce an error in Keyslot; installing/upgrading does not enable or reload the
extension. An already running old extension must be reloaded by the user for
its new handler guard to take effect. Do not use an older running extension to
acceptance-check the new recorder.

KeePassXC2.8’s native settings UI delegates global shortcut configuration to an
external configurator when the platform provides one. Keyslot’s GNOME integration
uses this companion rather than pretending that a stock native INI accelerator
configures a Wayland Shell binding. The native selector’s Virtual Keyboard
choice is compiled only for Windows/macOS; the Linux executor does not implement
that mode, so it is not added as an ineffective Linux UI setting.

Evidence for this change is package/Python compilation, compiled GSettings schema
and JavaScript syntax parsing only. No tests/harnesses or automated recorder,
GSettings, Shell, GTK, D-Bus, typing, focus, vault or portal behavior runs were
added/performed. Manual GNOME50/X11/Wayland acceptance remains for add/change/
remove/disable/reset, aliases/layouts/consumed modifiers, inhibition grant/denial/
revocation, read-only settings, concurrent edits, focus/service/disable races,
old/missing companion, keyboard and screen-reader operation. Other platform and
full replacement readiness remain unproven.

References (independent GPL3-only Keyslot integration):

- https://gjs.guide/extensions/development/preferences.html
- https://docs.gtk.org/gdk4/method.Toplevel.inhibit_system_shortcuts.html
- https://docs.gtk.org/gdk4/property.Toplevel.shortcuts-inhibited.html
- https://docs.gtk.org/gtk4/func.accelerator_parse.html
- https://github.com/GNOME/gnome-shell/blob/50.4/js/dbusServices/extensions/extensionsService.js
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/ApplicationSettingsWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoTypeSelectDialog.cpp
