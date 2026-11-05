# Window behavior

Preferences → Window Behavior offers Keep Window Open, Minimize, or Lower
Behind Other Windows after copying entry data. Field-header and custom-attribute
Copy buttons, entry keyboard actions and TOTP/combined-password copies share
this policy. It runs only after a successful regular-clipboard claim and only
while the originating vault window is still focused and unlocked. Generic
copies in generator, metadata and setup dialogs, and native text-selection
copies, keep their existing clipboard policy without moving the window.

Minimize After Unlocking applies to successful master/key-file/hardware, short
password, login-keyring, system-authentication, stdin and sealed linked-vault
unlock paths. New database creation/import and reauthentication of an already
open changed vault do not trigger it. Ordinary edits and refreshes do not
re-trigger unlock behavior. Initial hidden startup remains hidden; another
vault's unlock never minimizes the focused vault. If the unlock dialog is still
closing, the action waits for its closed signal. Deferred actions carry the
session/view/helper epochs and weak snapshot identity. Lock, focus/visibility
loss, a new dialog/file chooser, settings changes and session shutdown cancel
pending actions; stale completions cannot minimize a replacement view.

Hide Instead of Minimize applies to copy, unlock and link actions together.
It hides only when Run in Background is enabled; otherwise normal minimize is
used so the window remains recoverable. Close-to-background and Quit keep their
existing separate behavior. Minimize After Opening Links now uses this shared
policy rather than hiding solely because background operation is enabled.
Minimizing/hiding still follows Automatic Locking's existing clipboard grace;
enabling both minimize-after-unlock and lock-on-minimize can therefore relock
the vault. These options do not bypass security locking.

Explicit Qt INI profiles use stock settings; private profiles keep strict boolean
values in startup JSON:

| Keyslot field | KeePassXC key | Default |
| --- | --- | --- |
| `hide_window_on_copy` | `HideWindowOnCopy` | false |
| `minimize_on_copy` | `MinimizeOnCopy` | true |
| `drop_to_background_on_copy` | `DropToBackgroundOnCopy` | false |
| `minimize_after_unlock` | `MinimizeAfterUnlock` | false |
| `minimize_to_background` | `GUI/MinimizeToTray` | false |
| `minimize_on_url` | `MinimizeOnOpenUrl` | false |

Minimize wins if both stock copy mode flags are true. HideWindowOnCopy=false,
or enabled with both mode flags false, keeps the window open. Editing another
window preference does not normalize those flags; changing the copy-mode row
updates the chosen mode. INI writes retain the existing per-key conflict guard
and unknown settings preservation. Save failures restore the controls.

Lowering requires companion metadata version2/package0.2.0. GTK has no portable
Wayland client-side lower operation, so the app uses the companion's existing
`com.neg_zero.keyslot.AutoType1` interface on `/com/neg_zero/keyslot/AutoType1`
at `org.gnome.Shell`. `Lower(s window_path) → b` carries no entry/vault data.
The companion accepts only the current owner of `com.neg-zero.keyslot`, and
only if the currently focused compositor window has Keyslot's app identity,
the caller's GTK unique bus name and the exact requested GTK window object
path. It rejects lock screen, overview, override-redirect windows, windows
without a compositor actor and an in-progress Auto-Type focus request. It never
searches for another window,
activates another app or accepts keyboard data. GTK4.22.4 publishes the same
GApplication unique bus name and `/window/<id>` path through gtk_shell1.
Mutter50.4 provides all three identity/lower methods used here.

Calls have a three-second timeout, do not auto-start the Shell, and are canceled
on invalidation. An absent/old/disabled companion or a rejected request leaves
the window in place with a nonblocking message; no silent minimize fallback.
Cancellation cannot undo an action the compositor has already executed. The
extension remains a separate package and is not enabled/reloaded by the app.

References: stock KeePassXC2.7.12 Config/MainWindow/DatabaseWidget behavior
(GPL2-or-3), GTK4.22.4 application/window identity (LGPL2.1-or-later), and
Mutter50.4 Meta.Window APIs. Keyslot adapters are GPL3-only.
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/DatabaseWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/MainWindow.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/Config.cpp
- https://github.com/GNOME/gtk/blob/4.22.4/gtk/gtkapplication-dbus.c
- https://github.com/GNOME/gtk/blob/4.22.4/gtk/gtkapplication-wayland.c
- https://mutter.gnome.org/meta/method.Window.get_gtk_unique_bus_name.html
- https://mutter.gnome.org/meta/method.Window.get_gtk_window_object_path.html
- https://mutter.gnome.org/meta/method.Window.lower.html

Compilation and JavaScript syntax parsing only; no new tests/harnesses or
automated GTK/Shell/clipboard/vault/auth/config behavior runs. Manual acceptance
remains for X11/Wayland, extension upgrade/disable, focus/lock/close races,
multi-vault and every unlock path, opening links, clipboard failure, Never,
minimize-lock grace, explicit INI conflict handling, accessibility and layout.

Preferences → Startup → **Start as a Service** controls login-keyring startup.
It defaults on, including existing profiles. With it enabled, the generated
launcher uses `--login --background`, takes a background application hold, and
restores/unlocks vaults without presenting their windows. Turn it off to show
the login-unlocked vault. Explicit `--background`/`--minimized` still takes
precedence. Later explicit Open/Show opens normally; a repeated login command
does not hide a window the user already opened. Hidden credential failures stay
locked and queue their error until explicit opening. This is the existing GTK
background process, not a new system daemon. Run in Background separately
controls keeping the process alive when windows close.

The preference is stored in private startup JSON or the selected profile's
local `Keyslot/StartAsService` boolean. Changing it refreshes the login launcher.
Enrollment uses the running packaged build; a stable profile command is retained
when it resolves to that same binary. Trying a newer build therefore does not
silently schedule an older installed binary for the next login.
An existing user `org.keepassxc.KeePassXC.desktop` autostart entry with a plain
`keepassxc` command is disabled only when that executable resolves to Keyslot's
launcher and service login is enabled. Its exact contents are preserved beside
it as `.desktop.keyslot-backup`, and an owned Hidden tombstone prevents duplicate
GUI activation. Disabling service login or login unlock restores the original
entry only while the tombstone remains unchanged. Unrelated commands and real
KeePassXC executables are untouched; managed symlinks/conflicting backups are
reported instead of overwritten. Launcher/backup writes roll back if settings
cannot be saved. No system services or keyring credentials are changed.

Runtime/Python/gettext compilation and static review only; no tests or automated
login, keyring, GTK or vault runs. The next desktop login remains for manual
acceptance.
