# Automatic desktop locking candidate

Preferences → Automatic Locking exposes independent inactivity, screen/suspend,
user-switch and minimize/hide policies, applying to all vault windows.
Screen/suspend and user-switch default on; minimize/hide defaults off. Never
inactivity affects the inactivity timer. Each desktop-event switch applies to
its own event; a screen lock caused by user switching still uses screen policy.

The explicit KeePassXC INI codec maps Security/LockDatabaseScreenLock,
Security/LockDatabaseOnUserSwitch and Security/LockDatabaseMinimize. Private
startup.json stores booleans otherwise. Type checks, per-key optimistic INI
conflict checks, atomic writes and preservation of unrelated settings use the
existing storage implementation. Changing policy does not unlock a vault.

The GNOME ScreenSaver ActiveChanged signal and initial GetActive query track
screen state. systemd-logind PrepareForSleep and the manager's initial
PreparingForSleep property track sleep preparation; a session Lock request also
uses screen policy. Initial and restart queries are asynchronous/bounded, and
serials stop old replies from overriding newer signals. GNOME/logind service
owner changes invalidate obsolete queries and lock under the relevant enabled
policy before monitoring is rebound. Unlocking is never triggered by any signal.

The logind session resolves from XDG_SESSION_ID, with GetSessionByPID fallback.
Its immutable User UID must match, and its Class must identify a user login
before session monitoring is installed. Manager/background sessions belonging
to a user service are not mistaken for an inactive graphical login. Active=false and SessionRemoved use user-switch
policy. Properties are subscribed before the final state query; invalidated
Active values are re-read. No unrelated login session is guessed. A process
outside an identifiable login session needs a valid session ID for this policy;
non-systemd/non-GNOME environments have incomplete desktop-event monitoring.
Service restarts are handled; complete bus/session replacement across logout
still requires platform acceptance. No session/seat state is changed by this code.

Known screen lock/sleep/inactive-session state gates both job state publication
and vault rendering, cancelling late native/keyring completion before exposed
views/integrations can be published. The existing epoch, native-helper teardown,
dialog, clipboard, recovery and encrypted dirty-checkpoint cleanup are reused.
Unknown initial/unavailable monitor state is not claimed as a verified active
lock. Actual login, authentication, browser and lock race behavior remains manual.

GTK GdkToplevel MINIMIZED changes and transitions from visible to hidden trigger
minimize policy, including close-to-background and link-triggered hiding.
Initial hidden background startup is not a visible-to-hidden transition. All
vaults lock after the current owned clipboard's remaining lifetime, rounded up
and clamped to 1–20 seconds, matching the stock clipboard grace policy. With no
owned timed clipboard, the grace is one second. The timer is renewed by a new
minimize event, cancelled when the policy is disabled or the app locks/quits,
and does not silently change the configured clipboard-clear deadline. Restoring
a window does not cancel an already requested lock, as in upstream. Existing
manual/automatic lock save and encrypted recovery behavior remains unchanged.

References (upstream GPL2-or-3 behavior; Keyslot adapter GPL3-only):
- KeePassXC2.7.12 MainWindow::handleScreenLock/changeEvent/hideWindow
- KeePassXC2.7.12 DatabaseTabWidget::lockDatabasesDelayed/lockDatabasesOnUserSwitch
- KeePassXC2.7.12 ScreenLockListenerDBus and Config defaults
- https://github.com/keepassxreboot/keepassxc/tree/2.7.12/src/gui
- https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html
- https://docs.gtk.org/gdk4/flags.ToplevelState.html

Compilation-only candidate, no tests/harnesses or automated GUI/session/bus/
clipboard/vault behavior runs. Exact build environment: Python3.13.15,
PyGObject3.56.3, GLib2.88.3, GTK4.22.4, Adw1.9.3, GNOME50.4, systemd260.2.
Published online GTK/systemd docs are newer; the chosen APIs predate these
installed releases and GTK MINIMIZED is present in the installed GIR. These
observations do not prove behavior. Real minimize/hide/background, clipboard
ownership/grace, switch/VT/suspend/resume, login-session fallback, stale queries,
service loss/restart, INI/private migration/conflicts, unsaved changes and
accessibility remain for user manual acceptance. No live desktop operations
were performed to validate this feature.
