# Wayland Auto-Type keyboard permission

Preferences → Wayland Keyboard Permission offers three lifetimes:

- **Do Not Remember** requests no permission persistence when a connection opens.
- **Until Keyslot Quits** keeps a returned restore token in application memory.
  This is the stock `AutoTypeDesktopPortalPersistMode=1` default. Closing a
  background-enabled window does not quit Keyslot.
- **Until I Forget** requests persistence across application restarts. Only this
  mode stores a returned token, using stock `AutoTypeDesktopPortalRestoreToken`
  in the selected local INI profile. Private-default fallback uses a separate
  `keyslot/portal-permission.ini`; tokens do not enter `startup.json`.

The desktop decides whether to grant persistence and may show a prompt again.
The portal's interface version is read before negotiation; version 1 or a failed
version lookup uses a normal temporary request without persistence options.
Saved tokens are not consumed on that fallback. Only keyboard access is requested;
no pointer, screen capture or EIS access is requested. The separate opt-in
[portal Copy](autotype-clipboard.md) preference requests clipboard access before
Start when enabled.

Restore tokens are single-use. A persisted token is read and cleared with an
expected-value configuration transaction before submission; an in-memory token
is removed before use. Denial, cancellation, failure or process exit cannot leave
that consumed token queued for reuse. A replacement is accepted only after Start
grants keyboard access and the permission policy/profile remain current. The
invocation is checked again after storage before any focus/plan/input work. A
permission already approved by the desktop can remain cached when a vault is
subsequently locked; it does not authorize that vault or a later sequence. Missing tokens
mean the desktop did not grant persistence; typing can continue with the current
permission. Invalid token data is rejected without logging its contents. Saving
a replacement requires the local slot to remain empty, so another process's new
token is not overwritten. Failed storage aborts the invocation and retains the
existing configuration error/recovery handling.

**Forget Remembered Access** clears Keyslot's memory and selected-profile token.
Changing the lifetime also forgets the previous token. Both invalidate pending
keyboard operations before waiting for storage; stale completion cannot continue
typing. The settings UI uses the session worker and restores controls on failure.
Profile identity, configuration links and expected-value writes are checked;
late settings actions cannot retarget another profile. Shutdown clears in-memory
permission state and cancels input; mode 2 tokens already saved remain for the
next run. Forgetting removes Keyslot's restore capability. It is not a claim that
the portal's central permission store has been revoked: future prompts and
permission revocation are controlled by the desktop.

Permission persistence never authorizes a vault unlock or an Auto-Type sequence.
Every invocation still captures a destination, applies its configured entry and
field confirmation policy, prepares a native one-use token, and checks the vault,
flow, focus lease, deadline and portal session while waiting and sending keys.
Portal connections now use the separate stock keep-open preference and idle
timeout; see [Keyboard connections](autotype-connections.md). The separate
[portal Copy](autotype-clipboard.md) option implements the native clipboard setting;
Auto-Type still emits its parsed key sequence. Tokens are
opaque portal access metadata, never a substitute for master credentials, quick
unlock, keyring enrollment or automatic approval of a different destination.

Runtime/Python compilation only. No tests/harnesses added/run and no portal,
keyboard, GTK, token/configuration, vault or clipboard behavior probes. Manual
acceptance remains for all lifetimes, desktop denial/revocation, token rotation,
application/background exit, old portal versions/service changes, profile/link
changes, failed writes/concurrent writers, keyboard/focus/lock/cancel races and
accessibility. No production or full-parity claim is made.

Independent GPL3-only integration; KeePassXC Team/Felix Geyer source behavior is
GPL2-or-3. Portal API documentation is from the XDG Desktop Portal authors.

- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/osutils/nixutils/RemoteDesktopPortal.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
