# Auto-Type confirmation preferences

Preferences → Auto-Type now includes the stock settings:

- **Always Show the Entry Selector**, on by default (`Security/AutotypeAsk`).
- **Skip Confirmation for the Selected Entry**, off by default
  (`Security/AutoTypeSkipMainWindowConfirmation`). This applies to Type Entry
  from a vault window and is relevant when the first switch is on.

Explicit INI profiles share these keys with KeePassXC. Private profiles save
the booleans with their existing Auto-Type options. The older six- and
seven-field private formats retain their choices and gain only the new defaults.

| Invocation | Result |
|---|---|
| Global, always-show on | Choose an entry in the selector, then type |
| Global, always-show off, exactly one fresh entry/sequence match and a nonempty destination title | Prepare and type that match without the selector |
| Global, no matches or multiple entry/sequence matches | Show the selector |
| Type Entry, always-show on and skip-confirmation off | Confirm the selected entry once |
| Type Entry, always-show off or skip-confirmation on | Prepare and type the selected entry |

Choosing a selector row, pressing its **Type** button or Enter is the explicit
approval for that choice; the old redundant second confirmation is removed.
PICKCHARS still asks for character positions, with invalid input shown inline
so it can be corrected. Portal keyboard access, fresh destination capture,
native one-use token/working-revision/eligibility checks and per-key focus checks
still apply. Existing X11 destination selection remains; this update does not
add active-window capture to that backend.

Automatic single-match mode is available to the app's own user actions and the
current verified `org.gnome.Shell` D-Bus sender. Other callers of the public
AutoType method must choose an entry explicitly, even with always-show off.
Verification asks the session bus for the current Shell name owner without
activating a service; a failed lookup falls back to explicit selection. The
public method accepts no entry identifier or sequence. A request can use an
unlocked source when the remembered active vault is locked. The global shortcut
is ignored while a Keyslot window itself has keyboard focus, as upstream does;
app-menu actions can explicitly target the previously active external window.
Locked vaults now use the request-bound [Unlock for Auto-Type](autotype-unlock.md)
workflow with existing providers and destination checks.

One application-wide flow serializes capture, matching, selection, preparation,
PICKCHARS/confirmation and execution across vaults. Source and chosen-owner
epoch/identity/generation/snapshot, active-window ownership and dialog lifetime
are checked around workers. Internal owner handoff is allowed; user switching,
hiding, locking/closing, reloading, an unrelated dialog, stale state or shutdown cancels.
Window watches are disconnected on completion/cancel. Closing an owned chooser
as part of the handoff does not cancel the following step. No typing approval
is stored in the short-lived last-choice cache.

Canceling while typing may lock the chosen vault to stop its native helper;
portal execution also checks flow cancellation while waiting and sending keys.
Keys already sent cannot be withdrawn. Existing encrypted recovery remains in place. Relocking now applies only to the
vault unlocked for this flow, including cancellation; see [Unlock for Auto-Type](autotype-unlock.md). No live settings, vaults, input or processes were
used to validate this implementation.

[Chooser Search](autotype-search.md) now includes native search scopes and association variants.
The unlock form now offers a [vault chooser](autotype-unlock.md) across existing
locked vault windows without changing the destination or restarting expiry.
Remaining Auto-Type work includes sort preferences, portal persistence/clipboard typing,
global shortcut preferences and broader backend/accessibility acceptance.
Runtime/Python compilation only; no tests/harnesses or automated GTK, typing,
keyboard, portal, settings or vault behavior runs were added or performed.
Manual acceptance must cover the policy table, sender fallback, multiple vaults,
repeated shortcuts, owner handoff, cancellation/lock/hide/dialog races,
PICKCHARS correction and real X11/Wayland input behavior. This is not a production
readiness claim.

Behavioral references: KeePassXC Team/Felix Geyer GPL2-or-3 sources; Keyslot's
independent integration is GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoType.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/DatabaseWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
