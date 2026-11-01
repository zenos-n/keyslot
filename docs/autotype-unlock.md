# Unlock a vault for Auto-Type

A global request can now continue when all open vaults are locked. Keyslot uses
the active vault (or an existing vault window when none is active), captures the
Wayland destination before showing an unlock dialog, then uses the normal master,
key-file/hardware, quick-unlock or Polkit system-authentication provider. Provider
fallbacks retain this specific request. No credential is retained in the request
object and no login-keyring unlock is started implicitly. If an unlocked vault
already exists, the existing multi-vault matching path still uses it.

When multiple open vaults are locked, **Vault** appears in each provider's form.
Choose another locked vault without leaving the Auto-Type workflow. Duplicate
filenames include their parent path. The old provider form is closed and cleared,
then the selected vault's own master/quick/system provider and remembered key
components are used. No credential or provider state is transferred. Choices
use weak window references and captured canonical paths; a closed, busy,
already-unlocked or changed vault is rejected, with the old selection restored.
Selection during authentication does not redirect the in-flight operation.
The original destination, caller policy and monotonic expiry are preserved;
switching vaults or providers never recaptures a target or restarts the timeout.
Vaults opened after a form was built require a new invocation. There are no tabs.

The unlock form says **Unlock for Auto-Type**. After authentication, the exact
current snapshot/native identity/generation/path are checked, closing unlock
animations and existing credential-remembrance work are allowed to finish, and
matching/selection resumes with the captured destination. The normal
minimize-after-unlock window action is deferred for this workflow so it cannot
hide/cancel the continuation. On X11, the existing explicit destination chooser
opens after unlocking; no active-window-capture parity is claimed.

The pending request expires after180 seconds, earlier than the companion's240
second lease. Expiry is also checked directly against monotonic time, even if
the GTK timeout callback has been delayed. It serializes with ordinary Auto-Type flows. Canceling a form,
hiding/closing/switching its vault window, explicit locking, login unlock,
an unrelated dialog/error, path/session changes, desktop locking or shutdown
ends it. In-flight authentication is canceled through the existing session lock
path; late callbacks cannot resume typing. Normal provider initialization and
explicit provider fallbacks are the only allowed reset transitions. Recovery
review interrupts Auto-Type and proceeds as an ordinary explicit recovery/open
workflow; it cannot leave a continuation for some later unrelated unlock.

The destination is not silently recaptured after authentication. Expired or
changed Wayland leases must fail existing Focus/Check validation. Fresh native
matching, selected-entry approval/always-ask policy, public non-Shell caller
fallback, PICKCHARS, one-use native token/revision validation and per-key focus
checks still apply. Unlocking is not itself a typing approval. Another request
cannot replace the pending request's destination or provider callback.

**Relock Vaults Opened for Auto-Type** now follows the intent of stock
`Security/RelockAutoType`: the flow records the specific newly unlocked vault
and relocks that unchanged vault when the flow ends, including cancel/failure.
Already-unlocked vaults are not relocked just because this preference is on.
The old Keyslot behavior that locked any selected vault after typing is replaced.
Relocking is immediate; no delayed-relock timer or cached typing approval is
introduced. Normal inactivity/desktop locking remains independent. With relock
off, a successful unlock remains open as usual after the Auto-Type flow ends.

Selector Copy actions keep the chooser open, as upstream does. They fetch only
an explicitly selected field, disable competing selector input during the read,
and retain normal selected-vault clipboard ownership/timeout/secret hint/primary
selection. Copy does not end the temporary-unlock flow before placing the value
on the clipboard. Closing/hiding/relocking later retains existing owner-lock
clipboard clearing. The presenting window's explicit copy/hide policy still
applies and can end the flow. A stale form built before cancellation/relocking
is cleared instead of being presented after its session epoch changes.

Native core and companion are unchanged. Runtime/Python compilation only; no
tests/harnesses or automated unlock, Polkit/keyring/hardware, GTK, typing,
clipboard, portal, browser, profile or vault runs were added/performed. Manual
acceptance remains for all providers/fallbacks and wrong credentials, recovery,
initially hidden windows, X11/Wayland capture and expired leases, verified/untrusted
callers, repeated requests, all cancellation/timer/authentication/animation/save
races, multiple vaults, duplicate names, stale/busy/closed choices, repeated
vault/provider switches with the original deadline, old-provider callbacks,
Copy/lock clearing and relock on/off. Sort preferences, portal persistence and
clipboard typing, global shortcut preferences, full Qt6/native2.8 migration,
platform/accessibility acceptance and broader parity remain open. No production
readiness or complete replacement claim is established.

Behavioral references (KeePassXC Team/Felix Geyer, GPL2-or-3; independent Keyslot
integration GPL3-only):

- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/DatabaseTabWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/autotype/AutoType.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/DatabaseOpenDialog.cpp
