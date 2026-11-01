# Production release requirements

Keyslot is still a development build. Manual saving, interrupted-save recovery
and Save As are implemented for user stress testing. Normal Nix builds compile
only the runtime; existing development checks are opt-in. Automated runs were
stopped at the user's request. The historical results below apply to their frozen
checkpoints and do not establish production readiness of the current candidate.

Configuration discovery now supports KeePassXC2.8's XDG state layout with an
existing2.7 cache fallback, explicit CLI/environment overrides and single-file
mode. Invalid XDG base directories use standard defaults. Automatically selected
local layouts and symlink targets are checked around settings I/O; a detected
change requires reopening, and a late write is reported as possibly committed.
Default-selected login launchers preserve discovery; explicit local choices
stay fixed. Existing files are not migrated by discovery. See
[Configuration Layouts](configuration-layouts.md) for precedence, older launcher
limitations and non-atomic race handling. Package/Python compilation only;
no tests/harnesses or automated config/path/login/vault/GTK behavior runs.
Real2.7/2.8 profiles, encodings, override/permission/symlink/race cases, startup
and login behavior require user manual acceptance.

Group icon propagation now supports child groups, entries or both from Edit
Group. Native counts and a revision/group/icon/scope-bound, two-minute single-use
review precede one encrypted group-and-children transaction. Recycled descendants
are counted, ambiguous UUIDs rejected and unchanged icons skipped. Changed
entries use existing history/custom-data backports and configured history
limits; groups have no history. Drafts survive review cancellation/failure.
See [Group Icons](../engine/GroupIcons.md). Native/package/Python compilation
only; no tests/harnesses or automated GTK/native/vault/history/save runs.
Manual scope, icon/history/plugin preservation, stale-review, lock/cancel,
manual-save/recovery, format and accessibility acceptance remains open.

The [clipboard registry](clipboard.md) now tracks regular and primary-selection
providers, native GTK selections and built-in Copy actions. Explicit copies
carry KeePassXC's Linux secret hint. Timeout changes re-evaluate existing copy
ages; session lock/reload/close and shutdown clear only still-owned providers,
and minimize locking considers both clipboard deadlines. Clipboard managers can
ignore the hint or retain previously read data. Runtime/Python compilation only;
no tests/harnesses or automated clipboard/GUI/vault behavior runs. Manual
X11/Wayland, multi-window, selection, timeout and clipboard-manager acceptance
remains open.

[Window Behavior](window-behavior.md) adds stock copy/minimize/lower, minimize
after unlock and minimize-to-background preferences with INI mappings. Entry
copies and successful unlocks share guarded session/window hooks; link actions
use the same hide/minimize policy. Lowering uses companion version2/package0.2.0
with current bus-owner, focused GTK unique-bus/window-path and compositor-state
guards, no credentials or keyboard data. An absent/old companion fails with a
nonblocking message. Package/Python compilation and JavaScript syntax parsing
only; no tests/harnesses or automated desktop/config/auth/vault behavior runs.
Every real unlock path, focus/lock/dialog race, hide/minimize/relock, extension
upgrade and multi-window/X11/Wayland behavior remains manual acceptance.

Entry/group Properties now expose identity, activity and counts, plus paged
name-only plugin data and explicit sensitive inspect/copy/export. Selected removal
requires a native revision/object/value-bound review and uses existing encrypted
transactions and entry-history backport. Groups have no entry history. These
[properties workflows](../engine/Properties.md) have compilation evidence only;
manual GUI/history/export/recovery/permission-revocation acceptance remains.
No tests/harnesses or automated behavior checks were added/run for this update.

The Proton Pass reader now includes upstream 2.8 Wi-Fi and SSH-key handling,
with protected private-key attributes and annotated unknown record content.
Keyslot additionally protects unknown content and extra-field TOTP URIs,
retains structured/scalar/empty values, and assigns collision-free extra-field
names. Existing import review and encrypted save/recovery paths are used.
Custom-attribute names now have an explicit GTK suggestion menu, with paged,
case-insensitive numeric ordering and current-entry/recycle/passkey filtering.
The native RPC returns names only, never values. The shared
`AutocompleteSuggestions` preference is read/written separately so unrelated
settings saves cannot overwrite it. Private profiles keep a dedicated boolean.
Configuration failure leaves free-form editing available. Runtime compilation
only: real Proton exports, field protections, import/save/recovery, large-vault
suggestions, settings, keyboard and lock cancellation await user manual
acceptance. No tests/harnesses or automated behavior runs were added/performed.

A user reported vault metadata behind an Unlock Database prompt after boot.
Inspection found the normal-launch/manual-prompt plus login-keyring completion
handoff could leave a stale manual prompt on an already unlocked view. Login
unlock now dismisses and clears the tracked prompt before starting, canonicalizes
the remembered path, and keeps the locked view until completion. Current vault
rendering dismisses obsolete prompts and refuses locked/stale snapshot objects;
security locking switches the view first, clears pending unlock requests, and
worker delivery rechecks its epoch after state observers. Already unlocked
vaults do not receive stale ordinary unlock requests. Changed-vault reauthentication
continues to preserve the previous unlocked data explicitly. The screenshot
establishes metadata visibility; password/autofill bypass remains unconfirmed.
No user restart, vault/process action or automated behavior runs were performed;
boot/activation/keyring/lock acceptance remains manual.

Adwaita presentation maps standard KeePass icon IDs without database rewrites.
The entry picker offers a searchable, paged Adwaita catalog. Additional icons are
embedded with an explicit custom-icon name marker and PNG fallback; current
custom images are retained. Only names present in the packaged theme are used
for live themed rendering. Icon metadata/cache work remains vault-epoch scoped.
Search options now use an available Adwaita icon and a window-aware minimum
content width. These UI changes are compiled candidates with visual/manual
acceptance still pending, and no new tests or automated runs.

SSH generation now uses the upstream 2.8 Botan generator with the pinned 2.7.12
parser/agent. GTK offers Ed25519, RSA and ECDSA, key sizes, comment and attachment
name, plus optional protection with the entry's current password. Private bytes
stay native; public review precedes a single-use, revision-bound save of private
and `.pub` attachments with the selected KeeAgent source. Existing attachments,
external files and loaded agent keys are preserved, and policy is unchanged.
Native parse/decrypt validation runs as part of generation. No automated
behavior runs are performed here. OpenSSH signing/import, algorithm/encoding,
cancel/expiry, history/save/recovery and real desktop acceptance remain manual;
runtime compilation alone does not establish production readiness.

Configurable application shortcuts now include staged recording, conflict
replacement, disabling and default resets, shared KeePassXC action-key overrides,
private Keyslot-only actions and help generated from active bindings. Reset
removes individual keys atomically and refuses stale shortcut snapshots or
settings with descendant keys. Unknown keys and unsupported Qt sequences are
preserved. Entry copy/edit/delete actions yield while text is focused or dialogs
are open, and recording temporarily inhibits application accelerators. The GUI
records one combination per action; multi-stroke and unavailable platform keys
remain inactive until replaced. This batch is runtime compilation only; user
keyboard-layout, recording, conflict and desktop acceptance are pending.

The generator now manages a persistent custom word-list library beside the
selected KeePassXC configuration, using its existing wordlists directory.
Import copies the selected regular file through private staging, validates it
with the upstream parser, and publishes without overwriting existing names.
Empty lists are rejected and small lists retain the upstream warning. Removal
requires confirmation and an unchanged regular file; original sources and
installed lists are preserved. UI and file/parser acceptance remain with the
user; this batch has runtime compilation only and no new tests or automated runs.

The saving model keeps the saved-file revision separate from the current working
revision. Manual edits create private encrypted checkpoints with atomic journals
and owner locks. Explicit Save commits them; forced security locks erase the
unlocked helper before optional keyless encrypted commits. Failed or deferred
commits remain available through independent recovery working copies. Recovery
storage cannot be used as a Save As destination, and working copies remain
labelled until saved to a normal location.
The main menu also exposes all inactive recovery records independently of the
original file and last-vault preferences.

Save As reviews the destination and working revision before replacing a file,
keeps an encrypted backup of a replaced destination, retargets the open vault,
updates remembered key/login settings and resolves the originating recovery
record after the new file is durable. External conflicts support merge,
discard/reload, encrypted copy and reviewed overwrite. Closing and quitting
support Save/Discard/Cancel. User acceptance of these new paths remains open;
no further test runs are being performed.

Recycle-bin workflows now include original-location entry/group restore,
bulk entry restore, Restore All Contents, Empty Recycle Bin and explicit
permanent deletion, including when recycling is disabled. The native helper
binds confirmation to the exact selection and working revision, counts nested
groups/entries, and uses upstream deletion records inside the existing encrypted
transaction/save model. Missing original locations fall back to the root group;
the restore review also offers an explicit destination. These additions are
runtime-build candidates for user manual stress testing, with no new tests,
harnesses or automated runs.

Report additions include reused-password groups, browser permission/URL
inventory, filtering, reviewed report exclusion and single/shown permission
reset, plus passkey/TOTP statistics. HIBP online checks require per-run consent,
send only five SHA-1 characters over HTTPS and request padded responses. Full
hashes and matching stay in the native helper. Offline checks read an extracted
SHA-1 corpus in chunks, allowing progress and cancellation between chunks.
Failures/cancellation retain visibly partial findings; refreshing the report
clears previous results. Unresolved references and ambiguous IDs are counted as
unchecked. Empty/malformed data cannot produce a clean result. User desktop,
live network and large-corpus acceptance remain pending; runtime compilation
alone does not prove these workflows. No additional tests or automated runs.

Search now offers whole-vault, direct-group and recursive-group scope,
case sensitivity, password/protected-custom-field matching, explicit recycled
and disabled-group controls, Enter-to-search and syntax help. Whole-vault
matches are no longer hidden by the selected sidebar group. Recursive browsing
excludes recycled descendants unless browsing a recycled group. Search defaults
map stock SearchLimitGroup/GUI SearchWaitForEnter and private Keyslot recursive
preferences; queries and temporary switches are not written to configuration.
Pending, waiting, failed and stale requests are distinguished in the UI. These
additions are compiled candidates for user acceptance, with no new tests,
harnesses or automated behavior runs.

Icon additions include review-bound unused-icon removal preserving current,
history, recycled and editor-draft references, plus user-initiated website icon
download/review/preview. Candidate site/parent-domain and optional DuckDuckGo
addresses are shown before requests; entered credentials/query/fragment are
stripped, cookies/cache are disabled, redirects are bounded with no HTTPS
downgrade, responses are capped and each request is limited to at most 15 seconds.
Network requests run in a separately cancellable helper with no open database,
allowing vault/browser operations to continue; replies are bound to their native
request and vault revision. Images reuse native normalization/deduplication, SVG byte-only
conversion and existing encrypted transactions. ICO normalization selects the
largest supported frame. HIBP now shares the bounded transport while retaining
its fixed HTTPS/padded-range policy. New GUI/network/image/cleanup acceptance is
pending, with runtime compilation only and no new tests or automated runs.

Authenticated browser new-login saves now honor boolean/string downloadFavicon
requests through an explicit switch in the existing GTK consent dialog. The
legacy save RPC still returns a boolean; an additive result RPC identifies the
exact new native entry for optional queued icon work. Browser response and
credentials complete before network activity, with nonfatal icon failure. The
target is reserved at credential-save completion and remains bound to database
identity, UUID, website and original icon, including while waiting in the queue;
unrelated in-vault saves may continue, while target changes/deletion/reload
prevent attachment. Assignment waits for modal editors, manual downloads take
priority, and lock/close/integration disable cancels queued/active work without
extending idle time. Existing-entry updates retain upstream icon behavior. Picker
utilities now precede the catalogue. Native/runtime compilation is the current
evidence; browser/network/desktop acceptance remains user-owned, with no new
tests, harnesses or automated behavior runs.

Browser rules now have GTK entry and group settings using upstream custom-data
flags, tri-state inheritance and connection-restriction IDs. Entry controls show
forced group rules; group rules include www matching and inherit/all/one-paired-
connection modes, retaining disconnected existing restrictions. Only changed
fields are written, preserving unrelated and noncanonical untouched metadata.
Native target uniqueness, recycled-state and reviewed-revision guards precede
the existing transaction/save model; entry edits use upstream history updates.
These new controls have runtime compilation evidence only, with user manual
browser/inheritance/concurrency acceptance pending and no automated runs.
Additional Websites now has dedicated GTK create/edit/remove workflows over the
existing upstream URL attributes. Protected list values are masked and discarded
before UI delivery, explicit editing uses a masked input, and names are allocated
without replacing existing fields. Existing attribute revision, duplicate-name,
history and encrypted-save behavior is reused. User manual URL/reference/privacy
and desktop acceptance remains pending; no new tests or automated runs.

Entry actions now include same-group duplication through upstream Entry::clone,
with new UUID/time information, optional stock title suffix, username/password
references and history. Selected-entry tag and expiry actions use a single-use,
two-minute native review bound to database identity, working revision, exact
unique nonrecycled UUIDs and canonical choices. Review reports selected/changed
counts and masked protected titles; no-ops do not write. Changed entries commit
together through the existing encrypted/manual-save transaction, with upstream
history updates. Password copying and reference creation stay in the native helper. User manual
clone/metadata/history/save/concurrency acceptance remains pending; this batch
has runtime compilation evidence only and no new tests or automated runs.

Browser metadata inventory now implements the 2.8 get-database-entries action
with standard fields and error codes19/16. It requires a current authenticated
association and a default-OFF shared Browser/AllowGetDatabaseEntriesRequest
permission. Enabling the GTK switch confirms its broader inventory scope,
including hidden-entry metadata and resolved references/protected values.
Native traversal and field resolution match upstream, including skipping the
recycle-bin group itself rather than changing subgroup traversal. Shared policy
is read before/after enumeration, GUI revocation is checked before delivery,
and malformed/unreadable policy fails closed. Unrelated settings writes do not
rewrite the dedicated shared permission. Output is bounded for the encrypted
transport and returns an error rather than a partial list or transport restart.
Fresh permission reads request only that key and use a five-second RPC timeout;
opening Preferences refreshes its switch without writing the configuration.
No vault mutation, idle touch or browser-protocol version spoofing is added.
User browser/permission/reference/traversal/large-list acceptance remains pending;
this batch has runtime compilation only and no new tests or automated runs.

## Verified checkpoint

The [2.8 security backports](../engine/SecurityBackports.md) and
[serialization corrections](../engine/SerializationFixes.md) pass native and
application regressions. Coverage includes crafted encrypted legacy files,
browser crypto bounds/reference rejection/error 34, history metadata, effective
C++ deallocation scrubbing, XML attachment retention and stream-cipher boundaries.
The new KDBX4/Argon2id defaults and all 18 advertised KDBX4 cipher/KDF/compression
combinations pass, together with upstream KDBX3/4 encrypted-copy fixtures.

The actual upstream KeePassXC-Browser 1.10.4.1 on Chromium 155 passes pairing,
login fill, TOTP, generation, saving, groups and DOM WebAuthn create/get, including
independent signature verification. These results are regression evidence, not
an independent security audit or complete platform acceptance.

Frozen code artifacts: app `/nix/store/nhcfyvijijq2hgkq1zhlcv4vkrx07ky9-keyslot-0.2.0`,
engine `/nix/store/r5vl42yi221vg3jd7wvkxfwd4w8rad45-keyslot-engine-2.7.12`.
Full log: `/tmp/keyslot-production-security-final.log`; browser acceptance:
`/tmp/keyslot-production-real-browser-final.log`. Documentation was updated after
validation without changing runtime code.

The subsequent recovery/foreground-queue implementation also passes all existing
323 backend tests and 19 application gates, plus the existing 332 native checks.
No new tests or harnesses were added for that batch, as requested by the user.
Failed edits restore a verified encrypted pre-mutation snapshot; unavailable keys
retain an encrypted copy and report its location. Unexpected native failures
preserve completed snapshots. Background status polls can queue behind foreground
saves. The updated trial app is `/nix/store/z5ilm7zc1qxsbd82gfgxvf80a3na8pr4-keyslot-0.2.0`;
log: `/tmp/keyslot-recovery-build.log`. The running user instance was preserved.

The subsequent custom-attribute/reference-editing batch passes the same existing
323 backend tests, 19 application gates and 332 native checks. Attribute renames
preserve protection and history, reject collisions and guard reviewed edits
against database changes. The GTK picker inserts standard UUID references from
paged entry metadata without fetching passwords. No tests or harnesses were
added; the new picker interaction flow still needs manual desktop acceptance.
Trial app: `/nix/store/8sky8xic5gdys620sm44pj9i6rdx8fbj-keyslot-0.2.0`;
engine: `/nix/store/c163v5g0jf9pf66kdafyin1gx47i9z71-keyslot-engine-2.7.12`;
log: `/tmp/keyslot-reference-editing-build.log`. The trial profile was updated;
the companion extension and running user instance were preserved. This remains
a development build. Documentation was updated after runtime validation.

The generator batch adds upstream word-case/separator controls, installed/custom
word lists, 999-character/100-word limits, small-list warnings, strength/entropy
display, edited-result estimates and separate private settings containing no
generated results. The same existing 323 backend tests, 19 application gates and
332 native checks pass; no new tests or harnesses were added. Existing browser
protocol acceptance exercises the richer default-generator flow. Manual custom
word-list and edited-result acceptance remains open.
Trial app: `/nix/store/g9sjyg66mkk6lkn6ry5p8q7iqp6kbwna-keyslot-0.2.0`;
engine: `/nix/store/f64jvxamcjqcmfvg67chk5pzcypypj2i-keyslot-engine-2.7.12`;
log: `/tmp/keyslot-generator-options-build.log`. Only the trial app was updated;
the companion and running user instance were preserved. Documentation was
updated after runtime validation.

The GUI command-line batch passes the existing 323 backend tests and all 19
application gates, with the native engine unchanged from the verified 332-check
checkpoint. No tests or harnesses were added. The package now supplies a
`keepassxc` GUI launcher with lock, key-file, stdin, minimized and diagnostic
options. Manual use of upstream sample vaults in a private display/bus verified
primary and remote stdin unlock, multiple-file input including a missing file,
hidden background state, headless diagnostics/lock, terminal echo restoration,
and cancellation with partially typed input. A stopped-background-process issue
found during manual use was corrected by reading the TTY in the invoking process
group and forwarding only a pipe. Cancellation terminates that reader and flushes
unfinished input. Generator validation errors now stay on their form.
The core-dump guard runs before local option processing so the TTY reader also
inherits it. The final build passes the same existing checks.
Trial app: `/nix/store/kpg714h2941y13vj1c6ckhz67ryr529d-keyslot-0.2.0`;
unchanged engine: `/nix/store/f64jvxamcjqcmfvg67chk5pzcypypj2i-keyslot-engine-2.7.12`.
Logs: `/tmp/keyslot-gui-command-line-secured-final.log` and
`/tmp/keyslot-cli-manual-acceptance.log`. The packaged alias also ran headlessly.
Only the trial app was updated; the companion and user instance were preserved.
Broader key-component/terminal and actual GNOME lifecycle acceptance remain
open. Documentation was updated after runtime validation.

Explicit `--config`/`--localconfig` profiles now use the pinned Qt INI codec and
support `KPXC_CONFIG`/`KPXC_CONFIG_LOCAL`. Supported startup, timeout, integration
and generator settings are shared with KeePassXC; other keys remain in the INI.
Private manual use verified exact-second timeout import and reopening, generator
round trips, typed Qt values, nested option changes, stale-writer rejection,
read-only two-file preservation, repeated unknown QVariant rejection, same-file
roles, symlink guards and profile-bearing login launchers. A disposable desktop
verified primary/remote same-profile commands, changed-profile rejection,
environment defaults and graceful quit. The new engine passes the existing 332
native checks. The existing 323 backend checks and all 19 application gates pass
(backend 320.47 seconds); no tests or harnesses were added. All 37 packaged
Python files match the current source. App:
`/nix/store/pwh7h4fr60k93f5ag3y1jrnv494i8avp-keyslot-0.2.0`;
engine: `/nix/store/rdxhpdrdijldl6pmv8hvpy17bydv28im-keyslot-engine-2.7.12`.
Logs: `/tmp/keyslot-ini-profile-build.log`,
`/tmp/keyslot-ini-profile-final.log` and
`/tmp/keyslot-ini-manual-observations.txt`. This batch has not been installed or
published. A subsequent batch implements remembered key-file/hardware selections
and multiple-vault startup restoration in separate windows, with independent
recent-file/session/key-component settings, hidden background restore, keyring
unlock only for the enrolled vault and open-session persistence on quit. Private
GTK use verified prefilled key files and a real password-plus-key-file unlock;
remote stdin unlock used the remembered file, while an explicit missing file
overrode it and failed without overwriting the remembered choice. Two-window
startup/background restore, active-window persistence, missing-file filtering,
last-window close, independent remember flags and hardware-slot string conversion
also passed. A disposable GNOME login keyring unlocked only the enrolled vault
and kept both windows hidden; its enrollment path stays independent of the
focused window. Physical hardware-key use remains unverified. Existing package
checks passed for the restoration work; the enrollment-path correction was also
verified against the disposable keyring. No tests/harnesses were added. Evidence:
`/tmp/keyslot-session-manual-observations.txt` and
`/tmp/keyslot-remembered-session-final.log`. Remaining config migration includes
other unsupported preferences.

First-launch compatibility now reuses an existing stock INI profile when no
private preferences have been saved. Existing private settings are retained;
unreadable stock settings queue a notice and fall back without altering either
stock file. A read-only `GetConfigurationProfile` handshake returns an opaque
fingerprint and leaves the public status properties unchanged. Explicit requests
reject older or differently configured primaries before forwarding; ordinary
launches still attach to an older running app. Private real-primary acceptance
covered legacy rejection, automatic reuse across restarts/sidecar creation,
same/different profiles, private-setting preservation and unreadable automatic
versus explicit settings. The actual live legacy user's primary was also probed
read-only with aggregate state unchanged. All existing 323 backend checks and 19
application gates pass (backend 318.44 seconds); the native engine is unchanged.
No tests/harnesses were added. Source-only checkpoint:
`/nix/store/2fxh9h5a1v2j881yass1zd8j2qv0c9q6-keyslot-0.2.0`;
logs `/tmp/keyslot-profile-upgrade-build.log` and
`/tmp/keyslot-profile-upgrade-manual-observations.txt`. This work awaits the next
package batch. Legacy INI-key migration, remaining preferences and broader
concurrent-owner replacement/desktop acceptance remain open.

External-file monitoring now combines directory events (including atomic
replacement) with asynchronous metadata polling. Native revision checks are
passive; only a confirmed reload reserves the foreground worker slot. This
preserves browser/URI actions during ordinary checks and defers reload around
forms and file choosers. The native core keeps the current open data on reload
failure; persistent notices offer Reload or encrypted Save Copy. AutoReloadOnChange
is mapped to the GNOME preference and private settings. Actual GTK use verified
external changes, no redundant reload after own saves, preserved drafts and
stale-save refusal, manual reload/revert, missing/corrupt/changed-key retention,
official-CLI-readable recovery copies, actual chooser deferral, polling fallback,
unchanged idle time with an active search and cancellation on idle lock. The
existing browser and URL gates initially exposed foreground contention in checks;
the passive-check correction passes both unchanged gates and the final full
323-backend/19-gate package run (backend 324.20 seconds). No tests or harnesses
were added. Native engine 8ibf9x passes the existing 332 checks. Checked app:
`/nix/store/f01aszsr68nb0mlqjcnamv711v1kb4is-keyslot-0.2.0`;
logs `/tmp/keyslot-file-watch-verified.log`,
`/tmp/keyslot-watch-existing-regressions.log` and
`/tmp/keyslot-watch-manual-observations.txt`. Physical network/hardware behavior,
broader concurrent-source races and changed-key reauthentication remain open.

The subsequent changed-key recovery batch supplies new credentials without
locking or discarding the previously open database. The native helper swaps in
a candidate only after successful authentication and a stable source revision.
The dialog remains open after credential errors and offers an encrypted copy of
the old data. Successful reopening refreshes the authorized login-keyring
credential and remembered key components, clears old views and invalidates the
previous quick-unlock credential. Manual Reload uses the same recovery path and
defers around forms and file choosers.

Private real GTK use verified password/key-file rotation, wrong-password and
wrong-component retention, cancellation, dialog-driven encrypted recovery readable
by stock KeePassXC, successful composite and password-only reopening, actual
disposable GNOME login-keyring updates, key-file memory removal, quick-unlock
invalidation, editor deferral and idle-lock cleanup. All existing 323 backend
checks and 19 application gates pass (backend 328.06 seconds), alongside the
existing 332 native checks. No tests or harnesses were added. Checked app:
`/nix/store/b19813zap4zq1h9h1035fd12d50mx8bf-keyslot-0.2.0`;
engine `/nix/store/5wi36i91zkdnji0y9wpymw99m8a2sq97-keyslot-engine-2.7.12`.
Evidence: `/tmp/keyslot-reauth-build.log` and
`/tmp/keyslot-reauth-manual-observations.txt`. Physical hardware keys, network
filesystem races and source replacement during key derivation remain unverified.
The running user application and system generation were preserved.

## Release blockers

- Complete the KDBX 3/4 cipher/KDF and key-component preservation matrix. Exercise
  interrupted saves, backup failure, concurrent writers, key rotation and
  recovery when the original source disappears during a failed mutation. Keep
  the last usable state available for encrypted recovery.
- Extend browser/session acceptance for concurrent foreground actions, denied
  and revoked permissions, cancellation/lock races and fresh authentication.
- Complete real GNOME 50 lifecycle acceptance: close-to-background visibility,
  explicit quit, screen lock, suspend/resume, login-keyring unlock, idle/Never,
  quick-unlock fallback, Wayland clipboard and auto-type portal permissions.
- Finish release packaging checks for independently installed app and extension,
  native-host discovery, upgrades and migration. Publish reviewed source commits
  and update the two ZenPkgs packages only after the release candidate passes.

Hardware keys and desktop interactions require actual hardware/session evidence;
an isolated GTK test does not substitute for those checks. Do not disturb the
user's open vaults or desktop session to perform acceptance tests.

## Replacement compatibility

The [coverage matrix](parity.md) remains the full replacement checklist. Security
backports retain the pinned 2.7.12/Qt5 API and do not implement all 2.8 features.
The [official 2.8 release](https://keepassxc.org/blog/2026-10-21-2.8.0-released/)
adds features beyond the pinned baseline. Runtime candidates now include configurable
shortcuts, SSH generation, additional Proton Pass types, passkey/TOTP statistics,
attribute-name suggestions, and remote synchronization. Linux Polkit session
unlock now has an encrypted native broker/process-keyring adapter, explicit enrollment, per-release authorization, cancellation/revocation
and a packaged system action. Its [requirements](../engine/PolkitUnlock.md) and
real installed GNOME/agent/PAM/lifecycle behavior still require manual acceptance.
All implemented candidates still need manual acceptance. Remote sync now has
compatible encrypted location settings, command review, download/two-way merge/durable local save/pre-upload check/upload and
cancellation. Its [limits](../engine/RemoteSynchronization.md), including remote
write races and unknown failed-upload outcomes, require manual acceptance.
Existing gaps such as broader field-reference and breach-report acceptance, advanced
preferences, import/export coverage and accessibility remain open.

The supported target is Linux/GNOME; one window per database replaces tabs at
the user's request. Platform-specific Windows/macOS features must be explicitly
scoped rather than counted as implemented on GNOME.

Drag-and-drop now has app-local entry/group payloads, Ctrl-copy, sibling group
positions, reviewed recycle/restore, KDBX file opening and revision/source-bound
attachment batches. [Limits and manual acceptance](../engine/DragAndDrop.md)
remain open, including actual recycled-item transfers and GTK
drag negotiation, cancellation, modifiers, save/recovery and accessibility.

Recycled entries/groups now support reviewed same/cross-vault copy/move and
recycle-bin destinations, with native source-state metadata and save receipts
before permanently removing recycled originals. Original-location Restore
remains separate. Native group/entry UUID ambiguity is rejected. Whole recycle-bin
groups and containing ancestors support reviewed copy/move: local moves retain
the designated role, copied groups do not replace destination bin metadata,
and cross-vault cleanup clears source bin metadata after the saved receipt. Actual file/history/receipt/lock/GUI behavior of the
new paths remains manual and is not proven by package compilation.

Local entry/group transfers now honor Manual Save and use the existing encrypted
dirty checkpoint instead of forcing an on-disk save. Cross-vault destination
receive and source cleanup still force durable saves for their receipt contract.
The review text distinguishes these policies. This correction needs user manual
save/recovery acceptance; compilation is the only evidence for this revision.

Automatic-lock policy now maps stock screen/suspend, user-switch and minimize
settings. GNOME/logind initial state, service owner changes, session identity,
sleep/active signals, stale query guards, job/render gating and bounded clipboard
grace are implemented. [Desktop-lock policy](desktop-locking.md) documents
requirements and incomplete evidence. Package/Python compilation is the only
validation for this revision; actual session/login/clipboard/lock/save lifecycle
and preferences migration remain for user manual acceptance.

Entry Privacy now maps stock username/notes/password-preview visibility, empty
password placeholders and monospace notes. A selected-entry native batch returns
only requested display fields and password-empty metadata, with explicit bounded
preview truncation and unchanged full Copy. Lifecycle/cancellation guards and
passive queue behavior are documented in [Entry privacy](entry-privacy.md).
Native/package/Python compilation is the only validation for this revision;
actual privacy, reference, focus/selection/lock, config and clipboard behavior
remains user-manual. Copy/minimize/background preferences are now implemented in
[Window Behavior](window-behavior.md), with manual desktop acceptance open.
