# KeePassXC feature coverage

Target: a GNOME HIG client with drop-in behavioral compatibility with the official
KeePassXC application. Current status: **alpha, incomplete parity**. No percentage
claim is made. The pinned engine baseline is KeePassXC **2.7.12**; upstream
security changes are being backported from **2.8.0**, released 2026-10-21.
The [release requirements](release-readiness.md) track validation and the new
upstream feature inventory; no 2.8 feature-parity claim is made.

**Historical 0.2 development verification:** the native helper and full Nix application
package build on the GNOME 50 host. All 323 tests pass without skips. Nineteen
gates cover the backend, GTK, real GNOME login keyring, terminal signals,
encrypted browser workflow, passkey/SSH management, GCR, actual agent forwarding,
auto-type review/X11 delivery, real encrypted libsecret interoperability and
mapped icon/appearance editing and reviewed cross-vault entry transfer with
partial-save warnings, bulk selection/actions, recursive group transfers and
entry URL activation through an actual private URI handler and native/GTK entry history inspection and live TOTP/QR workflows.
The Secret Service coverage includes fifteen native and fifteen controller tests.
Each GTK test owns a private bus and
checks a completion marker, so another test's application cannot satisfy its gate.
Native build gates additionally pass 332 security/serialization checks and 331
under AddressSanitizer/LeakSanitizer. This includes 2.8 security backports,
current/history XML attachment retention and exact stream-cipher boundaries.
New-vault KDBX4/Argon2id defaults and all 18 advertised KDBX4 cipher/KDF/compression
combinations pass, alongside upstream KDBX3/4 encrypted-copy fixtures. Actual
KeePassXC-Browser 1.10.4.1 on Chromium 155 passes pairing, fill, TOTP, save, groups
and DOM WebAuthn with independently verified signatures after these changes.
These results apply to earlier frozen checkpoints. New manual-saving, recovery
and Save As changes compile but await user stress testing; no current full-gate
claim is made. Full feature and platform acceptance remains open.

Inventory sources: [KeePassXC feature list](https://github.com/keepassxreboot/keepassxc),
[user guide](https://keepassxc.org/docs/KeePassXC_UserGuide), and the installed
`keepassxc-cli --help`. The full target includes user-visible workflows, command
interfaces, integration protocols, data preservation, migrations, and packaging.

| Capability | Current implementation | Acceptance remaining |
|---|---|---|
| GTK4/libadwaita interface | Adaptive sidebar/list/details, native dialogs/actions | Visual review, screen reader and keyboard testing |
| KDBX open/save | Native upstream Database/format implementation; encrypted copy; optional manual Save and encrypted dirty checkpoints; Save As retargeting with reviewed destination replacement; failed refresh retains open data | User manual stress acceptance of new saving/recovery workflows; broader KDBX3/key-component/unknown-data and interrupted-save matrix |
| New databases | Password, existing/generated key file, key-file-only and hardware-key options | Real-core and hardware tests, creation wizard polish |
| Composite unlock | Password, key file, key-only | Physical YubiKey/OnlyKey and malformed-key tests |
| Entry editing | UUID-based create/edit/move/recycle; empty/multiline/Unicode fields, tags, expiry, standard/custom icons, text/background colors, URL-override metadata and report exclusion; native/GTK round trips preserve credentials/history; same-group duplication with upstream UUID/time/title/reference/history options and reviewed bulk tag/expiry changes | Entry Properties inspector with identity/timestamps/history count and masked plugin-data inspect/copy/export/reviewed removal is implemented; new properties/actions await user manual acceptance and broader format matrix |
| Entry URL activation | Native placeholder/reference/conversion resolution, Qt URL normalization and GTK URI launcher; explicit override action; reviewed native command execution with masked previews, remembered/revoked approvals and no implicit shell; sealed native-to-native linked-vault credentials, path/key-file fingerprints, open-window reuse/manual fallback, lock cancellation and minimize preference; native and mapped real-handler tests pass | Linked-vault login-keyring enrollment, broader handler/portal/Wayland/minimize and failure acceptance |
| Groups | UUID browse/create/rename/move/notes/recycle; duplicate names; standard/custom icons, inherited search settings, tags and expiry; configurable new-entry group-icon inheritance with selected-group tracking until an explicit icon choice; reviewed recursive icon application to child groups/entries/both in one encrypted edit with history for changed entries; optional recursive entry browsing with separate recycle-bin context; browser tri-state rules and inherited/all/paired-connection restrictions | Group Properties inspector includes identity/timestamps/counts and masked plugin-data inspection/reviewed removal; remaining custom group settings and broader format/desktop acceptance; properties/recursive browsing await user manual acceptance |
| Search | Upstream EntrySearcher with whole-vault/current-group/direct-or-recursive scope, case and password/protected-custom-field controls, recycled/disabled-group options, Enter-to-search and syntax help; pending/error/stale-query handling; global matches bypass sidebar filtering; stock scope/Enter configuration keys and private recursive-view defaults | New search controls await user manual acceptance, especially grammar/protected/reference/large-vault behavior; no additional automated runs |
| Password generator | Upstream random passwords/diceware, 1–999 characters/1–100 words; character groups, custom/excluded characters, look-alike exclusion and group requirements; word case/separator, installed/custom lists with small-list warning; upstream strength/entropy display, edited-result estimates and private remembered settings; saved generator options reused by entry Generate, in-draft options and optional new-entry auto-generation with edited-field/cancel guards; profile-scoped persistent word-list import/discovery and reviewed removal, no-clobber duplicate copies and upstream import validation | New library workflows await user manual acceptance; broader file/parser/desktop behavior remains open; no automated runs |
| Credential clipboard | Fetch on demand, configurable owned regular/primary expiry including native GTK selections, explicit-copy secret hints and per-session lock/close cleanup that preserves newer owners | New registry paths have compilation evidence only; Wayland/X11, multi-vault, selection, expiry/Never and clipboard-manager behavior remain manual |
| TOTP | Native standard/Steam/custom key/link setup, algorithm/period/digit controls, retained legacy formats, persistent KeePass2 removal, live reveal/countdown/progress, fresh code/password+code copy, short-lived QR display/link copy/private SVG export; RFC vectors, clock edges, independent QR decoder and mapped GTK lifecycle/clipboard checks pass | Broader authenticator/format and physical desktop clipboard/accessibility acceptance |
| Custom attributes | Add/edit/rename/delete/copy with protection flag; atomic rename, duplicate-name rejection and revision-guarded editing; paged name-only suggestions from non-recycled entries, excluding current/reserved keys, with shared preference | Suggestion/configuration/keyboard/lock acceptance, ordering UI and broader format acceptance; no new automated runs |
| Attachments | File-based import/save/confirmed replace/remove; no 40 MiB frontend cap; reviewed local-file drop batches with explicit replacement consent, native source/revision guards and one history/transaction update | Dropped batches limited to 32 files/256 MiB; compilation only, actual GTK/filesystem/history/save/cancel acceptance and network filesystem coverage remain open |
| History | Native any-version comparison and full field/property/Auto-Type/custom-data/attachment metadata preview; explicit protected-field reveal, historical attachment export, confirmed restore/remove/delete-all, revision guards and current-version preservation | Broader format/large-history/accessibility acceptance |
| Field references | Preserved; retrieval delegated to upstream; searchable, paged UUID-reference picker for entry fields, notes, URL override and custom values | Broader resolution and manual desktop acceptance |
| Recycle bin | Recycle entries/groups; revision-bound review of exact recycle/permanent counts including nested contents; explicit permanent deletion with disabled-bin support; original-location single/bulk entry and group restore with destination override/root fallback; direct same/cross-vault recycled-item copies/moves with source-state counts, destination-bin warnings and durable receipt-before-permanent-source-removal; Restore All and Empty Bin; upstream deletion records and existing encrypted transaction/save policy | Newly built restore/purge/disabled-bin workflows await user manual acceptance; no additional automated runs |
| Custom icons | Exact upstream 69-icon catalogue and existing picker/import/export/deletion/lock-safe previews; reviewed unused-icon cleanup retaining current/history/recycled/draft references; explicit favicon site/parent-domain/optional DuckDuckGo lookup with sanitized URL review, bounded redirects/requests, SVG conversion, largest-frame ICO normalization, preview-before-storage and native transaction/save policy | New downloader/cleanup await user manual acceptance; broader malformed/legacy images, CDN/network/cancellation and large-library behavior; no new automated runs |
| Database settings | Metadata, defaults, history/recycle/compression, cipher/KDF tuning and calibration, key rotation | Real-core tests, legacy format upgrade UX, remaining advanced preferences |
| Multi-database | One window per database, separate helpers/keys/workers/views, path deduplication and independent/all-database locking; reviewed single/bulk entry and recursive group copy/move with native streamed KDBX, history/attachments/icons/settings, fresh cross-vault UUIDs and saved-destination-before-source-removal ordering; GTK selection/cancellation and real pointer/Shift-range/secondary checks ; app-local entry/group drag-and-drop with Ctrl-copy and sibling positions; recycled-item and whole-bin transfers with explicit role warnings; local Manual Save policy | New drag/recycled/bin-role/manual-save paths have compilation evidence only; actual pointer/selection/modifier, lock/close/cancel, format/filesystem/save/recovery and accessibility acceptance remains open; tabs intentionally omitted at user request |
| Merge/synchronization | Upstream merge, no-op detection, stale-write refusal, encrypted backup; directory monitoring plus asynchronous metadata fallback, native revision checks, deferred/optional automatic reload; changed-source credential retry retains previous data until successful open, with encrypted recovery copies and refreshed keyring/key-file memory | Broader conflict/merge, hardware-key reauthentication and network filesystem behavior |
| Import/export | Upstream KeePass 1/XML, Bitwarden, 1PUX/OPVault, Proton Pass and mapped CSV import; paged review; Proton2.8 Wi-Fi/SSH-key records, protected unknown/structured content and extra TOTP fields with collision-free names; XML/CSV/HTML export and attachments | New Proton records await user manual acceptance, broader import/export fixtures, live review/mapping UX, complete icon output; no new automated runs |
| Reports | Upstream health/statistics, reused-password groups, passkey/TOTP counts; browser URL/Allow/Deny inventory with protected-URL hiding and filters; reviewed per-entry report exclusion and single/shown permission reset; user-confirmed padded HIBP online range checks and chunked extracted SHA-1 corpus checks, native-only hashes/matching, progress/cancellation/partial results/retry | New reports await user manual acceptance; broader corpus/network/reference and large-vault behavior, accelerated offline lookup and report actions remain open; no new automated runs |
| Browser integration | Existing opt-in authenticated transport, matching/permissions, pairing/fill/TOTP/save/group/generator/passkey workflows; new-login downloadFavicon handling with save-consent switch and post-reply, native-entry-bound, cancellable queued icon assignment through the separate keyless helper; legacy save RPC/protocol responses retained; GTK entry/group visibility, auto-submit, HTTP-auth and www matching controls with inherited paired-connection restrictions, changed-field-only saves and native revision guards; dedicated additional-website create/edit/remove with protected masking and literal reference retention; 2.8 all-entry metadata inventory behind authenticated/default-off shared permission, fresh policy checks, bounded output and standard errors | New browser inventory/options and favicon automation await user acceptance; custom/sandboxed browser paths and broader browser/session/network/cancellation acceptance remain; no new automated runs |
| Passkeys | Upstream crypto and RP/origin validation, protected storage, GTK create/attach/replace/account selection; searchable/expired-filtered management, import/export and history-preserving removal; OpenSSL EC/RSA/Ed25519 transfer checks; actual extension DOM WebAuthn create/get | Localhost/advanced preferences, broader browser/platform acceptance |
| Auto-type | Native upstream parser, entry/group settings, associations, multi-vault matching/search, GTK review/PICKCHARS, X11 executor and permission-gated Wayland portal with companion focus lease/shortcut; timed last-choice preselection with UUID/sequence-digest/session guards, stock retype-time preference and legacy-private settings normalization; keyboard selection/Type/Enter with fresh search; stock always-show and selected-entry confirmation policies, configured single-match execution and serialized cancellable owner handoff with public caller fallback; seven field-only templates with native presence/eligibility and prepare guards, selector Copy Field actions and scoped keybindings, selected-entry CtrlShiftV/shared Qt keys; historical native/GTK/X11/GNOME lease checks | New selection memory and keyboard/INI/private-profile workflows await manual acceptance; new confirmation/automatic/caller/flow/PICKCHARS and field/clipboard/shortcut workflows await manual policy/lifecycle acceptance; general-search association variants, temporary-unlock timing, portal persistence/clipboard typing, global shortcut preferences and broader platform behavior |
| SSH Agent | GTK preferences/entry settings, saved-policy automatic loading on unlock, public preview/copy, token-bound manual add/constraints, managed/external/other-vault removal and clear-agent review, cleanup warnings; upstream KeeAgent/key/agent reuse and separate native ownership with PID authentication; socket-alias ownership, GCR/real forwarded-agent signing and mapped GTK tests; native upstream Ed25519/RSA/ECDSA generation, optional entry-password protection, public-only review and revision-bound attachment storage without replacing existing keys | Generation/OpenSSH/manual acceptance, hardware/security keys, GCR preload/keyring prompts and broader disconnect/failure/platform acceptance; no new automated generation runs |
| Secret Service | Opt-in D-Bus collections/items/aliases, peer-owned sessions and GTK prompts; upstream native plain/DH-AES ciphers and item conventions; exposed-group scope, independent one-shot password/TOTP reads, history/recycle semantics, incumbent-owner preservation, policy revocation and reply cancellation; real encrypted libsecret item/collection/alias/property/metadata-cache/GTK workflows pass | Broader client/desktop interoperability, persistence/session recovery and copied-vault acceptance |
| KeeShare | Native upstream group references, cloning/import/merge, encrypted standard/legacy containers, private persistent signing identity, opt-in GTK settings and unlocked-vault polling with file-change/alias guards; native interoperability/history/rollback/identity-reload fixtures pass | Identity import/export/management, broader conflict/network/share acceptance; legacy signatures are ignored by upstream 2.7.12 |
| Remote synchronization | Named KeePassXC2.8-compatible encrypted locations; masked command review and explicit trust; download/current-or-different composite key/two-way merge/durable local save/pre-upload byte check/upload; direction-only locations, multiline stdin, timeouts, native revision guards and cancellable keyless Linux process-group supervisor; merge-local location settings preserved | Compilation only; manual transfer/quoting/credentials/hardware/merge/recovery/timeout/cancellation/GUI acceptance pending; generic commands cannot guarantee atomic remote compare-and-swap or stop deliberately daemonized descendants |
| Quick unlock / biometrics | Existing session-only short password, Argon2id KDBX credential sealing and five-attempt fallback; Linux Polkit session unlock via encrypted native broker/private process keyring, explicit master-credential enrollment, per-release authorization, cancellation/revocation, system action packaging and fallbacks; vault helpers still die on lock | New Polkit provider has compilation evidence only; real installed policy/agent/PAM/biometric/hardware/session/revocation/cancellation acceptance pending; historical PIN checks do not cover it |
| Official CLI/proxy replacement | Public keepassxc GUI launcher, --lock/keyfile/pw-stdin/minimized/version/debug-info; bounded origin-aware stdin, foreground TTY-to-pipe forwarding and cancellation; manual headless, primary/remote multi-file, TTY/echo and cancellation checks; pinned upstream CLI with2.8 passkey/TOTP db-info statistics, stdio-open guards and clipboard-tool failure diagnostics; corrected browser proxy; explicit Qt INI profiles with selected settings, unknown-value/conflict guards,2.8 state/2.7 cache discovery, default-local layout/launcher guards, empty CLI values selecting configured defaults and single-file environment/same-path overrides; historical private primary/remote acceptance | Remaining config migration, broader terminal/remote/key-component acceptance and remaining desktop/IPC compatibility |
| Preferences/localization | Preview username/notes/password masking and individual reveal, empty-password placeholders and monospace notes with stock INI keys; configurable screen/suspend, user-switch and minimize/hide locking with Qt INI mappings, GNOME/logind state monitoring and clipboard grace; remembered vault, login-keyring unlock, background mode, configurable inactivity/Never, owned regular/primary clipboard expiry and explicit-copy secret hints, session quick unlock, copy minimize/lower and unlock/link minimize with shared background hiding; staged shortcut recording, conflict replacement, per-action disable/reset and all-default reset, shared Qt action keys, scoped atomic configuration deletion, live help and guarded entry GActions | Shortcut GUI/layout acceptance, manually authored multi-stroke/platform keys, remaining preferences, translations, real desktop login-cycle and linked-vault keyring enrollment acceptance |
| Lock lifecycle | Manual/idle/screen/suspend hooks; cancellation; immediate locked view, pending-unlock clearing, current-snapshot render guard and post-observer worker epoch check; tracked manual/quick prompt teardown on login unlock/completion | Reported boot metadata exposure addressed in source; password/autofill bypass unconfirmed, boot/keyring/activation and GNOME acceptance remain manual; no new automated runs |
| GNOME Quick Settings | Separate tile and native Background Apps row; generic status, Show/Lock/Quit; companion0.2 publishes Auto-Type chooser/focus leases/global shortcut/schema and authenticated focused-window lowering; historical GNOME50.4 background lifecycle checks | New companion methods have package/schema and JS syntax evidence only; actual Auto-Type/lower, lock screen, upgrade/restart and other-extension interaction remain manual |

## One-time password workflows

The core returns current codes, period and remaining milliseconds without the
seed. The GTK view polls asynchronously at most once a second and derives a
conservative local monotonic deadline from request start and native remaining
time; expired/late codes stay blank until a fresh reply. Passive reads use the
background worker directly and do not call `touch`, so inactivity lock remains
effective. Hide, selection changes, view teardown and idle/screen lock invalidate
reads and erase code labels/timers. Clipboard actions fetch the current native
code again, with an optional resolved-password prefix matching upstream semantics.
Provider replacement is direct: clearing and immediately reclaiming the X11
clipboard could lose ownership and discard the newer copy on the tested X11 backend.
Owned timeout/lock cleanup preserves a different clipboard owner.

Setup supports a secret key or TOTP URI, standard/Steam/custom modes and native
hash/period/digit controls. The setup fingerprint binds save/removal to the
reviewed database, preserving transactional failure behavior. Native legacy and
KeeOtp formats are retained where supported; custom legacy setup upgrades to URI
storage. All `TimeOtp-*` KeePass2 fields are cleared inside upstream `setTotp`'s
history update, preventing removal from being undone by reopening. A narrow core
patch rejects empty decoded keys and unbounded imported lengths and uses integer
64-bit alphabet powers for ten-digit codes. URI parsing retains upstream bounded
normalization rather than inventing different URI rules.

QR encoding reuses upstream QrCode/libqrencode, rendering a native PNG and an
explicit private SVG output. No temporary QR image is written for display. The
GTK view clears its paintable and auto-closes after 45 seconds; setup-link copy
and SVG export require the displayed encrypted-file revision. An independent
zbar decoder checks the real PNG against the exact upstream setup URI, including
Unicode labels. Fifteen native cases cover RFC 6238's eighteen published hash/time
vectors, Steam, clock edges, ten-digit values, formats, removal/history, invalid
requests, stale reviews, failed saves, read-only/recycled/locked states and
no-clobber output. The serial GTK gate uses an isolated bus/display, actual
clipboard reads, passive-idle assertions, QR/export/expiry, standard/Steam/link
setup and cancellation after view changes/hide/idle lock. Physical clipboard,
large/custom authenticator and accessibility acceptance remains open.

## Entry history inspection

The history list opens a comparison between a saved version and the current
entry. Either endpoint can be changed to any version. Changes-only filtering
can be disabled to inspect unchanged fields too. Native comparison includes
attribute existence, exact values and protection flags; tags, expiry, icons,
colors, URL override, report exclusion and timestamps; Auto-Type sequences and
window associations; custom-data values/timestamps; and attachment sizes and
SHA-256 fingerprints. Stored placeholders stay literal rather than resolving
against today's entry. Custom fields, protected/default-password fields, OTP,
Auto-Type sequences, URL overrides and custom-data values are hidden until an
explicit per-field reveal. Showing a secret does not change its storage protection.

Attachment export reads the chosen version through a native output file, not a
base64 UI payload; parent-owned staging enforces private permissions and no
clobber. Every comparison, reveal, export and history mutation must match the
encrypted database fingerprint captured by the history list. External writes,
other edits, missing indices and stale reviews fail instead of retargeting a
version. Restore adds the previous current state using upstream history, subject
to the database's retention/truncation limits; this is not an archival guarantee.
Remove/delete-all save transactionally and preserve the current entry. GTK
clears reveals on hide, collapse, selector/filter rebuild, close and lock, and
rejects late results belonging to a detached view. Native and mapped GTK gates
exercise these behaviors with disposable KDBX/XML fixtures. The upstream XML
reader has a narrow null-inner-stream guard: a Protected encrypted-value marker
in a plain import produces an error instead of crashing the helper. Valid
ProtectInMemory flags remain supported; the regression verifies a failed malformed
import inspection keeps the already unlocked vault available.

## Architecture and remaining integration work

`engine/main.cpp` is compiled as an additional target inside the pinned upstream
source tree and links `keepassx_core`. The app uses `keyslot/core_backend.py`;
there is no automatic CLI fallback. `keyslot/backend.py` remains a legacy
regression adapter. The helper owns Database, composite keys, serialization,
search, generation, TOTP, history, groups, attributes, attachments, settings,
key rotation, merge/export, encrypted copies, and local reports.

`engine/KeyslotTransfer.cpp` clones selected entries through upstream `Entry` and
streams a private KDBX4 capsule directly between the two native child processes.
Unix peer credentials bind the channel to the exact expected PID and UID; the
socket and its directory have owner-only permissions. Upstream dump hardening
remains enabled. The generic KDBX reader probes then rewinds, so this known-format
channel uses `Kdbx4Reader` and a bounded chunk adapter that fills reads across
chunk boundaries. Neither credentials, attachment bodies nor a decrypting key
cross the Python pipe, and no transfer file is created. Pending reviews expire
after two minutes and channel I/O after five minutes. Each transfer is single-use
and bound to both vault fingerprints and helper identities. The destination
saves first and issues a native receipt tied to its staged-output hash; the
source verifies that saved file again before removing originals. Unknown or
partial outcomes never trigger an automatic retry. Current/history custom-icon
UUID collisions are remapped without changing the existing destination icon.
Fourteen native tests cover preservation, fresh UUIDs, history/icons, a 65 MiB
incompressible attachment, changed vaults, hardlink identity, replay, cancellation,
lost replies and failed save/cleanup. A mapped GTK gate checks destination/group
selection, review/cancel, copy/move, refreshed views, partial-save messaging and
lock cancellation. Thirteen additional native cases and a separate GTK gate
cover recursive/empty group transfer, settings and current/history icon collision
preservation, fresh copied IDs and retained local move IDs, forbidden root/recycled/
descendant destinations, mismatched manifests, changed-child cleanup, bulk entry
copy/move and transactional recycling with failed-save rollback. Source capsules
preserve group/entry UUIDs for manifest validation; final copies use upstream
`Group::clone(Entry::CloneCopy)` and new UUIDs, while local moves keep their IDs.
Metadata-only entry manifests cover the full selection while review previews are
limited to ten titles; counts and field-reference warnings cover every selected
entry, including those beyond the preview. Group reviews include total recursive
counts and retain Auto-Type and KeeShare settings with a shared-file-path warning.
The GTK gate exercises real pointer hover/checkbox/toggle/Shift-range/secondary
selection, keyboard selection, filtered rows, reviewed bulk copy/move/recycle,
group-editor transfer, refreshed navigation and lock clearing. Its pointer input
runs serially in private Xvfb; live Wayland/touch/screen-reader acceptance remains
open. Selection follows the [GNOME HIG selection-mode pattern](https://developer.gnome.org/hig/patterns/containers/selection-mode.html)
with header count/Cancel and bottom actions. Remaining bulk editing/field copying
and drag-and-drop workflows are not implied by these checks.

`engine/KeyslotLaunch.cpp` reuses pinned `Entry` placeholder resolution and
`QProcess::splitCommand`. Ordinary URI data is released to GTK only for the
requested launch, while prepared previews contain masked protected values.
Command previews resolve a separate tree of current entries with protected
attributes/passwords/TOTP replaced before expansion, including nested references
and conversions. Actual command arguments stay native; detached children receive
null standard streams and no internal `KEYSLOT_*` environment. Normal remembered
approvals use upstream `_EXEC_CMD`; entry editing calls `Entry::setUrl` to revoke
that approval on URL changes. Override approval is stored separately with a hash
of both URL templates. Upstream 2.7.12 stores OverrideURL but does not use it in
`DatabaseWidget::openUrlForEntry`; Keyslot therefore exposes an explicit override
action without changing normal Open semantics. A failed start returns its saved
approval snapshot so GTK can display/revoke the actual persisted decision.

Linked-vault passwords travel in a bounded authenticated upstream crypto-box
packet between ephemeral native keys, bound to both one-shot tokens and the
reviewed file/key-file hashes. No raw linked master password enters Python.
Nonces use canonical standard Base64, not upstream's similarly named URL-safe
random-string helper. The recipient opens a candidate and adopts it only after
fingerprint checks; mismatched recipient, replay, tampering, changed files and
locked generations are rejected. Native tests cover ordinary schemes/overrides,
protected previews, command argv/stdout isolation, approval revocation, failed
save/start, linked passwords/key-only/composite/empty keys, changed inputs,
wrong credentials, tampering/replay/recipient identity and bounded ciphertext.
The GTK gate tests actual default URI dispatch under private XDG directories,
asynchronous cancellation/error redaction, command review/remember/revoke/error
state, hide/minimize preference, existing/locked/new linked windows, manual unlock
fallback and paused recipient cancellation on source lock. The remembered path
updates after linked opening; saving its credential to the login keyring is still
an explicit enrollment step, not an implemented automatic handoff.
Import uses the pinned upstream readers and a separate candidate database;
source credentials and the new target unlock key are distinct. The candidate
is adopted only after a no-clobber encrypted save. File or directory fingerprints
detect source changes during parsing. The source is never written. Upstream
import fixtures are required by the package's real-core integration tests.
`engine/CsvImport.cpp` adapts the pinned upstream CSV mapping/group/time/TOTP
conversion using its CsvParser. Encoding, delimiter/quote/comment, escape,
header/skip and all eleven field mappings are configurable. Source-value preview
is opt-in, paged and shortened only for display. Mapped review hides passwords,
pages through entries, and binds the final import to the reviewed source's
fingerprint. Dedicated dialog cleanup clears raw preview contents on lock.

The private stdin/stdout protocol is versioned and UUID-based. It does not use
the session bus for credentials. The public Quick Settings D-Bus API remains
Show/Lock/Quit/AutoType and Locked/Busy/Background booleans. AutoType only opens
the chooser; typing requires a separate review. The Nix application build requires real helper
integration tests; mock protocol tests cannot pass that release gate alone.
The package also requires a GTK smoke test under Xvfb/private D-Bus. It exercises
CSV parser-to-field mapping, the native dialog surfaces, responsive navigation,
multiple windows, path deduplication, aggregate public state, window teardown,
character-restricted generation and preview/password cleanup on lock. This gate
passes but does not replace GNOME Shell 50 acceptance.

The application window/controller is in `keyslot/app.py`; each database has its
own controller/view in `keyslot/application.py` and queue in `keyslot/session.py`.
Queued callbacks and modal editors remain bound to their originating window.
Late selections after session closure and inactive clipboard results are
discarded, and one window's lock does not lock the others. Screen/suspend/idle and
the Quick Settings Lock method lock every session. Public Locked/Busy properties
aggregate every session; Busy reflects foreground work. A user action can queue
behind a browser read without losing the click or disabling navigation. Browser
polling never resets the inactivity timer. Entry objects have client-side ownership tokens, so
equal UUIDs in copied databases cannot cross the adapter boundary. Startup uses
a cancellation generation so a cancelled unlock cannot restart a helper later.

Secret Service now has a native adapter and GTK provider, with private-bus
libsecret interoperability checks; broader client acceptance remains open.
Advanced browser preferences and broader
SSH/auto-type/KeeShare platform acceptance remain open. Services are not activated
by linking the core. Several upstream services
depend on DatabaseWidget and Qt confirmation dialogs, which must be adapted to
GTK before claiming a native replacement. No fallback to upstream Qt windows is
represented as GTK feature parity.

`engine/BrowserTransport.cpp` compiles against upstream BrowserMessageBuilder.
It serves the official local-socket protocol only when explicitly launched by
a parent, with owner-only socket permissions and private inherited JSON pipes
for decrypted requests and authorization results. It validates crypto field
lengths before calling upstream, binds requests to a connection/key generation,
rejects reused nonces and drops stale replies after rekey/disconnect. Pending
requests and buffers are bounded and requests time out. Endpoint collision tests
caught Qt's permission-option rename behavior. The transport binds an owner-only
private socket under umask0077 and creates the standard proxy endpoint as a
no-clobber symlink. Shutdown removes only its unchanged alias; a later stock
KeePassXC endpoint is preserved. The native suite uses independent libsodium plus
both the packaged and unmodified upstream proxies. Preferences explicitly enables the listener and
shows readiness. Browser Setup installs only selected browser registrations,
backs up previous bytes/mode, requires replacement confirmation and restores
owned files on disable; externally changed files and symlinks are preserved.
No browser integration setting or real user registration is enabled by tests.

`keyslot/browser_requests.py` scopes authentication to connection, client key
generation, session epoch and helper identity. GTK pairing and site/entry prompts
precede new authorization; remote approval/remember flags are ignored. Lock,
disconnect, rekey and native timeout invalidate pending work and dismiss prompts.
Existing foreground editors/jobs take priority. Native private pipes are
nonblocking and bounded. Supported actions are change-public-keys,
get-databasehash, associate, test-associate, get-logins, set-login, get-totp,
get-database-groups, create-new-group, lock-database, generate-password and
delete-entry, passkeys-register and passkeys-get. Unsupported actions return a protocol
error. Favicon download and advanced browser preferences remain open. The mandatory encrypted browser smoke uses
actual GTK preferences, pairing/replacement and entry consent, independently
sealed requests, and the packaged proxy read from a registered manifest. It
checks remembered permissions, cancellation, rekey, lock, restoration, cleanup,
idle-time preservation and confirmed save/update/cancel with real encrypted
request payloads. Separate host acceptance exercises the unmodified upstream
Chromium extension1.10.4.1 in sandboxed Chromium155.0.8059.40 with an owned profile,
HTTPS site and disposable vault. Its unpacked identity is trusted only by a
disposable manifest; production registration origins are unchanged. Pairing and
GTK consent, native crypto, DOM form filling, TOTP, generation, saving, group
creation and DOM WebAuthn create/get pass. OpenSSL independently verifies the
returned signature and rejects tampering. These checks do not cover every browser,
platform or extension setting.

Lock requests recheck native authentication/hash and send their encrypted success
response before locking the originating vault. Lock/unlock and active-helper
changes broadcast only the fixed public actions database-locked/database-unlocked;
no metadata is permitted. Polling does not repeat notifications or reset idle.
The real workflow covers encrypted lock, manual unlock, notifications and required
reauthentication. It exposed an upstream proxy defect: a socket read may combine
JSON messages. ProxySocketFraming.patch splits/validates bounded JSON objects,
shares framing with the transport and preserves partial input. Both unmodified
upstream and corrected proxies pass request interoperability tests; the packaged
proxy also passes fragmented/coalesced/Unicode and malformed/depth/size cases.
Browser Setup points to the corrected proxy. Existing stock registrations retain
the upstream defect until the user selects Keyslot.

Passkey registration/assertion delegates to pinned BrowserPasskeysClient,
PasskeyUtils and BrowserPasskeys. Native preparation validates RP/origin/options,
exclude/allow credentials and existing group/entry restrictions, returning review
metadata only. Approval tokens bind captured options, identity/fingerprint/key,
entries/groups and a bounded browser timeout (1–300 seconds). GTK reviews site,
RP/account and destination; replacement needs a separate destructive confirmation.
Keys/handles/credential IDs use upstream protected attributes. Entry metadata has
an explicit passkey flag because upstream customKeys excludes passkey fields.
A narrow confirmed parameter bypasses the upstream Qt replacement prompt only
after native approval; no Qt windows are used. Authentication does not write.
Tests independently verify EC/RSA signatures with OpenSSL, challenge/origin/RP
binding, protected storage/reopen, explicit replacement, replay/expiry/capacity,
external revocation, excluded/allowed/recycled credentials and normal-entry field
preservation. Transport timeout cancels stale work and returns the upstream
nested cancellation response. The actual GTK/proxy workflow covers cancel,
create, replacement cancel/approve, sign-in cancel/approve and rekey rejection.
Localhost controls remain unfinished; the separate
DOM WebAuthn host acceptance above does not prove complete passkey parity.

The SSH native adapter uses upstream KeeAgentSettings/OpenSSHKey/SSHAgent without
Qt dialogs. Bounded regular-file reads load external keys through an in-memory
attachment; private keys never need a plaintext temporary file. Both SHA256/MD5
fingerprints/public keys can be previewed without an active agent. UTF16 settings
remain compatible with KeeAgent; truncated/DTD settings are rejected before
replacement. Manual add does not require the automatic-loading AllowUse flag,
matching upstream semantics. Approval tokens bind captured keys/settings to the
unchanged database and expire after30seconds.

The new keyslot-ssh-agent process retains public ownership/cleanup records beyond
the per-vault helper's lifetime. Only parent-registered helper PIDs can connect
to its owner-only socket. Private-key data goes directly between native processes;
the parent's separate control pipe exposes process/status metadata. It reuses the
upstream agent protocol implementation, preserves externally loaded keys, rejects
cross-vault ownership conflicts and honors lifetime/confirmation/removal policies.
Owner disconnect, parent EOF and SIGTERM trigger cleanup; failures remain explicit
and can be retried. Requests are size/deadline bounded and stale queued adds are
rejected. Twenty-eight tests use real disposable OpenSSH agents for independent
Ed25519/RSA/ECDSA signatures, askpass confirmation and expiry, plus a deterministic
peer for killed-helper/late-add and refused-removal races. Startup failures are
reaped; an abrupt relay crash never reports successful key cleanup. No real user SSH state
is modified. GTK preferences/entry settings, public preview/copy, reviewed manual
add, managed removal and saved-policy loading on every helper/unlock are wired.
Twelve controller tests cover async startup/cancel/retry, independent vault queues,
foreground priority, epoch cancellation and visible cleanup errors. The required
mapped GTK gate uses a real disposable agent for save/preview/cancel/add/sign,
remove/cancel, re-unlock automatic loading, background retention, stale lock
responses and quit cleanup. Agent Keys lists actual public keys and ownership,
with search/filter/selection and reviewed removal or clear-agent actions. Native
single-use removal reviews bind to helper/vault fingerprint, exact keys, ownership
and socket identity. Changed key lists/comments/ownership/sockets require fresh
review; partial or unconfirmed outcomes are explicit. Per-key requests preserve
unreviewed new keys. Kernel peer checks stop further external removals after
helper death. Cleanup refuses a replacement socket with unresolved old ownership.
Tests cover external/mixed-vault clearing, cancellation/replay/stale/expiry, review
limits/owner authentication, changed lists/ownership/comments, replacement sockets,
refusal/unconfirmed removal/retry and helper death mid-clear. GTK tests cover
filter/selection, external removal/clear cancellation, changed-list rejection and
stale review clicks after lock. File paths retain upstream expansion syntax with
bounded cycle/substitution/size checks. Socket ownership uses device/inode plus
public-key fingerprint across symlink/hardlink aliases, with up to16 recent
canonical routes retained for cleanup. Alias deletion/retargeting, cross-vault
conflicts, changed review targets and canonical add routing are tested. Refresh
reloads the key list while retaining search/ownership filters.

Two required gates run unmodified GCR4.4.0.1 and a real OpenSSH10.5p1 forwarding
channel through a temporary loopback server. Encrypted Ed25519/RSA/ECDSA signing,
independent verify/tamper, borrowed-key preservation, aliases, cleanup, removal
and lifetime pass; forwarding also passes host acceptance. GCR runs only in the
Nix sandbox with an absent home, avoiding its default ~/.ssh scan. NSS wrapper
1.1.16 supplies test-only account data/home for the unprivileged forwarding
server; user SSH files/services are never used. The NSS library remains test-only.
Hardware/security keys, GCR preload/keyring prompt workflows and broader agent
disconnect/failure/platform acceptance remain unfinished; these tests do not prove complete
SSH feature parity. Agent operations cannot be made atomic with unrelated clients
reloading identities, since the protocol offers no compare-and-remove operation.

Local passkey management adapts the six-field format and validation from pinned
PasskeyImporter/PasskeyExporter, while using upstream addPasskeyToEntry/group,
Entry::removePasskey and entry history. The file reader is bounded to1MiB and
rejects non-regular files before reading. Import review returns public metadata
only; source fingerprint, unchanged database and explicit replacement guards
precede mutation. GTK offers new/attached entry and group destinations, actual
passkey account/RP metadata, search and expired-entry filtering. Export writes
private keys only inside the helper and uses parent-owned private staging,
no-clobber publication or explicitly approved replacement. Bulk duplicate titles
receive unique names; partial failures report completed file counts. Removal
preserves other fields/history and does not revoke a website credential. Native
tests verify protected storage/reopen, EC/RSA/Ed25519 signatures and tamper rejection
after transfer, malformed/changed/special sources, replacement and recycled-state
guards, permissions/no-clobber/bulk failure and cross-vault ownership. A dedicated
private-bus GTK gate verifies the manager, review/replace/export/remove decisions,
filtering, changed-source errors and stale actions after lock. Actual stock Qt
import/export UI interoperability remains a separate acceptance check.

Browser generation reuses the GTK character/passphrase generator with an explicit
Use Password action. Automatic preview neither copies nor resets inactivity;
user-requested regeneration and applying are activity. Cancel/rekey/lock clear the
output and prevent late release. Browser deletion uses a native expiring token
bound to entry/database/fingerprint/key and requires GTK confirmation. Recycle
preserves history; disabled-bin deletion has an explicit permanent warning.
Cancellation and missing entries return encrypted success=false, permitted only
for delete-entry by the transport. Native/controller tests cover false-result
shape, token replay/expiry/capacity, changed recycle mode, external writes and
history. The real GTK/proxy workflow covers generation cancel/restricted apply,
clipboard avoidance, deletion cancel/recycle/permanent/missing and locked cleanup.

Browser save review returns metadata while the native helper holds its captured
password. The controller drops its request password before showing GTK consent.
A bounded, expiring, single-use token binds approval to
the database identity/fingerprint, connection key and captured input. Creation
uses upstream BrowserService::addEntry with explicit database/group selection.
Updates use upstream history semantics, preserve other fields and username
references, and resolve password references with cycle/missing-target guards.
Cancel/unchanged requests do not serialize the database. Tests cover replay,
expiry/capacity, external writes/revocation, refreshed identity, group selection,
reference updates/cycles, preserved custom fields and history.

Browser TOTP uses upstream Entry::totp and the upstream direct-UUID matcher to
respect hidden/recycled entries and connection-key group restrictions. Reads do
not extend inactivity or write the file. Group listing reuses upstream recursive
formatting and omits the recycle bin. Nested group creation is captured in a
bounded, expiring confirmation token and requires GTK consent; existing groups
return unchanged. Parent groups and metadata are preserved. Native tests cover
actual codes/policies, authentication, invalid UUIDs/paths, replay, stale tokens,
expiry/capacity and group preservation. The encrypted GTK/proxy gate covers TOTP,
listing, create/cancel/existing groups and locked-request rejection.

Association primitives persist KeePassXC-compatible KPXC_BROWSER_ metadata inside
the encrypted database, without exporting identification keys to the GUI listing.
Database Settings exposes connected-browser review and confirmed revocation.
Read/authentication requests reject external-file changes so stale in-memory
permissions cannot authorize a revoked browser. Tests include upstream CLI
export, existing-association import, duplicate consent, invalid keys, revocation
across reopen, unrelated metadata preservation and GTK cancel/lock cleanup.
The headless BrowserService adapter reuses upstream search/ranking/permission and
credential formatting methods. Its constructor skips MainWindow and socket
activation; the adapter is the sole additional friend. Native lookup returns no
credential values. A single-use token binds release to the database object and
fingerprint, eligible entries, request options and a monotonic 30-second deadline.
Remembered allow/deny decisions use upstream BrowserEntryConfig. Tests cover
unauthorized/replayed/expired/cross-edit requests, HTTP-auth consent, option
isolation, URL boundaries, bounded pending requests and expired best matches.
Helper settings are parent-owned private temporary files, removed after helper
termination; no stock KeePassXC preferences are accessed. The transport also
uses monotonic deadlines and includes its client key generation in parent events.
Replay-cache exhaustion currently requires rekey;
real browser reconnect behavior still needs acceptance.

Startup settings use mode-0600 JSON with flags and a vault path only. Optional
login credentials use libsecret and GNOME's persistent login collection. Enrollment
verifies credentials in a separate upstream Database inside the native helper;
the current vault and file stay intact. Login activation never overrides a manual
lock in an existing window. Cancellation cancels outstanding keyring requests.
The login smoke test covers real keyring enrollment, lookup, application unlock
and removal without accessing the user's keyring. A real logout/login cycle,
locked-keyring fallback, physical hardware-key interaction and desktop autostart
after package upgrades still require platform acceptance.

Background mode hides rather than destroys windows, preserving their vaults,
worker queues and unfinished forms. The process holds the application alive;
Quit still closes every helper. Background login starts hidden. The companion
adds native apps to GNOME's existing Background Apps menu because portal 1.20.4
only monitors Flatpak instances. Its reversible InjectionManager overrides and
row lifecycle pass an isolated GNOME Shell 50.4 test with the actual app.

Short-password quick unlock is scoped to one vault/window and lasts until quit.
The helper first verifies the master credential, seals it into an upstream
Argon2id KDBX container using the short password, and returns only ciphertext.
The UI retains that encrypted bundle in memory across locks. Unsealing stays
inside the helper; successful unlock opens the original vault with its unchanged
master key. Path binding, wrong-password rejection, unchanged original bytes,
and successful reopen pass native tests. GTK tests cover setup and the five-failure
fallback. Key changes/quit clear the bundle. This does not implement biometrics.

Attachment and explicit export output is staged in directories owned by the
parent client so cancellation can remove plaintext even after helper termination.
Keys are retained only by the native helper, and failed key changes reload with
the original key. Protocol/OS tests cover output confirmation, no-clobber writes,
permissions and cancellation cleanup; real-core tests cover their cryptographic
and serialization behavior when the helper is available.

Failed explicit refresh keeps the last open database and fingerprint. Encrypted
copy serializes that open state without requiring the source file, and leaves
the current database path in place. Read-only access uses the open state even
when the source changes; mutation transactions retain their file-change guard.
Failed mutations now restore a verified encrypted snapshot made before the edit,
without replacing the original file or loading a concurrent writer's revision.
If recovery cannot reopen that snapshot, an encrypted copy is retained and its
path reported. The existing 323-test/19-gate package checks pass for this batch;
physical-key and broader interrupted-save acceptance remain open.

Native compilation and integration tests now pass with the pinned Qt5/Botan
dependencies. Remaining work includes the missing services above, broader fixture
coverage and GNOME 50 platform acceptance, particularly the companion extension.

Completion requires a release-pinned acceptance suite against both applications:
KDBX3/4 and all encryption/KDF variants; unknown/custom field, reference, icon,
history, and attachment preservation; invalid files/keys; interrupted saves;
concurrent edits and merge; browser pairing/permission and passkey fixtures;
hardware-key tests; and a GNOME 50 VM covering Wayland, screen lock, suspend,
clipboard, accessibility, extension teardown, and install/upgrade migration.
Only after those features and checks are complete can this be called a drop-in
replacement.
