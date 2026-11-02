# KeeShare signing identity (R01)

Preferences → KeeShare → Signing Identity exposes the stock2.8 signer-name,
certificate fingerprint and Generate/Regenerate controls. These are global/profile
settings and can be used with a locked vault. Reading does not create a key;
missing identities can be generated explicitly. Automatic legacy exports retain
their existing ability to create an identity on first use.

The UI shows the public signer/fingerprint and lets the user save a changed
signer name. Replacing an existing identity requires destructive confirmation.
Private signing keys/XML remain in the native process and the existing private
profile identity file, never in GTK or IPC responses. The helper has no open
vault and refuses these operations on a helper with a database loaded.

The response is capability-gated and strictly typed: exists, signer, fingerprint,
revision. Public metadata is loaded in a worker with no GTK blocking. A per-job
keyless helper is cancelled on dialog/security teardown and destroyed after
completion; its operation generation prevents cancel-before-start from launching
late. Session/profile/epoch/visibility guards reject stale callbacks. Expected
native/file errors remain in the form, with a Reload control and editable draft.
Closing is deferred during an update; security teardown can still cancel it.
Cancellation cannot undo an already committed atomic identity replacement.

Updates require the SHA-256 revision read by that form (or missing for a new
identity). The same QLockFile used by legacy exports serializes cooperating
Keyslot readers/writers. Files are opened with O_NOFOLLOW/O_CLOEXEC/O_NONBLOCK,
then checked for regular-file type, user ownership, private permissions and a
64KiB size limit on the opened descriptor. Malformed existing identities are
rejected and preserved. The existing identity directory must be private and
owned by the user. QSaveFile uses0600 permissions, file fsync, atomic replacement
and no direct-write fallback. A second prewrite revision check detects evident
external changes; the advisory lock/recheck is not an atomic filesystem CAS
against arbitrary non-cooperating writers.

Legacy .kdbx.share exports check the private identity revision before skipping
unchanged data. A change reloads the native identity and invalidates export cache;
unchanged identities avoid repeated private-key parsing. Already-running exports
may finish with an earlier identity; a later sync observes the change. Standard
KDBX share/import policies and vault transaction/save guards remain unchanged.
KeePassXC2.8 ignores legacy signatures when importing; these controls do not
claim signature-verification support. No identity import/export UI is added,
because it is not part of the audited stock2.8 settings widget.

This implements R01 in development source. The frozen4a65093 manual candidate
listed in the replacement checklist predates it and is deliberately unchanged.
Runtime/native/Python compilation and static source/artifact inspection only;
no tests/harnesses or automated certificate/key generation, real identity-file,
GTK, synchronization, vault or crypto behavior checks were added/performed.
Manual locked/unlocked/missing/existing/rename/regenerate/cancel/readonly/
malformed/oversized/symlink/concurrent-writer/export-cache/profile/lifecycle and
accessibility acceptance remains. No production/full-parity claim follows.
GTK language scope remains English, Polish and Romanian; no other translation
work is included.

References: KeePassXC Team native source GPL2-or-3; independent Keyslot adapter
GPL3-only.

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/keeshare/SettingsWidgetKeeShare.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/keeshare/KeeShareSettings.cpp
