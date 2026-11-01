# Remote vault synchronization

The GTK workflow is **Main Menu → Database → Remote Synchronization…**. Named
locations are stored inside the encrypted database, using KeePassXC 2.8's
`KPXC_REMOTE_SYNC_SETTINGS` JSON array and its seven `RemoteParams` fields.
Unknown object fields survive editing. Invalid/duplicate/oversized settings are
rejected without replacing them. The existing encrypted transaction, automatic
or manual saving, revision/conflict and recovery paths handle setting changes.

Configure download and/or upload commands with `{TEMP_DATABASE}` as their
transfer file, optional multiline standard input, and a per-command timeout.
Commands are split by Qt's double-quote argument parser and run directly; shell
syntax needs an explicit shell command. Substitution happens separately in each
argument, preserving private runtime paths containing spaces. Standard input is
UTF-8, has a final newline when nonempty, and is always closed afterward. Tools
must already be installed in the user's environment. No provider/password is
silently inferred and no command runs just because a vault opens.

Every synchronization requires a command review and affirmative trust checkbox,
including settings authored by another client. Commands are masked with an
explicit reveal control; configured standard input is inspected in the location
editor. No command output is returned or logged. The command supervisor receives
only transfer arguments/input over a private pipe, not vault keys or database
objects, and removes internal `KEYSLOT_*` variables before execution.

A download must produce a regular, nonempty file in a private runtime directory.
The native core first tries the local composite key; a different remote password,
key file and/or hardware slot can be supplied in the same progress dialog.
The local-to-remote then remote-to-local merger sequence matches upstream.
Remote encryption key/cipher/KDF are retained, subject to the core's required KDBX
format upgrades; local encryption remains local. Only encrypted KDBX scratch
files are written. Remote location commands are protected against deletion and
copying during metadata merges, preserving each vault's own configuration.

The local merge and all previously unsaved local edits are durably saved before
upload is possible. A second download compares the remote bytes with the first
download; a changed source or failed check stops upload, keeping the saved local
merge. Upload-only and download/merge-only locations are supported. Revision or
local file conflicts stop further work. There are no automatic transfer retries.

The keyless Linux supervisor starts each external command in its own session and
process group. Cancellation, timeout, normal completion and native-helper death
terminate that command and ordinary descendants. The UI polls short native RPCs,
leaving cancellation and security locking available. Closing the progress dialog
cancels; locking also destroys the helper and clears credentials/dialogs. A
completed local merge remains saved after cancellation. Programs must stay in
that process group: deliberately daemonized/escaped descendants are outside this
contract, so commands should run their transfer in the foreground.

Generic transfer commands cannot guarantee a remote compare-and-swap. A writer
can still change the remote file between the second download and upload, and
remote write atomicity belongs to the configured command/provider. Failed,
timed-out or cancelled uploads have an unknown remote outcome; inspect the
remote file before a fresh manual retry. Transfer tools must return only when
finished and should provide their own atomic replacement/backups where possible.
The review dialog explains these limits before execution.

## Source and attribution

The schema and two-way merge sequence follow the KeePassXC Team's GPL-2.0-or-later
sources; the Keyslot implementation is GPL-3.0-only, compatible with that license.
The narrow custom-data protection patch adapts the upstream protection rule and
additionally prevents copying remote location settings to another database.

- [RemoteSettings.cpp, 2.8.0](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/remote/RemoteSettings.cpp)
- [RemoteProcess.cpp, 2.8.0](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/remote/RemoteProcess.cpp)
- [DatabaseWidget::syncWithDatabase, 2.8.0](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/DatabaseWidget.cpp)
- [CustomData.cpp, 2.8.0](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/CustomData.cpp)

Validation for this candidate is native/package/Python compilation only. No new
tests or harnesses, and no automated command/GUI/network/vault acceptance runs.
Manual acceptance remains required for command quoting/input, cancellation and
process lifetime, different credentials/hardware keys, both merge directions,
conflicts, upload failure/recovery, settings interoperability and GNOME layout.
