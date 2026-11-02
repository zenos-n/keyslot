# Backups before saving

Preferences → Backups maps KeePassXC's roaming `BackupBeforeSave` and
`BackupFilePathPattern` settings. The stock defaults are disabled and
`{DB_FILENAME}.old.kdbx`. The path row has an explicit Apply action; the folder
picker chooses a folder with that default filename pattern. An empty pattern
uses the same stock default. The switch and pattern apply to all vault windows
in the current configuration profile, including subsequently opened windows.

The native helper reuses KeePassXC2.8's `Tools::substituteBackupFilePath` for
`{DB_FILENAME}`, `{TIME}`, `{TIME:Qt-date-format}` and escaped braces. Relative
patterns resolve against the current database's directory; absolute patterns
can select another directory. As in the stock Save As path, the current
database's filename/directory supplies the pattern context when replacing a
different destination. The backup contains the previous destination file.
Missing backup directories are created. Original backup files are not deleted
when disabling this option.

Normal saves, saves of encrypted manual/recovery checkpoints, and reviewed
Save As replacements use the policy. Initial creation of a new file has no old
version to back up. The keyless recovery helper inherits the owning vault's
policy, including close-time recovery commits. Preference changes update
existing helpers without triggering a save or changing the autosave setting;
a failed preference write attempts to restore the previous helper policies.
Each helper also refreshes the committed shared policy before subsequent
commands, including helpers opened while the preference change is in progress.

This replaces the new client's previously mandatory `.keyslot.bak` behavior
with the stock configuration controls/defaults. Native private clients that
do not send the new policy retain their older fixed backup behavior. The new
client requires the native `backup-policy` capability before opening a vault.

Keyslot retains its existing atomic-save protection: backup files are encrypted
regular files written with private0600 permissions and no direct-write fallback.
A backup destination may not alias either the replaced database or the original
Save As source, use a symlink/non-regular file, or enter private recovery storage.
Checks run before staging and before the backup commit, alongside existing
database revision checks. These filesystem checks do not provide an atomic
compare-and-swap against a noncooperating writer.

As in upstream2.8, an optional backup that cannot be written does not block the
primary save. The backup writer still refuses unsafe destinations and writes
private atomic copies, but its failure is best-effort. The caller revalidates the
primary source/recovery revision before proceeding; conflict checks and the
primary atomic save can still fail normally. No direct-write fallback is enabled
for the database. This applies to normal saves, manual/recovery commits and Save
As replacement. The older private client's mandatory fixed-backup contract is
retained when it has not configured the new optional policy.
Transaction rollback snapshots and encrypted unsaved recovery storage remain
independent of this optional backup setting.

Source references:
[stock save/path selection](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/DatabaseWidget.cpp),
[substitution](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Tools.cpp),
[defaults](https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp).

Validation is ordinary native/runtime/Python/gettext compilation and static
source/artifact inspection only. No tests, harnesses or filesystem/vault/GTK
behavior probes were added or run. Pattern expansion, defaults/migration,
absolute/relative paths, existing backups, permissions, failures/concurrent
changes, recovery/Save As and UI accessibility still require user manual
acceptance. This does not establish full parity or production readiness.
