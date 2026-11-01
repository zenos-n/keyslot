# New-entry defaults

Preferences → New Entries includes **Use the Group Icon** (on by default) and
**Generate a Password Automatically** (off by default). Explicit INI profiles
use KeePassXC's `UseGroupIconOnEntryCreation` and
`AutoGeneratePasswordForNewEntries` keys. Private profiles store only the flags
in their existing settings file.

For a new entry, changing the selected group updates an inherited icon until
you choose an icon yourself. Standard closed/open folder icons use the usual
entry key icon; custom icons, including stored Adwaita icons, are inherited.
Turning inheritance off starts with the standard key. Editing or moving an
existing entry preserves its icon. Browser-created entries retain their native
browser-specific icon behavior.

The entry password's Generate button now uses saved generator settings rather
than a hardcoded length and character set. Its dropdown opens Generator Options
without discarding the entry draft. Password/passphrase mode, separate character
length and word count, character groups, exclusions, additional characters,
word list, case and separator use the same native generator as the full dialog.
Use Password applies the chosen result and closes Generator Options. Options
are saved when generation succeeds; generated values are never saved in the
settings file or automatically copied to the clipboard.

Automatic generation applies only to new entries. Save waits for generation;
the password field remains editable, and a late result never replaces text
changed while generation was pending. Closing, hiding or locking the form
invalidates the result and clears widget text/undo. Canceled native generation
may finish, but its result is discarded. Settings-read failures or invalid
generator/word-list choices leave the entry draft available for manual input.
Invalid private settings do not silently change one-click generation options;
reviewing and generating in the full dialog can replace them with the displayed
settings. Small passphrase word lists show the existing warning.

Runtime/Python compilation only. No tests/harnesses or automated GUI, generator,
settings or vault behavior runs were added or performed. Manual acceptance is
still needed for profiles, all generation modes, custom word lists, icon
inheritance/override, cancellation and edits during generation, save/recovery,
multi-window operation, layout and accessibility. This feature does not establish
production readiness or full KeePassXC parity.
