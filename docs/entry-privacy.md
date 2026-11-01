# Entry preview privacy candidate

Preferences → Entry Privacy exposes Hide Usernames, Hide Notes, Hide Password
Previews, Use Monospace for Notes and Mask Empty Passwords. Defaults match the
pinned stock configuration: usernames/notes visible, password preview hidden,
monospace and empty-password masking off. Usernames are masked in the entry
list and detail preview. Hidden detail fields have individual reveal controls;
Copy still retrieves the complete field through the existing timed clipboard.
Notes use a rounded, scrollable read-only text view; new entry/group note editors
also honor monospace. Hiding notes applies to previews, not an explicit editor.

Stock INI keys are GUI/HideUsernames, Security/Security_HideNotes (the canonical
upstream spelling), Security/HidePasswordPreviewPanel, GUI/MonospaceNotes and
Security/PasswordEmptyPlaceholder. Private JSON carries booleans otherwise.
Existing typed/atomic/optimistic storage preserves unrelated INI values. Failed
saves restore the switch. Changes immediately mask/rebuild all open previews
and entry lists while preserving selection/search state.

The native entry.preview RPC accepts only unique UserName/Password/Notes field
requests for one unambiguous current entry UUID. It returns values ONLY for
requested display fields. A separate password-empty boolean lets masked views
represent empty values without sending password text. Values resolve references
natively, as stock previews and Copy do; visibility applies to the displayed
field rather than taint-tracking the source of a reference. The API reads the
current open state, including encrypted dirty checkpoints, without mutating it.

Each displayed value is limited to 32768 UTF-16 code units without splitting a
surrogate pair. Truncation is explicit; Copy uses the original complete native
field rather than the preview. Null characters are rendered as the visible
symbol ␀. This is display sanitization and never edits the database. Broader
very-large/unusual field/clipboard acceptance remains open.

GTK batches the currently wanted fields in a bounded passive worker request.
Automatic preview reads do not refresh the inactivity timer. Explicit reveal
does. Entry/snapshot identity, session epoch, helper generation, controller epoch
and per-field reveal serials guard delivery. Queued work checks cancellation
before requesting values. Selection, refresh, multiselection, privacy changes,
lock, hidden windows and shutdown mask/clear old labels/buffers before late
callbacks can publish. Manual reveals conceal on focus loss; explicitly always
visible fields remain governed by their preference. Reveal-off discards loaded
state so reveal-on fetches again. No plaintext field cache or preview file is
created. Notes undo history is disabled; password labels use plain text and
are not selectable, using tracked Copy instead. Explicit note Copy/Cut actions
are intercepted in the read-only view and use the owned timed clipboard for
the selected displayed fragment; the header Copy retrieves the complete field. Native and transient GTK/Python
strings are not promised secure-zero memory. Automatic primary-selection
ownership and expiry are now tracked by the application-wide
[clipboard registry](clipboard.md). Clipboard-manager retention remains outside
the guarantee of ownership clearing; the secret hint is advisory.

Preview errors keep the field masked/unavailable; only an explicit reveal
reports an error dialog. A new helper capability detects unsupported older
engines. Native copies, updates, browser permissions, keys and file formats are
unchanged. The helper's preview buffers are bounded, but the original fields and
attachments remain intact.

Behavior references: KeePassXC2.7.12 EntryPreviewWidget visibility and Config
keys (upstream GPL2-or-3); Keyslot's adapter is GPL3-only.
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/EntryPreviewWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/Config.cpp
- https://gnome.pages.gitlab.gnome.org/libadwaita/doc/1.9/property.ActionRow.subtitle.html
- https://docs.gtk.org/gtk4/method.TextBuffer.set_enable_undo.html

Compilation-only candidate, no new tests/harnesses or automated native/GTK/vault/
clipboard/profile behavior runs. Actual reveal/hide/focus/lock/selection races,
field references, empty/large/Unicode fields, config migration/conflicts, notes
scrolling/monospace, clipboard, accessibility and desktop acceptance remain for
user manual stress testing. Copy/minimize/background preferences are now
implemented in [Window Behavior](window-behavior.md); their manual desktop
acceptance remains open.
