# Clipboard ownership and expiration

Explicit Copy actions publish text to the regular clipboard and primary
selection, with the Linux `x-kde-passwordManagerHint=secret` format used by
KeePassXC. Repeated copies replace the provider directly, including empty
strings, without a clear/reclaim gap. Primary selection is available where the
display backend supports it; failure to claim the regular clipboard reports
failure rather than a successful Copy toast.

One application-wide registry tracks process-local providers on each display.
The same configured timeout also covers native GTK selections and built-in
Copy actions in editable fields and dialogs. Changing the timeout recalculates
existing deadlines from the original copy/selection time; an already expired
selection clears immediately. Never disables expiry, not lock/close cleanup.
The existing shared INI `Security/ClearClipboard` and
`Security/ClearClipboardTimeout` preferences remain in use.

Each record holds a weak reference to its originating vault session. Lock,
vault reload, session deactivation/close and application shutdown clear its
owned data, including primary selection. Another vault's current copy is kept
when a different vault is locked. Every clear checks the exact provider before
releasing ownership, so data subsequently copied by another application is
preserved. Only `Gdk.Clipboard.get_content()` is used for ownership checks; the
registry never reads another application's clipboard text. Minimize locking's
existing 1–20 second grace now considers both clipboard deadlines.

GTK primary-selection providers are left intact: replacing them with a union
would detach the native selection provider and collapse its selection. GTK
retains responsibility for updating the selection when text changes and for
clearing it when the underlying buffer is masked or destroyed. Timed clearing
may remove selection highlighting without deleting the field's text. Explicit
copies use a separate static provider and do not renew their lifetime on
unrelated clipboard notifications.

The secret hint is advisory. Clipboard history tools that ignore it can retain
copies independently; clearing ownership cannot revoke data already read by
another process. Native GTK automatic selections and built-in Copy actions
receive ownership tracking and expiry but are not rewritten to add the hint.
Keyslot never requests clipboard persistence with `store_async`. Transient
GTK/Python strings are not guaranteed to be securely zeroed.

References (behavior/API only; implementation is GPL3-only):
- KeePassXC 2.7.12 `src/gui/Clipboard.cpp` (GPL2-or-3):
  https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/Clipboard.cpp
- GTK 4.22.4 provider ownership and content-change signals (LGPL2.1-or-later):
  https://github.com/GNOME/gtk/blob/4.22.4/gdk/gdkclipboard.c
- GTK 4.22.4 buffer selection lifetime (LGPL2.1-or-later):
  https://github.com/GNOME/gtk/blob/4.22.4/gtk/gtktextbuffer.c
- https://docs.gtk.org/gdk4/method.Clipboard.get_content.html
- https://docs.gtk.org/gdk4/ctor.ContentProvider.new_union.html

Compilation-only candidate. No tests/harnesses or automated GTK, clipboard,
vault or desktop behavior runs were added or performed. Manual acceptance is
still needed for repeated/empty/Unicode copies, native editing and middle-click
selection, replacement by another app, multiple vaults/displays, timeout changes,
Never, mask/refresh/lock/hide/close, clipboard managers and X11/Wayland backends.
Copy/minimize/background preferences are now implemented in
[Window Behavior](window-behavior.md), with manual desktop acceptance pending.
