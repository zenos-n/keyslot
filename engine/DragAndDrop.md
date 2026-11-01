# Drag-and-drop candidate

Keyslot uses GTK4 DragSource/DropTarget for app-local entry and group drags.
The private GObject payload contains source/session identity, epoch, helper
identity/generation and item UUIDs. It has no text/URI serializer, credential
fields or password drag provider. Drag previews contain generic labels.

Drag an entry, or use the grip to drag selected entries in selection mode.
Drop on a sidebar group or the current entry list. Hold Ctrl to copy; otherwise
move. Group drops in the middle of a row nest inside that group; the upper or
lower quarter inserts before or after it, with an accent insertion line.
The root and recycle-bin root are not draggable. Self/descendant destinations
and ambiguous identifiers are rejected. UUIDs identify objects rather than paths.

Every ordinary drop opens the existing copy/move review in the destination
window, listing source/destination vault and group, and the insertion position
when applicable. Same-vault operations retain the normal encrypted transaction
and recovery path. Cross-vault operations retain native encrypted capsules,
peer-authenticated private sockets, review deadlines, new destination UUIDs,
icon/history/settings preservation and a durable destination receipt before
source removal. GDK's move completion never deletes originals. Lock, close,
cancel and epoch changes invalidate preparation/review. The native database
revision and source-file guards remain authoritative at commit time.

Moving ordinary items onto the recycle bin uses the existing recycle review.
Moving recycled items into an ordinary group uses Restore with that destination
preselected, and permits changing it during review. Cross-vault recycled-item
transfers and Ctrl-copy of recycled items remain unavailable; restore first.
These limits are explicit rather than silently changing the requested action.

Drop local .kdbx files on the window to open them using the existing window
and unlock flow. Multiple files require review. Drop local regular files on
an entry's Attachments section to review their canonical paths, sizes and names.
The batch is limited to 32 files and 256 MiB total; Add Attachment retains its
existing larger individual-file path. Nonlocal URIs and duplicate batch names
are refused. Replacing matching attachment names requires an unchecked-by-default
explicit choice. The native helper binds review to the working revision and
source device/inode/size/nanosecond modification+change times, bounds each read,
checks open descriptors/path identities and rechecks all sources before commit.
All batch changes form one entry history update and encrypted transaction;
source contents never pass through the GTK control pipe. This is a best-effort
filesystem change guard, not an atomic filesystem snapshot or proof against
an adversary controlling the source filesystem/kernel.

Implementation references: the pinned KeePassXC 2.7.12 EntryModel::mimeData,
GroupModel::dropMimeData and MainWindow file-drop behavior, and GTK/GDK 4
DragSource, DropTarget, ContentProvider and FileList APIs. Keyslot does not
reuse Qt's application/x-keepassx-* payloads: upstream resolves their database
UUIDs through its own in-process registry, so they are not an interprocess
transfer protocol. GTK4.22.4 supports the chosen APIs; FileList requires >=4.8.

Sources:
- https://docs.gtk.org/gtk4/class.DragSource.html
- https://docs.gtk.org/gtk4/class.DropTarget.html
- https://docs.gtk.org/gdk4/ctor.ContentProvider.new_for_value.html
- https://docs.gtk.org/gdk4/struct.FileList.html
- https://github.com/keepassxreboot/keepassxc/tree/2.7.12/src/gui

Compilation-only candidate. No new tests/harnesses or automated native/GUI
behavior runs. Actual pointer/touch/keyboard modifiers, edge markers,
selection-mode grips, same/cross-vault save/recovery, source/destination lock
and close races, recycled items, file/attachment review and accessibility
remain for user manual acceptance. Successful compilation does not prove parity.
