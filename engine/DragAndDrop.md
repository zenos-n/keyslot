# Drag-and-drop candidate

Keyslot uses GTK4 DragSource/DropTarget for app-local entry and group drags.
The private GObject payload contains source/session identity, epoch, helper
identity/generation and item UUIDs. It has no text/URI serializer, credential
fields or password drag provider. Drag previews contain generic labels.

Drag an entry, or use the grip to drag selected entries in selection mode.
Drop on a sidebar group or the current entry list. Hold Ctrl to copy; otherwise
move. Group drops in the middle of a row nest inside that group; the upper or
lower quarter inserts before or after it, with an accent insertion line.
The database root is not draggable. Self/descendant destinations
and ambiguous identifiers are rejected. UUIDs identify objects rather than paths.

Every transfer drop opens the existing copy/move review in the destination
window, listing source/destination vault and group, and the insertion position
when applicable. Same-vault operations retain the normal encrypted transaction
and recovery path, honoring Manual Save with an encrypted dirty checkpoint.
Cross-vault operations retain native encrypted capsules,
peer-authenticated private sockets, review deadlines, new destination UUIDs,
icon/history/settings preservation and a durable destination receipt before
source removal. GDK's move completion never deletes originals. Lock, close,
cancel and epoch changes invalidate preparation/review. The native database
revision and source-file guards remain authoritative at commit time.

Local moves onto the recycle-bin root use the existing recycle review. Local
moves from the bin into an ordinary group use Restore with that destination
preselected when no sibling insertion position was requested. Original-location
Restore remains available separately in entry, group and bulk actions.

Recycled entries and groups also support direct copy/move within or between
vaults, including Ctrl-copy and destination groups inside a recycle bin. Mixed
ordinary/recycled entry selections are accepted. Reviews show the source's
recycled entry count/group state and explicitly warn when transferred items
will remain recycled in the destination. Cross-vault moves warn that recycled
originals are permanently removed only after the destination save receipt.
Copies retain originals; local moves retain UUIDs, while cross-vault copies and
moves receive new UUIDs. Native working revisions bind recycled state and
membership to the prepared manifest, not just the GUI selection. Ambiguous
current group/entry IDs are rejected before any native mutation.

The designated recycle-bin group, including a containing ancestor, can also be
copied or moved. A local move retains the same designated bin object and role.
A copy/cross-vault move does not transfer that metadata role: its contents become
ordinary destination groups unless placed in that destination's recycle bin.
The review explicitly distinguishes these cases. After a confirmed cross-vault
move, source cleanup clears its bin metadata before deleting the subtree, so
upstream creates a fresh bin when next needed if recycling is enabled. No target
metadata role is overwritten. Empty bins/groups retain zero-entry receipt checks.
Only the database root remains unavailable as a group transfer source, matching
upstream. Cycle/descendant checks apply to all copies and moves, including bins.
Destination drop zones include recycled subgroups and their sibling positions.
Capability checks reject old helpers before using the new recycled paths.

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
transfer protocol. GTK4.22.4 supports the chosen APIs; FileList requires >=4.6.

Sources:
- https://docs.gtk.org/gtk4/class.DragSource.html
- https://docs.gtk.org/gtk4/class.DropTarget.html
- https://docs.gtk.org/gdk4/ctor.ContentProvider.new_for_value.html
- https://docs.gtk.org/gdk4/struct.FileList.html
- https://github.com/keepassxreboot/keepassxc/tree/2.7.12/src/gui
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/gui/group/GroupModel.cpp

Compilation-only candidate. No new tests/harnesses or automated native/GUI
behavior runs. Actual pointer/touch/keyboard modifiers, edge markers,
selection-mode grips, same/cross-vault save/recovery, source/destination lock
and close races, recycled items, file/attachment review and accessibility
remain for user manual acceptance. Successful compilation does not prove parity.
