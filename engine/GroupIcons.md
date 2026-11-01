# Group icon propagation

Edit Group → Apply Icon To supports the selected group alone, child groups,
child entries, or all children, matching KeePassXC's icon-application scopes.
Child entries include entries directly in the selected group and nested groups;
child groups exclude the selected group. Current entries are updated, never
historical versions. Standard icons, existing custom images and the Adwaita
picker's stored custom-icon fallback all use the existing icon-selection flow.

Saving a scope beyond This Group Only first requests `icons.group.review`.
The native helper validates a unique current source UUID, the chosen standard/
custom icon and scope, and counts only descendants whose displayed icon changes.
It checks affected current UUIDs against the whole vault to reject ambiguous
targets. The review contains counts and a token, not entry fields or passwords.
Recycled descendants are counted explicitly; selecting the root can include the
recycle bin and its contents, as in upstream recursive icon application.

The two-minute, single-use token binds the weak database object, complete
working revision, group UUID, selected icon and scope. `group.save` requires the
same request and explicit approval before consuming it. Another mutation,
reload, changed/missing icon, different target/scope or expired/reused token
rejects the operation. Source-file conflict checks remain in the existing
transaction. Failed saves require a fresh review even when rollback succeeded.

The group edit and all child icon changes commit together in the existing
encrypted transaction. Automatic saving, Manual Save checkpoints, conflict
handling, backups and recovery behavior are unchanged. Changed entries use
upstream `beginUpdate`/`endUpdate` around `Group::applyGroupIconTo`, preserving
the previous version including custom/plugin data through the existing history
backport, subject to the vault's history limits (including disabled history).
Unchanged entry icons create no history. Groups have no history.
Icons, history, search/Auto-Type/browser/KeeShare settings, tags, expiry and
other group custom data outside the chosen edit are retained.

The group editor freezes input while preparing/saving, keeps drafts after a
canceled or failed review and prevents duplicate submissions. Closing during
preparation invalidates delivery and releases a late token. Review dialogs and
responses carry their own identity, session epoch and vault identity, so an old
closing dialog cannot cancel a newer review. Lock/close clears pending frontend
values; closing the editor also clears widget buffers and undo history.
Token cancellation is best effort and native expiry/identity checks
remain authoritative. A save already approved and running completes through
the existing worker/transaction path; normal close waits, while security locks
still cancel the helper through normal recovery machinery. No credentials or
entry values go through the Shell companion.

`group-icon-propagation` is a native capability; older engines fail explicitly.
This update adds no icon download, configuration migration or automatic new-entry
icon preference. It does not change the selected icon on unrelated objects.

Upstream behavior references (GPL2-or-3); Keyslot adapters are GPL3-only:
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/EditWidgetIcons.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/gui/group/EditGroupWidget.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/Group.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.7.12/src/core/Entry.cpp

Native/package/Python compilation only. No tests/harnesses or automated
native/GUI/vault/history/save/clipboard behavior runs were added or performed.
Manual acceptance remains for every scope, direct/nested/recycled/root targets,
standard/custom/Adwaita icons, unchanged targets, history/plugin preservation,
draft cancellation, stale/expired/reused reviews, lock/close/failure recovery,
manual saving, legacy formats, layout and accessibility.
