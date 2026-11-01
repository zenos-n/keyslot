# SSH key generation backport

Historical2.7.12/Qt5 checkpoint. The current engine source/retained changes are
documented in [Native2.8 Migration](Native28.md); older patches are not applied
as a stack to2.8, and their historical verification is not reused as2.8 evidence.

`OpenSSHKeyGen.cpp` and `.h` come from KeePassXC 2.8.0:

- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/sshagent/OpenSSHKeyGen.cpp
- https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/sshagent/OpenSSHKeyGen.h

Their KeePassXC copyright and GPL-2.0-or-later notices remain intact. The only
API adaptation removes calls to the newer `OpenSSHKey::setCheck`; Keyslot's
serializer writes the check integers itself. The existing 2.7.12 key parser and
SSH-agent code are retained. No Qt 6 GUI or upstream test sources are imported.

The generator uses upstream Botan-backed Ed25519, RSA (2048/3072/4096) and ECDSA
(256/384/521). Keyslot writes the standard OpenSSH private-key envelope described
by https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key, reusing
the pinned BinaryStream and key-component writers. Optional passphrase
protection uses the existing entry password, Bcrypt-PBKDF with a random 16-byte
salt and 16 rounds, and AES-256-CTR with a 32-byte key and 16-byte IV. Only the
private component list is encrypted, with repeated random check integers and
block-aligned incremental padding. A native parse/decrypt/public-key comparison
must succeed before a review is returned. This is part of generation's input
and output validation, not a separate test execution.

The GUI receives public metadata and an opaque, single-use two-minute review
token. Private bytes and the entry password remain in the unlocked helper.
Saving rechecks the database identity, working revision, entry UUID uniqueness,
recycled state and both attachment names. It writes new private and `.pub`
attachments plus selected KeeAgent source in one existing history/save
transaction, preserving agent policy. Existing attachments/files are never
overwritten; a selected previous source remains available. Generating or saving
does not load or remove agent keys. Existing attachment export provides file
export of either generated attachment.

Cancel and consumed plans release private state; encoded buffers and serialized
plans receive explicit wiping, while upstream key-object lifetime/allocator
behavior remains unchanged. Expired plans cannot be used and are released on
subsequent SSH operations or helper teardown. Security lock destroys the vault
helper. This does not claim complete erasure of every transient Qt/Botan copy.

Only runtime compilation is performed for this batch, at the user's request.
OpenSSH signing/import, encrypted and unencrypted files, all algorithms,
history/save/recovery, token expiry, cancellation and desktop acceptance remain
for manual stress testing. No tests or harnesses were added or run.
