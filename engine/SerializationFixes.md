# Serialization corrections

`SerializationFixes.patch` corrects two defects reproduced in the pinned
KeePassXC 2.7.12 core. These are Keyslot corrections, separate from the upstream
security backports; original source copyright and GPL licensing are retained.

- **Stream-cipher finalization:** a write ending exactly on the 1,024-byte
  stream buffer boundary leaves an empty final buffer. Calling `process` on
  that buffer fails with “Cannot process 0 length data.” The final empty chunk
  is now a no-op for stream ciphers. Block-cipher padding remains in place.
  A small reproduction using the original Qt5/Botan source fails at 1,024 and
  2,048 bytes and succeeds at 1,023 and 1,025; the corrected source succeeds at
  all four lengths. The build-time native gate covers empty, neighboring and
  multiple-boundary lengths for ChaCha20, Salsa20, AES-CTR, AES-CBC and Twofish.
- **Standalone XML attachments:** KDBX4 normally stores binary attachments in
  its encrypted inner header, outside XML. Plain XML extraction omitted both
  the binary index and binary content, leaving unresolved attachment references
  on reimport. Explicit unprotected XML extraction now emits the binary map and
  content for every version; encrypted KDBX4 serialization keeps its inner
  header representation. The native gate checks current and historical binary
  attachments; application integration checks the complete export/import path.

The format matrix also exercises all advertised cipher/KDF/compression
combinations and upstream KDBX3/4 encrypted-copy preservation. Release evidence
is recorded only after the complete candidate passes.
