# Phase 4: storage and crypto

Phase 4 is wired into the root A11 build and has host coverage through
`make phase4-test`.

The layers are deliberately separated:

- `src/drivers/nand.c` owns controller reset, ID validation, page reads,
  bad-block markers, controller ECC status, and page-sink iteration.
- `src/fs/apfs.c` consumes a block-reader callback. It parses NXSB/APSB,
  validates object checksums, walks variable-key/value B-tree nodes, decodes
  file extents, and streams extent data to a sink.
- `src/drivers/aes.c` owns the hardware AES transaction. GID/UID keys remain
  in their hardware slots. The software AES-256 path is used for public known
  vectors and does not stand in for silicon GID verification.
- `src/research/keybag.c` accepts bounded DER and fixed-width KBAG records.
  It reports class/wrap/length metadata and an internal GID-check status; it
  does not print or return decrypted hardware key bytes to the shell.

Shell commands:

```text
nand id
nand info
nand bad <block>
nand read <block> <page>
nand dump <first-block> <last-block>
apfs scan
aes test
aes decrypt <16-byte-ciphertext-hex>
keybag <img4-or-kbag-hex>
```

The A11 NAND/AES addresses and geometry are still marked unverified. The
driver fails closed when the controller ID/status window does not respond.
The APFS shell command stops after container/volume metadata because OMAP
virtual-object translation and pathname lookup need a captured, verified A11
checkpoint layout.
