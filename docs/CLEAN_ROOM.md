# Clean-room boundary

dr1zzle may use publicly observable facts and high-level research conclusions:
addresses measured from hardware, documented CPU behavior, and device-tree
facts. It must not copy source, APIs, names, implementation structure, binary
payloads, proprietary firmware, or device-bypass procedures from other tools.

Where a procedure has to be implemented rather than described, the boundary is
the same: the published *analysis* of a bug may be a specification, and the
machine it describes may be measured from this project's own images and from
runs of them in this project's own emulator. The legacy exploit tooling that
used to be vendored here (`ipwndfu/`) has been removed, and
[docs/CHECKM8_IMPLEMENTATION.md](CHECKM8_IMPLEMENTATION.md) records which
constants were derived that way and which are still unmeasured.

The `iphemeral-latest` tree was consulted only for architectural direction:
keep CPU-independent platform data separate from execution, make time
deterministic, and validate accesses at the fabric boundary. No source files,
types, or implementation text were imported.

The initial target is a safe host simulator. Physical-device transports,
security-bypass logic, jailbreak workflows, firmware decryption, and restore
automation are out of scope.
