# Clean-room boundary

dr1zzle may use publicly observable facts and high-level research conclusions:
addresses measured from hardware, documented CPU behavior, and device-tree
facts. It must not copy source, APIs, names, implementation structure, binary
payloads, proprietary firmware, or device-bypass procedures from other tools.

The `iphemeral-latest` tree was consulted only for architectural direction:
keep CPU-independent platform data separate from execution, make time
deterministic, and validate accesses at the fabric boundary. No source files,
types, or implementation text were imported.

The initial target is a safe host simulator. Physical-device transports,
security-bypass logic, jailbreak workflows, firmware decryption, and restore
automation are out of scope.
