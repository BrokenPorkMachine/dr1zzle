# Hardware profiles and AP memory budgets

The portable monitor now has a working profile build, independent of the root
A11 payload build. Profiles are trusted, compiled data with a version, name,
at most eight disjoint memory regions, an exclusive OS arena, and byte budgets.
The implementation allocates nothing and performs no device probing or MMIO.
`AP` here means application processor; these budgets concern memory, not watts,
CPU scheduling, or real-time execution guarantees.

| QEMU profile | OS arena | Image ceiling (including BSS) | Heap | Stack | Reserved headroom |
| --- | ---: | ---: | ---: | ---: | ---: |
| small (default) | 256 KiB | 192 KiB | 32 KiB | 16 KiB | 16 KiB |
| monitor | 2 MiB | 1792 KiB | 64 KiB | 64 KiB | 128 KiB |

Both profiles use QEMU `virt`, 128 MiB machine RAM, one core, PL011 serial,
and an OS arena beginning at `0x40080000`. The machine RAM includes the boot
loader's space; the monitor owns only its arena. The 256 KiB figure is the
monitor's budget, not QEMU's required host memory or a physical board claim.

```sh
make profiles                         # build the small portable monitor
make profiles PROFILE=monitor         # build the larger portable monitor
make profiles-test                    # host sanitizer + link + QEMU checks
make profiles-qemu PROFILE=small       # interactive QEMU monitor
```

Requires clang with AArch64 support, `ld.lld`, Python 3, and
`qemu-system-aarch64`. Override `PROFILE_CC`, `PROFILE_LD`, `HOST_CC`, or `QEMU`
for local tool paths. Artifacts are isolated in `build/profiles/<profile>/`.
These targets do not use the root A11 linker script or device delivery targets.

## Enforcement

`drizzle/hardware.h` is the public allocation-free API. Validation rejects bad
versions, empty/overflowing ranges, overlapping regions, invalid arena ownership,
misalignment, and budgets exceeding the arena. Reserved regions must be separate
from RAM entries: split a RAM entry around a reserved hole. All intervals are
half-open; zero-length intervals are invalid. Range arithmetic and budget sums
are checked without unsigned wrapping. Failure never changes the caller's
remaining-byte result.

`boards/qemu_budget.h` supplies the same constants to compiled profile data and
the preprocessed linker script. Link assertions account for code, read-only data,
data, BSS, alignment, heap, stack, and reserved headroom. Startup validates actual
image, heap, and stack sizes before initializing the allocator or network state.
The heap allocator receives exactly the linked heap extent. Heap and stack are
NOLOAD sections, avoiding padding them into a flat binary's stored data.
The portable build uses general registers only; startup need not enable SIMD.

Budgets are ceilings. Unused image budget does not automatically enlarge the
heap. Static network queues count toward BSS. Reserved headroom is unavailable
to the allocator. Stack budgeting reserves space but does not detect stack
overflow; no MMU guard page or runtime stack watermark is implemented here.

## Physical board integration still required

The A11 `src/` build retains its existing implementation and is not validated by
these QEMU tests. Its unverified peripheral maps are not promoted to supported
profiles. A physical AP profile needs independently verified RAM ownership,
reserved ranges, boot-entry contract, console/timer adapters, and device testing.
Do not treat successful QEMU validation as evidence for an A11 driver.

For another board, supply compiled region/arena data, its linker layout and
budget constants, and a board adapter. Validate the profile before touching
optional peripherals. Incoming device trees require a bounded parser; this API
is not a serialized format and must never be populated by casting incoming bytes.
