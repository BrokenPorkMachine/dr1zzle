# Architecture

The bare-metal image begins in AArch64 assembly, establishes a private stack,
zeros `.bss`, and calls `kernel_main`. The generic QEMU `virt` board adapter is
the only component that knows about its UART. The libc has no board knowledge;
output goes through a single console hook.

```text
reset entry -> kernel_main -> monitor -> console -> board UART
                                  -> libdrizzle (memory, strings, format, heap)
```

No libc routine uses a syscall, assumes an operating system, or allocates
implicitly. Heap allocation is opt-in and bounded by linker-defined memory.
`snprintf` always NUL-terminates when its buffer length is non-zero and returns
the length that would have been produced.

The first board is deliberately generic. A future board profile belongs in
data/configuration rather than hard-coded execution paths.

The monitor is intentionally small and deterministic. Its QEMU-safe commands
are `help`, `info`, `heap`, `net`, `clear`, and a `reboot` stub; physical-device
transport and exploit-delivered payload behavior are out of scope for this tree.
