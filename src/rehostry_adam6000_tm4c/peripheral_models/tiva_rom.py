# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The TM4C's on-chip ROM -- a HAL boundary the silicon hands you on a plate.

WHAT THIS IS. TI's Tiva parts ship a masked ROM at 0x01000000 containing a copy
of TivaWare's driverlib, reached through a two-level table of function pointers::

    ROM_APITABLE  = (uint32_t *)0x01000010
    ROM_SYSCTLTABLE = (uint32_t *)(ROM_APITABLE[n])
    ROM_SysCtlPeripheralEnable(x)   ->  ((void (*)(uint32_t))SYSCTLTABLE[6])(x)

so a `ROM_*` call compiles to *load a table pointer, load an entry, branch*.
This firmware uses them, and the ROM contents are not in the image -- they are in
silicon we do not have.

WHY IT CANNOT SIMPLY BE LEFT UNMODELLED. With 0x01000000 unmapped the run aborts
on the first table read. With it served by the catch-all it is worse and much
harder to read: the busy-wait breaker returns an escalating value, the firmware
dereferences that as a table pointer, and the result lands *inside the firmware's
own vector table* -- so it fetched 0x0000F0C1 and `blx`'d into the shared default
handler, which is a `b .`. The device hung in thread mode with IPSR = 0, which is
exactly what an exception does NOT look like, after two wrong guesses about which
fault it was.

WHAT THIS DOES INSTEAD. It answers the table structurally:

  * a read of ``APITABLE[i]`` returns a synthetic sub-table address, distinct
    per ``i``;
  * a read of ``SUBTABLE[j]`` returns a **distinct stub address** per (i, j),
    inside a region the extractor fills with `bx lr`.

So every ROM call now goes somewhere real. Unimplemented ones return
immediately, which is the right default: most driverlib calls are configuration
(`SysCtlPeripheralEnable`, `GPIOPinTypeUART`, `IntEnable`) whose effect this
rehost models at the register level anyway or does not need at all. Only calls
that must *return a value* need an implementation, and those announce themselves
by breaking.

RECOVERING WHICH FUNCTION IS WHICH, WITHOUT rom.h. The table indices are a
TivaWare-version detail, so rather than assume a layout this logs every
(table, entry) the firmware fetches and lets the **call site** name it. That
works because driverlib arguments are self-identifying: the first ROM call this
firmware makes passes 0xF0000800 -- a `SYSCTL_PERIPH_*` constant -- from code
that also loads UART0's base address, so it is
``SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0)`` and its table is the SysCtl one.
Names in ``KNOWN`` were each pinned that way; the log line is the evidence.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

ROM_BASE = 0x01000000
APITABLE_OFF = 0x10          # ROM_APITABLE lives at 0x01000010
SUBTABLE_OFF = 0x1000        # synthetic sub-tables start here, in this region
SUBTABLE_STRIDE = 0x100      # 64 entries each
ENTRIES_PER_TABLE = SUBTABLE_STRIDE // 4
MAX_TABLES = 48

# Where the `bx lr` stub blob is mapped. Must match the config's `rom_stubs`
# region and tools/extract_firmware.py:ROM_STUB_SIZE.
STUB_BASE = 0x01010000
STUB_SIZE = 0x4000

# (table index, entry index) -> the driverlib function it turned out to be,
# each identified from the arguments at its call site rather than from a header.
KNOWN: Dict[Tuple[int, int], str] = {
    (13, 6): "SysCtlPeripheralEnable",
}


def trace_enabled() -> bool:
    """Log every distinct ROM entry the firmware fetches (default on).

    This is the map of exactly which driverlib functions the firmware depends
    on, and it costs one line per entry, once.
    """
    return os.environ.get("HAL_ADAM_ROM_TRACE", "1") == "1"


def stub_for(table: int, entry: int) -> int:
    """Address of the stub for one API-table entry, **with the Thumb bit set**.

    A real function pointer on a Cortex-M carries bit 0 = 1, and the firmware
    reaches these through `blx`, which reads that bit to choose the instruction
    set. Hand back a word-aligned address and `blx` switches to ARM state, which
    an M-profile core does not have: the run dies with UC_ERR_INSN_INVALID at
    the stub, pointing at a perfectly valid `bx lr`.
    """
    return STUB_BASE + (table * ENTRIES_PER_TABLE + entry) * 4 + 1


class TivaRom(SocCatchAll):
    """Answers the ROM API table with pointers into the stub region."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.table_reads = 0
        self.entry_reads = 0
        self.seen: set = set()
        self._trace = trace_enabled()
        log.info("TivaRom: synthesising the driverlib API table at 0x%08x; "
                 "unimplemented calls land on `bx lr` stubs at 0x%08x",
                 address + APITABLE_OFF, STUB_BASE)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        # --- the top-level table: APITABLE[i] -> a sub-table address --------
        if APITABLE_OFF <= offset < APITABLE_OFF + MAX_TABLES * 4:
            i = (offset - APITABLE_OFF) // 4
            self.table_reads += 1
            addr = self.base + SUBTABLE_OFF + i * SUBTABLE_STRIDE
            if self._trace and ("t", i) not in self.seen:
                self.seen.add(("t", i))
                log.info("ROM: APITABLE[%d] fetched (pc=0x%08x) -> sub-table "
                         "0x%08x", i, pc, addr)
            return addr

        # --- a sub-table: SUBTABLE[j] -> a distinct stub --------------------
        if SUBTABLE_OFF <= offset < SUBTABLE_OFF + MAX_TABLES * SUBTABLE_STRIDE:
            rel = offset - SUBTABLE_OFF
            table, entry = rel // SUBTABLE_STRIDE, (rel % SUBTABLE_STRIDE) // 4
            self.entry_reads += 1
            addr = stub_for(table, entry)
            if self._trace and ("e", table, entry) not in self.seen:
                self.seen.add(("e", table, entry))
                known = KNOWN.get((table, entry))
                log.info("ROM: table[%d] entry[%d] fetched (pc=0x%08x) -> stub "
                         "0x%08x%s", table, entry, pc, addr & ~1,
                         f"  == {known}" if known else "  (unidentified)")
            return addr

        # ROM_VERSION and anything else: zero is a safer answer than the
        # busy-wait breaker's escalating one, which is what caused the original
        # branch into the vector table.
        return 0

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        return True                            # masked ROM is read-only
