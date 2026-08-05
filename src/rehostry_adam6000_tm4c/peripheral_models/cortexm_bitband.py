# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The Cortex-M peripheral bit-band alias at 0x42000000.

WHAT IT IS. ARMv7-M gives the 1 MB peripheral window at 0x40000000 a 32 MB
alias in which every *word* maps to a single *bit* of the underlying region::

    alias = 0x42000000 + (byte_offset << 5) + (bit << 2)

A write of 1 or 0 to an alias word sets or clears that one bit atomically, with
no read-modify-write in the guest. Compilers and vendor HALs emit it freely, so
firmware can drive a peripheral for a long time without ever touching the real
address -- which is why the region can be missing from a config and nothing
notices until some specific path takes it.

WHY IT APPEARS HERE ONLY WITH A DEVICE PROFILE. Until this rehost had a profile
in its serial flash the module believed it had no I/O points, and the code that
configures them never ran. Give it twelve inputs and six outputs and it starts
setting up their pins -- through the alias -- and the run dies with
`UC_ERR_WRITE_UNMAPPED at PC=0x00032564`, in a routine whose only clue is
`orr.w r0, r0, #0x42000000`. Making the device more faithful is what uncovered
the gap (playbook §2.132).

WHAT THIS MODELS. The translation, forwarded to whatever already owns the
target address, so a bit set through the alias is visible to the peripheral
model that cares about it and vice versa. The alias holds no state of its own.
"""
from __future__ import annotations

from typing import Any

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

BITBAND_BASE = 0x42000000
BITBAND_SIZE = 0x02000000
PERIPH_BASE = 0x40000000


def alias_to_bit(alias: int) -> tuple:
    """(byte address, bit number) for one alias word."""
    offset = alias - BITBAND_BASE
    return PERIPH_BASE + (offset >> 5), (offset >> 2) & 7


class CortexMBitBand(SocCatchAll):
    """Translates alias accesses into single-bit accesses on the real region."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.hits = 0

    def _apb(self):
        from .tiva_apb import get_apb
        return get_apb()

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr, bit = alias_to_bit(self.base + offset)
        apb = self._apb()
        if apb is None:
            return 0
        try:
            word = apb.hw_read(addr - apb.base, 4, pc=pc)
        except Exception:                        # noqa: BLE001
            return 0
        return (word >> bit) & 1

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        addr, bit = alias_to_bit(self.base + offset)
        self.hits += 1
        if self.hits <= 3:
            log.info("bit-band: %s bit %d of 0x%08x (pc=0x%08x)",
                     "set" if value & 1 else "cleared", bit, addr, pc)
        apb = self._apb()
        if apb is None:
            return True
        try:
            word = apb.hw_read(addr - apb.base, 4, pc=pc)
            word = (word | (1 << bit)) if value & 1 else (word & ~(1 << bit))
            apb.hw_write(addr - apb.base, 4, word, pc=pc)
        except Exception:                        # noqa: BLE001
            pass
        return True
