# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The internal flash controller at 0x400FD000 -- where the device saves config.

The ADAM-6000 keeps its settings (IP address, Modbus enables, the DIO state it
should restore) in the microcontroller's own flash, written through the FLASH
controller rather than by a store to the flash address space. The firmware fills
a 32-word write buffer, points FMA at a page, writes FMC2 with the WRBUF command
and the 0xA442 key, and polls FMC2 until the command bit self-clears.

WHY THE CATCH-ALL CANNOT SERVE THIS. Those polls are the busy-wait breaker's
worst case: one PC reading one address, forever, with the answer meaning
"still busy" for every value the breaker escalates through. 19,207 polls of FMC2
and 19,196 of FCRIS in a single run, and the save never completes. The command
bits read back **zero** on real silicon once the operation is done, which is
also the answer that lets the firmware move on.

The writes are performed for real, into the mapped flash region, so a setting
the firmware saves is a setting it can read back -- which is the whole point of
the register from the firmware's side.
"""
from __future__ import annotations

from typing import Any, Optional

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

FMA = 0x000        # address
FMD = 0x004        # data (single-word write)
FMC = 0x008        # command + key
FCRIS = 0x00C      # raw interrupt status
FCIM = 0x010
FCMISC = 0x014
FMC2 = 0x020       # buffered-write command + key
FWBVAL = 0x030     # which write-buffer words are valid
FWB0 = 0x100       # 32-word write buffer
FWB_WORDS = 32

FLASH_KEY = 0xA442
CMD_WRITE = 1 << 0
CMD_ERASE = 1 << 1
CMD_MERASE = 1 << 2
CMD_WRBUF = 1 << 0        # in FMC2

FLASH_PAGE = 0x4000       # 16 KB erase page on a TM4C129x


class TivaFlashCtrl(SocCatchAll):
    """Performs the firmware's own flash writes, and reports them complete."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.regs = {}
        self.buffer = [0] * FWB_WORDS
        self.writes = 0
        self.erases = 0
        self._backend: Optional[Any] = None

    def set_backend(self, backend: Any) -> None:
        self._backend = backend

    # The internal flash. A write outside it is this model getting FMA wrong,
    # not the firmware programming something exotic -- and it would land in
    # SRAM, silently corrupting whatever lives there.
    FLASH_LO = 0x00000000
    FLASH_HI = 0x00100000

    def _poke(self, addr: int, words) -> None:
        if self._backend is None:
            return
        end = addr + len(words) * 4
        if not (self.FLASH_LO <= addr and end <= self.FLASH_HI):
            log.error("FLASH: refusing a %d-byte write to 0x%08x -- outside "
                      "the flash region. FMA=0x%08x", len(words) * 4, addr,
                      self.regs.get(FMA, 0))
            return
        try:
            data = b"".join(int(w & 0xFFFFFFFF).to_bytes(4, "little")
                            for w in words)
            self._backend.write_memory(addr, 1, data, len(data))
        except Exception:                        # noqa: BLE001
            log.exception("flash write to 0x%08x failed", addr)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if offset in (FMC, FMC2):
            # The command bits self-clear when the operation finishes, and in a
            # rehost it finished before the firmware could look.
            return 0
        if offset == FCRIS:
            return 0                             # no programming or access error
        return self.regs.get(offset, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        value &= 0xFFFFFFFF
        if FWB0 <= offset < FWB0 + FWB_WORDS * 4:
            self.buffer[(offset - FWB0) // 4] = value
            return True
        self.regs[offset] = value
        if offset == FMC and (value >> 16) == FLASH_KEY:
            addr = self.regs.get(FMA, 0)
            if value & CMD_ERASE:
                page = addr & ~(FLASH_PAGE - 1)
                self._poke(page, [0xFFFFFFFF] * (FLASH_PAGE // 4))
                self.erases += 1
            elif value & CMD_WRITE:
                self._poke(addr, [self.regs.get(FMD, 0xFFFFFFFF)])
                self.writes += 1
        elif offset == FMC2 and (value >> 16) == FLASH_KEY and value & CMD_WRBUF:
            addr = self.regs.get(FMA, 0)
            valid = self.regs.get(FWBVAL, (1 << FWB_WORDS) - 1)
            words = [self.buffer[i] if (valid >> i) & 1 else 0xFFFFFFFF
                     for i in range(FWB_WORDS)]
            self._poke(addr, words)
            self.writes += 1
            if self.writes <= 3:
                log.info("FLASH: buffered write of %d words to 0x%08x",
                         FWB_WORDS, addr)
        return True
