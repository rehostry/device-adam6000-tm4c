# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The whole 0x40000000 peripheral space, routed one 4 KB page at a time.

One region rather than a dozen: HALucinator peripheral regions may not overlap
and must be 4 KB-aligned multiples of 4 KB (playbook §2.39/§2.61), and the
peripherals this device needs are scattered across a 1 MB window. Declaring each
one plus the filler regions between them is a dozen config entries kept
consistent by hand, where one arithmetic slip leaves a hole that surfaces as a
mysterious abort.

Most of the SoC is left to the catch-all on purpose. The firmware drives GPIO,
SSI, UART and uDMA through the TM4C's masked ROM (see tiva_rom.py), so those
registers are never touched directly; what IS touched directly is the flash
controller and the Ethernet MAC, and those get real models.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from halucinator import hal_log

from .soc_catchall import SocCatchAll
from .tiva_emac import TivaEmac
from .tiva_flashctrl import TivaFlashCtrl
from .tiva_hib import TivaHib

log = hal_log.getHalLogger()

APB_BASE = 0x40000000
PAGE = 0x1000

# page index -> (attribute, class, label)
LAYOUT = [
    (0xEC, "emac", TivaEmac, "EMAC0 (Ethernet)"),
    (0xFC, "hib", TivaHib, "Hibernation module (RTC + retained RAM)"),
    (0xFD, "flashctrl", TivaFlashCtrl, "FLASH controller"),
]

_APB: Optional["TivaApb"] = None


def get_apb() -> Optional["TivaApb"]:
    return _APB


class TivaApb(SocCatchAll):
    """Routes 0x40000000..0x40100000 to the modelled peripherals."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.pages: Dict[int, Any] = {}
        for page, attr, cls, _label in LAYOUT:
            model = cls(f"{name}.{attr}", address + page * PAGE, PAGE, **kwargs)
            self.pages[page] = model
            setattr(self, attr, model)
        global _APB
        _APB = self
        log.info("TivaApb: modelling %s; every other page falls through to the "
                 "catch-all", ", ".join(lbl for _, _, _, lbl in LAYOUT))

    def set_backend(self, backend: Any) -> None:
        for model in self.pages.values():
            if hasattr(model, "set_backend"):
                model.set_backend(backend)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        model = self.pages.get(offset >> 12)
        if model is None:
            return super().hw_read(offset, size, pc, **kwargs)
        return model.hw_read(offset & (PAGE - 1), size, pc, **kwargs)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        model = self.pages.get(offset >> 12)
        if model is None:
            return super().hw_write(offset, size, value, pc, **kwargs)
        return model.hw_write(offset & (PAGE - 1), size, value, pc, **kwargs)
