# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The TM4C Hibernation module -- the RTC and its battery-backed RAM.

WHY IT NEEDS A MODEL AND THE CATCH-ALL WILL NOT DO. Two of its registers are
exactly the shape the catch-all handles worst:

  * **HIBCTL.WRC** (bit 31) is a write-complete handshake. Every write to this
    module has to be followed by a spin on it, so the firmware polls one address
    from one PC forever -- which is what the busy-wait breaker is for, except
    that here the breaker's escalating answer never settles and the boot stops
    at `sntp sync : 255`.

  * **HIBDATA** (0x400FC030 upward) is battery-backed RAM. Answering it with
    0xFFFFFFFF tells the firmware there is saved state when there is none; this
    device then reports `RTCExisted=1` and takes a path that does not exist on a
    board with no battery.

Zero is the honest answer for retained RAM that has never been written, and WRC
is always ready because there is no real 32 kHz domain to cross.
"""
from __future__ import annotations

from typing import Any, Dict

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

HIB_RTCC = 0x000
HIB_CTL = 0x010
HIB_WRC = 1 << 31


class TivaHib(SocCatchAll):
    """RTC counter, a ready write-complete bit, and retained RAM."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.words: Dict[int, int] = {}
        self.seconds = 0
        self.reads = 0

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if offset == HIB_CTL:
            # Always ready: there is no 32 kHz domain to synchronise with.
            return self.words.get(offset, 0) | HIB_WRC
        if offset == HIB_RTCC:
            # A seconds counter that advances, so a firmware that waits for it
            # to move is not waiting forever.
            self.reads += 1
            if self.reads % 64 == 0:
                self.seconds += 1
            return self.seconds
        return self.words.get(offset, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        self.words[offset] = value & 0xFFFFFFFF
        return True
