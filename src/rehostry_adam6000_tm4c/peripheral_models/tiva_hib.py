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

# TM4C129x calendar mode. The firmware spins on bit 31 (VALID) of both calendar
# words before it will read either -- `ldr r3,[r1,#20]; cmp r3,#0; bpl .` at
# 0x00046B02 -- and then demands that HIBCAL1 read the same twice, so the date
# must not move underneath it. Without VALID the provisioned boot never reaches
# lwIP; the only symptom is a device that stops printing after "sntp sync".
HIB_CALCTL = 0x300
HIB_CAL0 = 0x310          # VALID | HR<<16 | MIN<<8 | SEC
HIB_CAL1 = 0x314          # VALID | DOW<<24 | YEAR<<16 | MON<<8 | DOM
HIB_VALID = 1 << 31

# A FIXED DATE, deliberately. There is no battery and no host clock behind this
# model, and a rehost that quietly picks up the wall clock makes runs that
# cannot be compared with each other. 2026-01-01 is arbitrary and stable.
CAL_YEAR, CAL_MONTH, CAL_DAY, CAL_DOW = 26, 1, 1, 4


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
        if offset == HIB_CAL1:
            return (HIB_VALID | (CAL_DOW << 24) | (CAL_YEAR << 16)
                    | (CAL_MONTH << 8) | CAL_DAY)
        if offset == HIB_CAL0:
            secs = self.seconds
            return (HIB_VALID | (((secs // 3600) % 24) << 16)
                    | (((secs // 60) % 60) << 8) | (secs % 60))
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
