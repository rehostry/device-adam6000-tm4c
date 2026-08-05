# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The Cortex-M4 private peripheral bus -- NVIC, SysTick, and STIR.

DECLARED SO IT IS NOT AUTO-MAPPED, and claiming the whole 1 MB: the backend maps
the PPB in one call, so a partial claim leaves the remainder unmapped
(playbook §2.68).

THE CATCH-ALL IS THE WRONG THING HERE, and not by a little. Its busy-wait
breaker escalates the value it returns whenever one PC reads one address often
-- which is exactly what a *read-modify-write* looks like from the outside. This
firmware does::

    6b10:  ldr  r1, [r0]        ; r0 = 0xE000EF00
    6b12:  orr  r1, r1, #0x28
    6b16:  str  r1, [r0]

every time it wants to poke the Ethernet interrupt, so the breaker fired on it
forever: 401,059 escalation lines in one 60-second run, drowning the log and
starving the emulation. On the PPB, zero is the right default and the breaker is
pure harm.

**STIR is the interesting register.** 0xE000EF00 is the Software Trigger
Interrupt Register, and writing an interrupt number to it makes that interrupt
pending -- which is how this firmware hands work from thread mode to its
Ethernet ISR. `0x28` is 40, and IRQ 40 on a TM4C129x is EMAC0: the one live
external interrupt in the whole vector table. So this register *is* the
firmware's deferred-work mechanism, and a model that swallows it silently
removes the device's only interrupt.

The trigger is **queued, not injected**: appending to the backend's own pending
list is safe from an MMIO callback, synthesising an exception entry there is
not (playbook §2.7a).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

PPB_BASE = 0xE0000000

SYST_CSR = 0xE000E010
SYST_RVR = 0xE000E014
SYST_CVR = 0xE000E018
SYST_CALIB = 0xE000E01C
NVIC_ISER0 = 0xE000E100
NVIC_ICER0 = 0xE000E180
NVIC_ISPR0 = 0xE000E200
NVIC_ICPR0 = 0xE000E280
CPUID = 0xE000ED00
ICSR = 0xE000ED04
VTOR = 0xE000ED08
CCR = 0xE000ED14
SHCSR = 0xE000ED24
CFSR = 0xE000ED28
STIR = 0xE000EF00

# Cortex-M4 r0p1, from the ARM TRM.
CPUID_CORTEX_M4 = 0x410FC241
# SysTick calibration: 10 ms at 12.5 MHz, with the value marked exact.
SYST_CALIB_VALUE = 125000

_PPB: Optional["CortexMPpb"] = None


def get_ppb() -> Optional["CortexMPpb"]:
    return _PPB


class CortexMPpb(SocCatchAll):
    """Plain NVIC/SysTick state, plus a working software interrupt trigger."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.words: Dict[int, int] = {}
        self.enabled_irqs: set = set()
        self.triggers = 0
        self.stir_writes = 0
        self.systick_ticks = 0
        self._backend: Optional[Any] = None
        global _PPB
        _PPB = self

    # -- wiring ------------------------------------------------------------
    def set_backend(self, backend: Any) -> None:
        """Handed the emulator by the first ROM call, from breakpoint context."""
        self._backend = backend

    def armed(self) -> List[int]:
        return sorted(self.enabled_irqs)

    def _queue_irq(self, irq: int) -> None:
        """Make an interrupt pending, at the emulator's next safe point.

        A plain append to the backend's cross-thread queue; the dispatch loop
        drains it between instruction chunks, where all CPU-state mutation is
        single-threaded. One outstanding delivery at a time -- the backend
        drains its whole queue back to back with no guest instructions in
        between, so two entries would be a nested exception entry rather than
        two interrupts (playbook §2.98).
        """
        queue = getattr(self._backend, "_pending_irqs", None)
        if queue is None or queue:
            return
        queue.append(irq)
        self.triggers += 1

    # -- registers ---------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr = self.base + offset
        if addr == CPUID:
            return CPUID_CORTEX_M4
        if addr == SYST_CALIB:
            return SYST_CALIB_VALUE
        if addr == SYST_CVR:
            # A down-counter. The tick itself is driven by the backend's
            # instruction-count pacer, but firmware that reads CVR for a
            # sub-tick delay must still see it move.
            cur = self.words.get(SYST_CVR, 0)
            reload_ = self.words.get(SYST_RVR, 0xFFFFFF) or 0xFFFFFF
            cur = (cur - 1) % (reload_ + 1)
            self.words[SYST_CVR] = cur
            return cur
        if addr == STIR:
            return 0                      # write-only on real silicon
        # Zero, NOT the busy-wait breaker's escalating value -- see the module
        # docstring. Nothing on the PPB is a status bit worth guessing at.
        return self.words.get(addr, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        addr = self.base + offset
        value &= 0xFFFFFFFF
        if addr == STIR:
            irq = value & 0x1FF
            self.stir_writes += 1
            # Gate on the WRITE count, not the queue count: _queue_irq declines
            # while a delivery is already outstanding, so gating on it logs
            # every single write forever (544,093 lines in one run).
            if self.stir_writes <= 3:
                log.info("NVIC STIR: firmware triggered IRQ %d in software "
                         "(pc=0x%08x)", irq, pc)
            self._queue_irq(irq)
            return True
        if NVIC_ISER0 <= addr < NVIC_ISER0 + 0x20:
            word = (addr - NVIC_ISER0) // 4
            for bit in range(32):
                if (value >> bit) & 1:
                    irq = word * 32 + bit
                    if irq not in self.enabled_irqs:
                        self.enabled_irqs.add(irq)
                        log.info("NVIC: firmware armed IRQ %d", irq)
            return True
        if NVIC_ICER0 <= addr < NVIC_ICER0 + 0x20:
            word = (addr - NVIC_ICER0) // 4
            for bit in range(32):
                if (value >> bit) & 1:
                    self.enabled_irqs.discard(word * 32 + bit)
            return True
        if addr == SYST_CSR and value & 1:
            if not self.words.get(SYST_CSR, 0) & 1:
                log.info("SysTick: enabled by the firmware (reload=%d)",
                         self.words.get(SYST_RVR, 0))
        self.words[addr] = value
        return True
