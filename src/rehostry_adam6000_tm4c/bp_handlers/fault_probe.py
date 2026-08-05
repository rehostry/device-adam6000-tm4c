# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reports WHICH exception reached the firmware's shared default handler.

This device's vector table sends NMI to one `b .`, HardFault to a second, and
**everything else** -- MemManage, BusFault, UsageFault, SVCall, DebugMon, PendSV
and all 111 unused external interrupts -- to a third at 0x0000F0C0. So landing
there is a silent hang that says nothing about its own cause, and guessing at it
is expensive: two hypotheses (an unmapped access, and SVCall) were tested and
both were wrong before this existed.

A breakpoint on the spin can just ask. `IPSR` holds the exception number, which
names the cause outright, and the exception frame the backend pushed holds the
PC the fault came *from* -- which is the address actually worth having.
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

log = hal_log.getHalLogger()

# ARMv7-M exception numbers, so the report names the cause rather than a number.
EXCEPTIONS = {
    1: "Reset", 2: "NMI", 3: "HardFault", 4: "MemManage", 5: "BusFault",
    6: "UsageFault", 11: "SVCall", 12: "DebugMonitor", 14: "PendSV",
    15: "SysTick",
}


def describe(exc: int) -> str:
    if exc in EXCEPTIONS:
        return EXCEPTIONS[exc]
    if exc >= 16:
        return f"external IRQ {exc - 16}"
    return f"reserved/unknown ({exc})"


class FaultProbe(BPHandler):
    """One-shot: says what arrived and where it came from, then stays quiet."""

    def __init__(self, **kwargs: Any) -> None:
        self.hits = 0
        self._reported = False
        self._reported_trap = False

    @bp_handler(["lwip_trap_spin"])
    def lwip_trap_spin(self, qemu: Any,
                       bp_addr: int) -> Tuple[bool, Optional[int]]:
        """A `b .` in the lwIP init path that nothing in the image points at."""
        if self._reported_trap:
            return False, None
        self._reported_trap = True
        try:
            log.error("lwIP trap at 0x%08x: LR=0x%08x SP=0x%08x r0=0x%08x "
                      "r1=0x%08x r2=0x%08x r3=0x%08x", bp_addr,
                      qemu.read_register("lr"), qemu.read_register("sp"),
                      qemu.read_register("r0"), qemu.read_register("r1"),
                      qemu.read_register("r2"), qemu.read_register("r3"))
        except Exception:                        # noqa: BLE001
            pass
        from ..peripheral_models.tiva_console import get_console
        get_console().flush()
        return False, None

    @bp_handler(["default_handler_spin"])
    def default_handler_spin(self, qemu: Any,
                             bp_addr: int) -> Tuple[bool, Optional[int]]:
        self.hits += 1
        if self._reported:
            return False, None
        self._reported = True

        exc = None
        uc = getattr(qemu, "_uc", None)
        if uc is not None:
            try:
                from unicorn import arm_const as A
                exc = uc.reg_read(A.UC_ARM_REG_IPSR) & 0x1FF
            except Exception:                    # noqa: BLE001
                exc = None

        try:
            lr = qemu.read_register("lr")
            sp = qemu.read_register("sp")
        except Exception:                        # noqa: BLE001
            lr = sp = 0

        log.error("DEFAULT HANDLER reached: IPSR=%s (%s)  LR=0x%08x  SP=0x%08x",
                  exc if exc is not None else "?",
                  describe(exc) if exc is not None else "unreadable", lr, sp)

        # The stacked frame the exception pushed: R0-R3, R12, LR, PC, xPSR.
        # The PC is the instruction the fault came from -- the whole point.
        try:
            frame = qemu.read_memory(sp, 4, 8)
            words = [int.from_bytes(frame[i * 4:i * 4 + 4], "little")
                     for i in range(8)]
            log.error("  stacked frame: r0=0x%08x r1=0x%08x r2=0x%08x "
                      "r3=0x%08x r12=0x%08x lr=0x%08x **pc=0x%08x** "
                      "xpsr=0x%08x", *words)
        except Exception:                        # noqa: BLE001
            log.error("  stacked frame unreadable at SP=0x%08x", sp)

        # The SCB fault status registers, for whatever the model holds.
        for name, addr in (("CFSR", 0xE000ED28), ("HFSR", 0xE000ED2C),
                           ("MMFAR", 0xE000ED34), ("BFAR", 0xE000ED38)):
            try:
                log.error("  %s (0x%08x) = 0x%08x", name, addr,
                          qemu.read_memory(addr, 4, 1))
            except Exception:                    # noqa: BLE001
                pass
        return False, None
