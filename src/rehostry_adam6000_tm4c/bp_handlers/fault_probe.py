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

import os
from typing import Any, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

log = hal_log.getHalLogger()

_WATCH_INSTALLED = False


def install_watchpoint(qemu: Any) -> None:
    """Log every write into ``HAL_ADAM_WATCH`` ("<addr>:<len>"), with the PC.

    When a struct holds a value nobody admits to writing, stop reasoning about
    which model *could* have written it and ask the emulator who did. This is
    the memory-write equivalent of instrumenting the check (playbook §2.104):
    four hypotheses about the receive fault were wrong, and the field turned out
    to be 0xFFFFFFFF before the interrupt handler ever touched it.

    Off unless the variable is set -- a write hook over a live region costs a
    Python call per store.
    """
    global _WATCH_INSTALLED
    spec = os.environ.get("HAL_ADAM_WATCH")
    if not spec or _WATCH_INSTALLED:
        return
    uc = getattr(qemu, "_uc", None)
    if uc is None:
        return
    addr_s, _, len_s = spec.partition(":")
    lo = int(addr_s, 0)
    hi = lo + (int(len_s, 0) if len_s else 4) - 1
    try:
        from unicorn import UC_HOOK_MEM_WRITE, arm_const

        def _on_write(uc_, access, address, size, value, _ud):   # noqa: ANN001
            log.error("WATCH: write %d bytes = 0x%x to 0x%08x from pc=0x%08x",
                      size, value, address, uc_.reg_read(arm_const.UC_ARM_REG_PC))

        uc.hook_add(UC_HOOK_MEM_WRITE, _on_write, begin=lo, end=hi)
        _WATCH_INSTALLED = True
        log.error("WATCH: armed on 0x%08x..0x%08x", lo, hi)
    except Exception as exc:                     # noqa: BLE001
        log.error("WATCH: could not arm: %s", exc)

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
        self._rx_walks = 0
        self._copies = 0

    @staticmethod
    def _probing() -> bool:
        """The two probes below are how the receive fault was found.

        They are kept, and kept off: each answers a question that took several
        wrong guesses to ask properly, and the next person to meet a silent
        receive path on this device should not have to write them again. Set
        HAL_ADAM_PROBE=1.
        """
        return os.environ.get("HAL_ADAM_PROBE") == "1"

    @bp_handler(["lwip_rx_walk"])
    def lwip_rx_walk(self, qemu: Any,
                     bp_addr: int) -> Tuple[bool, Optional[int]]:
        """Read the pointer chain the receive walk is about to dereference.

        Three guesses at this fault have now been wrong, so this reads the
        actual chain instead: `r5 = [[r0+28]+8]`, and then the ring base and
        index `r5` is about to use. Instrumenting the check beats a fourth
        hypothesis (playbook §2.104).
        """
        if self._rx_walks >= 3 or not self._probing():
            return False, None
        self._rx_walks += 1
        try:
            r0 = qemu.read_register("r0")
            state = qemu.read_memory(r0 + 28, 4, 1)
            mgr = qemu.read_memory(state + 8, 4, 1) if 0x20000000 <= state \
                < 0x20040000 else None
            log.error("RX walk #%d: arg=0x%08x  [arg+28]=0x%08x  "
                      "[[arg+28]+8]=%s", self._rx_walks, r0, state,
                      "0x%08x" % mgr if mgr is not None
                      else "<unreadable: [arg+28] is not SRAM>")
            uc = getattr(qemu, "_uc", None)
            if uc is not None and self._rx_walks == 1:
                # Which struct is the interface the stack actually brought up?
                # 10.0.0.1 is this product's documented default address, and
                # the firmware ARPs for it, so its netif holds that word.
                blob = uc.mem_read(0x20000000, 0x40000)
                ip = (10) | (0 << 8) | (0 << 16) | (1 << 24)
                needle = ip.to_bytes(4, "little")
                at = [0x20000000 + i for i in range(0, len(blob) - 4)
                      if blob[i:i + 4] == needle]
                log.error("   10.0.0.1 appears at: %s",
                          " ".join("0x%08x" % a for a in at[:12]))
                for a in at[:12]:
                    cand = a - 4                 # netif->ip_addr is at +4
                    if cand % 4 or not 0x20000000 <= cand < 0x2003FF00:
                        continue
                    w = [int.from_bytes(blob[cand - 0x20000000 + 4 * i:
                                             cand - 0x20000000 + 4 * i + 4],
                                        "little") for i in range(12)]
                    log.error("   cand netif@0x%08x: %s", cand,
                              " ".join("+%d=%08x" % (4 * i, v)
                                       for i, v in enumerate(w)))
            words = [qemu.read_memory(r0 + 4 * i, 4, 1) for i in range(12)]
            log.error("   struct@0x%08x: %s", r0,
                      " ".join("+%d=%08x" % (4 * i, w)
                               for i, w in enumerate(words)))
            if mgr is not None and 0x20000000 <= mgr < 0x20040000:
                log.error("   ring base=0x%08x count=%d index=%d",
                          qemu.read_memory(mgr, 4, 1),
                          qemu.read_memory(mgr + 4, 4, 1),
                          qemu.read_memory(mgr + 8, 4, 1))
        except Exception as exc:                 # noqa: BLE001
            log.error("RX walk probe failed: %s", exc)
        return False, None

    @bp_handler(["bss_copy_loop"])
    def bss_copy_loop(self, qemu: Any,
                      bp_addr: int) -> Tuple[bool, Optional[int]]:
        """Where does the 0xFF that lands on the interface struct come from?"""
        if self._copies >= 4 or not self._probing():
            return False, None
        try:
            dst = qemu.read_register("r2")
            if not 0x200140C0 <= dst < 0x200140F0:
                return False, None
            self._copies += 1
            src = qemu.read_register("r0")
            log.error("copy #%d onto the interface struct: src=0x%08x "
                      "dst=0x%08x len=0x%x done=0x%x lr=0x%08x", self._copies,
                      src, dst, qemu.read_register("r1"),
                      qemu.read_register("r3"), qemu.read_register("lr"))
            log.error("   src base=0x%08x (this word is 0x%08x)",
                      src - qemu.read_register("r3"),
                      qemu.read_memory(src, 4, 1))
        except Exception as exc:                 # noqa: BLE001
            log.error("copy probe failed: %s", exc)
        return False, None

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
