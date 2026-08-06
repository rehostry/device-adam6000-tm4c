# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Implementations of the TivaWare ROM calls this firmware actually depends on.

Every entry in the TM4C's masked-ROM API table is answered by
`peripheral_models/tiva_rom.py` with a distinct address in a region of `bx lr`,
so an unmodelled ROM call already returns harmlessly. These are the ones where
returning immediately is not good enough -- either because the firmware *spins*
on the return value, or because the call is the only path to something the
device needs.

WHY SO FEW ARE NEEDED. Most of driverlib is configuration: `GPIOPinConfigure`,
`GPIOPinTypeUART`, `SysCtlPeripheralEnable` all describe a hardware setup that
this rehost either models at the register level or does not need at all, so
their stubs are left as `bx lr` **on purpose** and are listed here only to say
so. They are still named, because a named no-op is evidence and an anonymous one
is a question.

Each handler returns ``(True, value)``: the stub is never executed, the caller's
``lr`` becomes the new PC and ``value`` becomes r0 -- which is exactly a
function returning.
"""
from __future__ import annotations

import os
from typing import Any, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

from ..peripheral_models.cortexm_ppb import get_ppb
from ..peripheral_models.tiva_apb import get_apb
from ..peripheral_models.tiva_emac import EMAC_IRQ
from ..peripheral_models.spi_flash import get_flash
from ..peripheral_models.tiva_udma import get_udma
from ..peripheral_models.tiva_console import get_console

# The serial NOR flash's chip select: GPIO Q (0x40066000), pin 1.
SFLASH_CS_PORT = 0x40066000
SFLASH_CS_PIN = 1 << 1

log = hal_log.getHalLogger()


class TivaRomApi(BPHandler):
    """The driverlib entry points the firmware cannot get past without."""

    def __init__(self, **kwargs: Any) -> None:
        self.chars = 0
        self.busy_polls = 0
        self.periph_enables = 0
        self._present_checks = 0
        self.spi_bytes = 0
        self._rx: list = []
        self._logged_uart = False
        self._wired = False
        self.ticks = 0
        self._tick_calls = 0
        self._tick_every = int(os.environ.get("HAL_ADAM_TICK_EVERY", "4000"), 0)
        # The frame path runs far more often than the clock: it is what makes
        # the device answer, and it costs a ring scan.
        self._net_every = int(os.environ.get("HAL_ADAM_NET_EVERY", "64"), 0)
        self._samples = 0
        self._sample_calls = 0

    def _sample_state(self, qemu: Any) -> None:
        """Watch one word settle, to tell "never set" from "not set yet".

        A field that is wrong at the moment of use tells you nothing about
        whether the firmware would have set it later. Sampling it over time
        does, and it is the difference between a missing initialisation and a
        frame delivered before the driver exists (playbook §2.125).
        """
        spec = os.environ.get("HAL_ADAM_SAMPLE_STATE")
        if not spec or self._samples >= 40:
            return
        self._sample_calls += 1
        if self._sample_calls % 200:
            return
        self._samples += 1
        try:
            addr = int(spec, 0)
            log.error("SAMPLE %d (tick %d): [0x%08x] = 0x%08x", self._samples,
                      self.ticks, addr, qemu.read_memory(addr, 4, 1))
        except Exception as exc:                 # noqa: BLE001
            log.error("SAMPLE failed: %s", exc)

    def _tick(self, qemu: Any) -> None:
        """Advance SysTick, from breakpoint context, once the firmware wants it.

        THE RATE MATTERS AS MUCH AS THE MECHANISM. Too fast and emulated time
        outruns the firmware's own initialisation: lwIP's periodic timer runs
        `if (now - last >= 100) tcp_tmr()`, and at one tick per 24 ROM calls
        that fired while the TCP structures were still being built, so the timer
        walked a list whose head had not been set yet and dereferenced
        0xFFFFFFFF. It reads exactly like memory corruption, and it is not --
        it is a race the real device cannot have, because on silicon a hundred
        milliseconds is a hundred milliseconds however fast the boot is going.
        One tick per 4000 ROM calls keeps the ordering the firmware expects.

        THE DEVICE PACES ITS OWN CLOCK, and the two obvious alternatives both
        fail. There is no idle primitive and no main-loop seam to hang a pump
        off; and the backend's instruction-count pacer (HAL_DET_TICK) starts at
        instruction zero, long before the firmware sets SYST_CSR.ENABLE, so its
        first tick lands in a SysTick handler that immediately pokes the
        Ethernet interrupt through STIR -- the ISR runs before the MAC exists
        and the boot dies before one console character. Gating that by skipping
        the handler is worse still: the skip returns through EXC_RETURN, which
        ends the emulation chunk, which makes the pacer fire again -- a tick
        storm with no guest progress at all (337,442 deliveries and still in
        the startup zero-init loop).

        Driving it from here fixes both. These handlers sit on the ROM calls the
        firmware makes constantly -- including inside its own timeout loops,
        which is exactly where a clock has to advance -- and a breakpoint is a
        safe place to inject.
        """
        self._tick_calls += 1
        self._sample_state(qemu)
        if self._tick_calls % 512 == 0:
            get_console().flush_idle()

        # THE NETWORK IS NOT GATED ON THE CLOCK. Moving frames between the DMA
        # rings and the peer has nothing to do with SysTick being enabled or an
        # interrupt being outstanding, and putting it behind those two checks
        # throttled it to almost nothing: one frame delivered in a hundred
        # seconds, so the peer's ARP request went in and its SYN never did.
        apb = get_apb()
        if apb is not None and self._tick_calls % self._net_every == 0:
            apb.emac.poll()
            from ..peripheral_models.net_peer import get_peer
            get_peer().on_poll()
            # The relay has to run on the device's own pump too: hanging it off
            # a boot-time ROM call means the device's answer is produced and
            # then never handed to the host.
            from .modbus_bridge import get_bridge
            bridge = get_bridge()
            if bridge is not None:
                bridge.pump()

        # ONE RATE, START TO FINISH. Speeding the clock up once the stack was
        # live looked obviously right -- the boot-ordering constraint above is
        # about initialisation, and a slow clock starves the servers afterwards
        # -- and it was wrong: at one tick per 400 ROM calls the device stopped
        # answering the peer's SYN altogether and never left SYN_SENT. The
        # firmware keeps deriving timing from this clock long after "IP ready.",
        # so the rate is a property of the whole run, not of the boot.
        if self._tick_calls % self._tick_every:
            return
        from ..peripheral_models.cortexm_ppb import SYST_CSR, get_ppb
        ppb = get_ppb()
        if ppb is None or not ppb.words.get(SYST_CSR, 0) & 1:
            return                              # SysTick is not enabled yet
        if getattr(qemu, "_pending_irqs", None):
            return                              # one delivery outstanding
        if apb is not None:
            ppb = get_ppb()
            if apb.emac.rx_irq_pending and not (ppb and ppb.in_handler_mode()):
                # A frame just landed: the MAC's own interrupt outranks the
                # clock this pass. One exception per delivery (playbook §2.98).
                apb.emac.rx_irq_pending = False
                try:
                    qemu.inject_irq(EMAC_IRQ)
                except Exception:                # noqa: BLE001
                    pass
                return
        try:
            qemu.inject_irq(-1)                 # vtor + (16 + -1)*4 = SysTick
        except Exception:                        # noqa: BLE001
            return
        self.ticks += 1

    def _wire(self, qemu: Any) -> None:
        """Hand the emulator to the PPB model, once, from breakpoint context.

        The PPB needs it to queue the software-triggered Ethernet interrupt, and
        a peripheral model has no moment of its own at which the backend exists.
        The ROM entry points run early and often, so this is the natural place.
        """
        if self._wired:
            return
        from .fault_probe import install_watchpoint
        install_watchpoint(qemu)
        ppb = get_ppb()
        if ppb is not None:
            ppb.set_backend(qemu)
            self._wired = True
        apb = get_apb()
        if apb is not None:
            apb.set_backend(qemu)

    @bp_handler(["main_idle_park"])
    def main_idle_park(self, qemu: Any,
                       bp_addr: int) -> Tuple[bool, Optional[int]]:
        """Keep the clock running while the firmware sits in its idle loop.

        THE PARK IS THE DEVICE'S NORMAL STATE, not a hang. `main()` ends with
        `bl <set status LED>; b .` -- and that LED call is a tail call into ROM
        GPIOPinWrite, so it returns straight into the `b .`. From there the
        whole device runs on interrupts: SysTick drives lwIP's timers and the
        EMAC ISR drives the network.

        Which is exactly where a clock paced off ROM calls dies. Parked, the
        firmware makes no ROM calls at all, so SysTick never advances, no
        interrupt is ever delivered, and a device that is actually alive looks
        completely frozen -- it reaches `IP ready.`, binds nothing, and resets
        every connection. Ticking here is what makes the idle state idle rather
        than dead.

        Passive: the `b .` still executes, as it does on silicon.
        """
        self._tick(qemu)
        return False, None

    @bp_handler(["hal_delay_yield"])
    def delay_yield(self, qemu: Any,
                    bp_addr: int) -> Tuple[bool, Optional[int]]:
        """Advance the clock from inside the firmware's own delay loop.

        SysTick here is paced off ROM calls (see `_tick`), which works only
        while the firmware is making them. Its millisecond delay
        (`while (ticks - start < n) yield();` at 0x0001E898) makes none at all,
        so the counter it is waiting on never moves and the delay never
        expires. This is the same class of problem as the boot-ordering one
        above and has the same shape of answer: tick where the firmware is
        actually waiting, rather than speeding up the clock everywhere.

        SCOPED TO THE PROVISIONED PATH, because it is not free. Ticking here
        changes the clock's phase everywhere, and on the unprovisioned build --
        which never reaches this delay -- it made the Modbus round-trip flaky:
        one run passed all 18 checks and the next failed three. The delay loop
        only stalls once the module believes it has I/O, so that is where the
        extra ticking belongs.

        Passive -- the yield still runs.
        """
        from ..peripheral_models import device_profile
        if not device_profile.provisioned():
            return False, None
        self._tick(qemu)
        return False, None

    # -- the console -------------------------------------------------------
    @bp_handler(["rom_UARTCharPut"])
    def uart_char_put(self, qemu: Any,
                      bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`UARTCharPut(base, ch)` -- the firmware's only way to say anything.

        Reached as a tail call (`bx r2`), so returning here returns to the
        caller's caller, which is what the real function would do.
        """
        try:
            ch = qemu.read_register("r1") & 0xFF
        except Exception:                        # noqa: BLE001
            return True, 0
        self.chars += 1
        get_console().putc(ch)
        return True, 0

    @bp_handler(["rom_UARTBusy"])
    def uart_busy(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`UARTBusy(base)` -- must return FALSE, and this one is load-bearing.

        The transmit path is `do {} while (UARTBusy(base));`. A `bx lr` stub
        leaves r0 holding the *argument* -- the UART base address, which is very
        much non-zero -- so the loop never exits: 2,557,558 passes of four
        instructions and not one character out. Nothing else on the device is
        wrong at that point; it simply never gets to speak.
        """
        self.busy_polls += 1
        self._wire(qemu)
        self._tick(qemu)
        return True, 0

    @bp_handler(["rom_UARTConfigSetExpClk"])
    def uart_config(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`UARTConfigSetExpClk(base, clk, baud, config)` -- observed, not acted on.

        The rehost has no baud rate, but the arguments are worth reporting once:
        they are how this console was identified (115200 8N1 on UART0).
        """
        if not self._logged_uart:
            self._logged_uart = True
            try:
                base = qemu.read_register("r0")
                clk = qemu.read_register("r1")
                baud = qemu.read_register("r2")
                cfg = qemu.read_register("r3")
                log.info("ROM UARTConfigSetExpClk(base=0x%08x, clk=%d, "
                         "baud=%d, config=0x%02x) -- the debug console",
                         base, clk, baud, cfg)
            except Exception:                    # noqa: BLE001
                pass
        return True, 0

    # -- the serial NOR flash on SSI3 --------------------------------------
    @bp_handler(["rom_SSIDataPut"])
    def ssi_data_put(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`SSIDataPut(base, data)` -- clock a byte to the flash.

        SPI is full-duplex, so the byte that comes back belongs to this same
        transfer; it is queued for the `SSIDataGet` the firmware issues next.
        """
        try:
            data = qemu.read_register("r1") & 0xFF
        except Exception:                        # noqa: BLE001
            return True, 0
        self.spi_bytes += 1
        self._tick(qemu)
        self._rx.append(get_flash().xfer(data))
        if len(self._rx) > 64:                   # the driver never gets behind
            del self._rx[0]
        return True, 0

    @bp_handler(["rom_SSIDataGet"])
    def ssi_data_get(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`SSIDataGet(base, *pdata)` -- hand back what the flash clocked in."""
        try:
            ptr = qemu.read_register("r1")
            value = self._rx.pop(0) if self._rx else 0xFF
            qemu.write_memory(ptr, 4, value)
        except Exception:                        # noqa: BLE001
            pass
        return True, 0

    @bp_handler(["rom_GPIOPinWrite"])
    def gpio_pin_write(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`GPIOPinWrite(port, pins, value)`.

        The only pin this device has to understand is the serial flash's chip
        select: SPI NOR framing is entirely defined by CS, with no length field
        anywhere, so without it every command runs into the next one.
        """
        try:
            port = qemu.read_register("r0")
            pins = qemu.read_register("r1")
            value = qemu.read_register("r2")
        except Exception:                        # noqa: BLE001
            return True, 0
        if port == SFLASH_CS_PORT and pins & SFLASH_CS_PIN:
            get_flash().select(not value & SFLASH_CS_PIN)   # active low
        return True, 0

    # -- the uDMA path that really reads the serial flash ------------------
    @bp_handler(["rom_uDMAChannelTransferSet"])
    def udma_transfer_set(self, qemu: Any,
                          bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`uDMAChannelTransferSet(chIdx, mode, src, dst, size)`.

        The fifth argument is on the stack (AAPCS), at [sp] on entry -- which is
        why this is worth intercepting rather than reading the uDMA control
        table out of RAM: the call hands over everything the transfer needs.
        """
        try:
            ch = qemu.read_register("r0")
            mode = qemu.read_register("r1")
            src = qemu.read_register("r2")
            dst = qemu.read_register("r3")
            size = qemu.read_memory(qemu.read_register("sp"), 4, 1)
        except Exception:                        # noqa: BLE001
            return True, 0
        get_udma().transfer_set(ch, mode, src, dst, size)
        return True, 0

    @bp_handler(["rom_uDMAChannelEnable"])
    def udma_channel_enable(self, qemu: Any,
                            bp_addr: int) -> Tuple[bool, Optional[int]]:
        try:
            get_udma().enable(qemu.read_register("r0"))
        except Exception:                        # noqa: BLE001
            pass
        return True, 0

    @bp_handler(["rom_uDMAIntClear"])
    def udma_int_clear(self, qemu: Any,
                       bp_addr: int) -> Tuple[bool, Optional[int]]:
        try:
            get_udma().int_clear(qemu.read_register("r0"))
        except Exception:                        # noqa: BLE001
            pass
        return True, 0

    @bp_handler(["rom_uDMAIntStatus"])
    def udma_int_status(self, qemu: Any,
                        bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`uDMAIntStatus()` -- run the armed transfer, then report it done.

        Performing the transfer here rather than at `uDMAChannelEnable` keeps it
        on a breakpoint the firmware reaches with the buffers already set up,
        and means a poll always observes a consistent state: either the channel
        has not been armed, or its data is in memory before the bit says so.
        """
        self._wire(qemu)
        self._tick(qemu)
        udma = get_udma()
        udma.run(qemu)
        return True, udma.complete

    # -- the Ethernet MAC --------------------------------------------------
    @bp_handler(["rom_EMACPHYRead"])
    def emac_phy_read(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`EMACPHYRead(base, phyAddr, regAddr)` -- the link-status gate.

        The firmware masks register 1's result with 0x20 (auto-negotiation
        complete) before it will use the network. A zero here leaves the stack
        initialised, printing "IP ready.", and permanently silent.
        """
        self._wire(qemu)
        try:
            reg = qemu.read_register("r2") & 0x1F
        except Exception:                        # noqa: BLE001
            return True, 0
        apb = get_apb()
        if apb is None:
            return True, 0
        return True, apb.emac.phy_read(reg)

    @bp_handler(["rom_EMACIntStatus"])
    def emac_int_status(self, qemu: Any,
                        bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`EMACIntStatus(base, bMasked)` -- why the MAC interrupted.

        This is the first thing the Ethernet ISR does, and everything it goes on
        to do is gated on the answer. A stub returning zero gives a handler that
        runs on every interrupt, concludes the MAC has nothing to say, and
        returns -- so frames sit in the receive ring, delivered and never
        collected, and the device looks like it is ignoring the network.
        """
        apb = get_apb()
        return True, apb.emac.int_status if apb is not None else 0

    @bp_handler(["rom_EMACIntClear"])
    def emac_int_clear(self, qemu: Any,
                       bp_addr: int) -> Tuple[bool, Optional[int]]:
        apb = get_apb()
        if apb is not None:
            try:
                apb.emac.int_status &= ~qemu.read_register("r1") & 0xFFFFFFFF
            except Exception:                    # noqa: BLE001
                pass
        return True, 0

    @bp_handler(["rom_EMACAddrGet"])
    def emac_addr_get(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`EMACAddrGet(base, index, pui8MACAddr)` -- the driver asks the MAC
        for its own address and hands the answer to lwIP. A stub that writes
        nothing leaves lwIP with whatever was in that struct field."""
        apb = get_apb()
        if apb is None:
            return True, 0
        try:
            ptr = qemu.read_register("r2")
            qemu.write_memory(ptr, 1, apb.emac.mac, len(apb.emac.mac))
        except Exception:                        # noqa: BLE001
            pass
        return True, 0

    @bp_handler(["rom_EMACPHYWrite"])
    def emac_phy_write(self, qemu: Any,
                       bp_addr: int) -> Tuple[bool, Optional[int]]:
        try:
            reg = qemu.read_register("r2") & 0x1F
            val = qemu.read_register("r3")
        except Exception:                        # noqa: BLE001
            return True, 0
        apb = get_apb()
        if apb is not None:
            apb.emac.phy_write(reg, val)
        return True, 0

    @bp_handler(["rom_EMACDescriptorListSetA", "rom_EMACDescriptorListSetB"])
    def emac_descriptor_list_set(self, qemu: Any,
                                 bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`EMAC{Tx,Rx}DMADescriptorListSet(base, pDescriptor)`.

        Both entries are handled together: which of the two is transmit is not
        stated anywhere in a stripped image, so the pointers are recorded and
        the rings inspected rather than guessed at.
        """
        self._wire(qemu)
        try:
            ptr = qemu.read_register("r1")
        except Exception:                        # noqa: BLE001
            return True, 0
        apb = get_apb()
        if apb is not None:
            apb.emac.register_list(ptr)
        return True, 0

    # -- configuration calls that are correctly no-ops ---------------------
    # Named so the trace says "this was deliberate", not "this was missed".
    @bp_handler(["rom_UARTEnable"])
    def uart_enable(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        return True, 0

    @bp_handler(["rom_GPIOPinConfigure"])
    def gpio_pin_configure(self, qemu: Any,
                           bp_addr: int) -> Tuple[bool, Optional[int]]:
        return True, 0

    @bp_handler(["rom_GPIOPinTypeUART"])
    def gpio_pin_type_uart(self, qemu: Any,
                           bp_addr: int) -> Tuple[bool, Optional[int]]:
        return True, 0

    @bp_handler(["rom_SysCtlPeripheralPresent"])
    def sysctl_peripheral_present(self, qemu: Any,
                                  bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`SysCtlPeripheralPresent(periph)` -- must say YES, and it is fatal.

        lwIP's bring-up does::

            1d51a:  blx  r1              ; SysCtlPeripheralPresent(EMAC0)
            1d51c:  cmp  r0, #0
            1d51e:  beq  0x1d5b2         ; -> `b .`, forever

        A `movs r0,#0` stub therefore tells the firmware its own Ethernet MAC is
        not fitted, and it stops -- 45.5 million samples at a two-byte infinite
        loop that nothing in the image branches to, because the branch is a
        `bl` into what looks like the middle of a function. This is the whole
        network stack hanging on a capability question.

        Answering "present" for everything is right for this device: the model
        exists precisely for the peripherals the firmware asks about.
        """
        self._present_checks += 1
        return True, 1

    @bp_handler(["rom_SysCtlPeripheralReady"])
    def sysctl_peripheral_ready(self, qemu: Any,
                                bp_addr: int) -> Tuple[bool, Optional[int]]:
        """`SysCtlPeripheralReady(periph)` -- spun on until true.

        Same shape as Present and the same consequence: a peripheral this rehost
        models is ready the instant it is asked about, because there is no clock
        to come up.
        """
        self._tick(qemu)
        return True, 1

    @bp_handler(["rom_SysCtlPeripheralReset"])
    def sysctl_peripheral_reset(self, qemu: Any,
                                bp_addr: int) -> Tuple[bool, Optional[int]]:
        return True, 0

    @bp_handler(["rom_SysCtlPeripheralEnable"])
    def sysctl_peripheral_enable(self, qemu: Any,
                                 bp_addr: int) -> Tuple[bool, Optional[int]]:
        self.periph_enables += 1
        self._wire(qemu)
        return True, 0
