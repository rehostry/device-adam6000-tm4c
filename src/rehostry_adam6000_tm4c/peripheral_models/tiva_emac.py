# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""EMAC0 -- the TM4C129x's on-chip Ethernet MAC, and its integrated PHY.

THE SEAM IS THE ROM, NOT THE REGISTERS. This firmware never touches an EMAC
register directly: every access goes through TivaWare's masked-ROM API table
(APITABLE[42]). A trace of the whole boot shows zero MMIO in the 0x400EC000
page. So the model hangs off the ROM entry points in
bp_handlers/tiva_rom_api.py, and this class holds the state they act on.

THE PHY IS THE GATE. The firmware asks the integrated PHY whether the link is
up before it will do anything with the network:

    1ca42:  r2 = 1                  ; PHY register 1 = BMSR
    1ca52:  blx  EMACPHYRead        ; f(base, phy 0, reg 1)
    1ca54:  and  r0, r0, #0x20      ; bit 5 = auto-negotiation complete

Answer zero and the stack initialises, prints "IP ready.", and never sends a
frame -- which is a *quiet* failure, indistinguishable from an idle network.
So BMSR reports a link that is up and negotiated, which is the state of a
device someone has plugged in.

DESCRIPTORS. The MAC moves frames by DMA over rings of descriptors in SRAM,
Synopsys-style: the owner bit (31) in word 0 says whose turn it is. The firmware
hands a descriptor to the DMA by setting it; the DMA clears it when done. This
model does the same thing from the other side, so the firmware's own ring
walking, buffer recycling and interrupt handling are all exercised rather than
bypassed.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from halucinator import hal_log

from .net_peer import get_peer
from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

EMAC_BASE = 0x400EC000
EMAC_IRQ = 40

# --- PHY registers (IEEE 802.3 clause 22) ----------------------------------
PHY_BMCR = 0
PHY_BMSR = 1
PHY_ID1 = 2
PHY_ID2 = 3
PHY_ANAR = 4
PHY_ANLPAR = 5

# BMCR: auto-negotiation enabled and complete, 100 Mb/s, full duplex.
BMCR_VALUE = 0x3100
# BMSR: 100BASE-TX full+half, 10BASE-T full+half, auto-neg complete (bit 5),
# auto-neg able (bit 3), LINK UP (bit 2), extended capability (bit 0).
BMSR_VALUE = 0x782D
# The TM4C129x's integrated PHY identifies itself as a TI part.
PHY_ID1_VALUE = 0x2000
PHY_ID2_VALUE = 0xA221
# Advertised and link-partner ability: 100BASE-TX full duplex, 802.3.
PHY_ANAR_VALUE = 0x01E1
PHY_ANLPAR_VALUE = 0x41E1

# The DMA status bits the ISR reads back, from the Synopsys DMARIS layout that
# TivaWare exposes as EMAC_INT_*. The handler's whole job is gated on these:
# it asks the MAC why it interrupted, and a zero answer means "not me".
EMAC_INT_TRANSMIT = 1 << 0
EMAC_INT_RECEIVE = 1 << 6

# Whether to raise transmit-complete (``HAL_ADAM_TX_COMPLETE=1``). OFF by
# default, and this is a stated limitation rather than an oversight: asserting
# it sends the driver into its pbuf-reclaim walk, which indexes the transmit
# ring from bookkeeping this model does not participate in, and the walk wrote
# through a descriptor slot that was not one -- corrupting its own ring manager
# and faulting on the next iteration. Leaving it unasserted means transmit
# buffers are not reclaimed, which for a short session costs memory and nothing
# else; the receive path, which is what carries the protocol, is unaffected.
REPORT_TX_COMPLETE = os.environ.get("HAL_ADAM_TX_COMPLETE") == "1"

# Descriptor word 0, bit 31: 1 = the DMA owns it, 0 = the CPU owns it.
DES0_OWN = 1 << 31
# Receive status: frame length in bits 16..29, plus "first" and "last" flags.
RDES0_FL_SHIFT = 16
RDES0_FS = 1 << 9
RDES0_LS = 1 << 8
# Transmit control: first/last segment, and the interrupt-on-completion flag.
TDES0_LS = 1 << 29
TDES0_FS = 1 << 28
# Buffer sizes live in word 1, 11 bits each.
DES1_SIZE_MASK = 0x1FFF

MAX_FRAME = 1536

# The device's own MAC. 00:D0:C9 is Advantech's real OUI; the low three octets
# come from the firmware's configuration, which on a blank unit reads back as
# 0xFE 0xFF 0xFF -- exactly what it printed on the console as
# "MACID:0.d0.c9.fe.ff.ff".
DEVICE_MAC = bytes.fromhex(os.environ.get("HAL_ADAM_MAC", "00d0c9feffff"))
# How many descriptors to scan in a ring. TivaWare's lwIP port uses far fewer.
RING_SCAN = 16


# How much of each transmitted frame to log. The default keeps the log
# readable; set HAL_ADAM_TX_HEX=1600 to capture whole frames, which is what
# shows a protocol response sitting in the guest's own transmit buffer --
# register-level evidence rather than the peer's reassembly of it.
TX_LOG_BYTES = int(os.environ.get("HAL_ADAM_TX_HEX", "32"), 0)


def descriptor_stride() -> int:
    """Bytes per descriptor (``HAL_ADAM_EMAC_DESC_STRIDE``).

    **36, not 32.** TivaWare's ``tEMACDMADescriptor`` is eight words with the
    enhanced (IEEE 1588) layout, but its lwIP port wraps each one in a struct
    that also carries the ``pbuf *`` the descriptor belongs to -- so the ring
    pitch is 36 bytes, not 32, and a 32-byte walk reads a pbuf pointer where it
    expects the next descriptor's status word. The value is not guessed: the
    firmware writes the next-descriptor link into word 3, and
    0x20020F84 - 0x20020F60 = 36.
    """
    return int(os.environ.get("HAL_ADAM_EMAC_DESC_STRIDE", "36"), 0)


class TivaEmac(SocCatchAll):
    """The MAC's state: PHY registers, descriptor rings, and the frame queues."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self._backend: Optional[Any] = None
        self.phy: Dict[int, int] = {
            PHY_BMCR: BMCR_VALUE,
            PHY_BMSR: BMSR_VALUE,
            PHY_ID1: PHY_ID1_VALUE,
            PHY_ID2: PHY_ID2_VALUE,
            PHY_ANAR: PHY_ANAR_VALUE,
            PHY_ANLPAR: PHY_ANLPAR_VALUE,
        }
        self.phy_reads = 0
        self.lists: List[int] = []          # descriptor-list pointers, as given
        self.tx_ring: Optional[int] = None
        self.rx_ring: Optional[int] = None
        self.tx_frames: List[bytes] = []
        self.rx_queue: List[bytes] = []
        self.tx_count = 0
        self.rx_count = 0
        self.rx_irq_pending = False
        self.int_status = 0
        self.stride = descriptor_stride()
        self._dumped = False
        # The other machine on the wire. Frames the firmware transmits are
        # handed to it, and whatever it answers is queued for receive.
        self.mac = DEVICE_MAC
        self.peer = get_peer()
        self.peer.set_send(self.deliver)

    def set_backend(self, backend: Any) -> None:
        self._backend = backend

    # -- PHY ---------------------------------------------------------------
    def phy_read(self, reg: int) -> int:
        self.phy_reads += 1
        return self.phy.get(reg, 0)

    def phy_write(self, reg: int, value: int) -> None:
        # BMCR's reset and restart-autoneg bits are self-clearing, and a model
        # that latched them would look permanently mid-reset.
        if reg == PHY_BMCR:
            value &= ~0x8200
        self.phy[reg] = value & 0xFFFF

    # -- descriptor rings --------------------------------------------------
    def register_list(self, pointer: int) -> None:
        """One of the two DMA descriptor lists. Which is which is learned, not
        assumed: the firmware registers them through two different API entries
        whose order is not documented in the image, so both are recorded and the
        rings are dumped once for inspection."""
        if pointer and pointer not in self.lists:
            self.lists.append(pointer)
            log.info("EMAC: descriptor list registered at 0x%08x", pointer)

    def dump_rings(self) -> None:
        if self._dumped or self._backend is None or not self.lists:
            return
        self._dumped = True
        for base in self.lists:
            words = self._read_words(base, 16)
            if words:
                log.info("EMAC: ring at 0x%08x first words: %s", base,
                         " ".join("%08x" % w for w in words))

    def _read_words(self, addr: int, count: int) -> List[int]:
        if self._backend is None:
            return []
        try:
            raw = bytes(self._backend.read_memory(addr, 1, count * 4, raw=True))
        except Exception:                        # noqa: BLE001
            return []
        return [int.from_bytes(raw[i * 4:i * 4 + 4], "little")
                for i in range(count)]

    # -- the frame path ----------------------------------------------------
    def poll(self) -> None:
        """Walk the rings: send what the firmware handed us, deliver what is
        queued. Called from breakpoint context, once per clock tick."""
        if self._backend is None or not self.lists:
            return
        self.dump_rings()
        for base in self.lists:
            self._walk(base)

    def _walk(self, base: int) -> None:
        """Look at one ring and act on whatever the DMA owns.

        A descriptor the firmware has given away (OWN set) with a non-empty
        buffer LENGTH in word 1 is something to transmit; one with a buffer but
        no length is a receive buffer waiting to be filled. That distinction is
        what identifies the two rings, rather than an assumption about which API
        entry registered which.
        """
        for i in range(RING_SCAN):
            addr = base + i * self.stride
            words = self._read_words(addr, 4)
            if len(words) < 4 or not words[0] & DES0_OWN:
                continue
            length = words[1] & DES1_SIZE_MASK
            buf = words[2]
            if not buf:
                continue
            if length and words[0] & (TDES0_FS | TDES0_LS):
                self._transmit(addr, buf, length, words)
            elif self.rx_queue and self.tx_count:
                # NOT BEFORE THE DRIVER HAS SPOKEN. The receive ring is armed
                # early in initialisation, long before the lwIP driver's own
                # state is built -- so a frame delivered too soon is picked up
                # by an interrupt handler that walks a struct chain nobody has
                # filled in yet, and faults on a pointer read. Waiting for the
                # device's first transmission is a sound proxy for "the driver
                # is live", and it is also physically honest: a MAC that has not
                # finished coming up does not have a link to receive on.
                self._receive(addr, buf, length)

    def _transmit(self, desc: int, buf: int, length: int, words) -> None:
        frame = b""
        if self._backend is not None and 0 < length <= MAX_FRAME:
            try:
                frame = bytes(self._backend.read_memory(buf, 1, length,
                                                        raw=True))
            except Exception:                    # noqa: BLE001
                frame = b""
        if frame:
            # THE MAC INSERTS ITS OWN SOURCE ADDRESS. TivaWare's lwIP port
            # leaves those six octets zero and lets the hardware fill them in,
            # so a model that transmits the buffer verbatim puts frames on the
            # wire from 00:00:00:00:00:00 -- which no peer will ever ARP-resolve
            # or reply to, and which looks like a device that talks and is
            # ignored.
            if frame[6:12] == b"\x00" * 6:
                frame = frame[:6] + self.mac + frame[12:]
            self.tx_frames.append(frame)
            if len(self.tx_frames) > 32:
                del self.tx_frames[0]
            self.tx_count += 1
            if self.tx_count <= 24:
                log.info("EMAC TX #%d: %d bytes %s", self.tx_count, len(frame),
                         frame[:TX_LOG_BYTES].hex())
            self.peer.on_device_frame(frame)
        # Give the descriptor back to the CPU, which is what the DMA does when
        # the frame is on the wire, and raise the transmit-complete status the
        # driver reads in its ISR.
        self._write_word(desc, words[0] & ~DES0_OWN)
        if REPORT_TX_COMPLETE:
            self.int_status |= EMAC_INT_TRANSMIT

    def _receive(self, desc: int, buf: int, size: int) -> None:
        frame = self.rx_queue[0]
        # THE LENGTH THE MAC REPORTS INCLUDES THE FCS, and the driver subtracts
        # four before handing the frame to lwIP. Report the payload length and
        # every frame arrives four bytes short -- for a 60-byte ARP request that
        # truncates the target address, so the device receives it, finds nothing
        # addressed to it, and stays silent. The four octets are written out too,
        # because the driver's buffer accounting expects them to be there.
        on_wire = frame + b"\x00" * 4           # placeholder FCS
        if size and len(on_wire) > size:
            return                               # will not fit this buffer
        if self._backend is None:
            return
        try:
            self._backend.write_memory(buf, 1, on_wire, len(on_wire))
        except Exception:                        # noqa: BLE001
            return
        self.rx_queue.pop(0)
        self.rx_count += 1
        # A real MAC raises its interrupt when a frame lands. The firmware also
        # pokes IRQ 40 from SysTick through STIR, so it would eventually notice
        # either way -- but "eventually" is a tick, and a receive that has to
        # wait for the clock turns every request into a round-trip of added
        # latency for no reason.
        self.rx_irq_pending = True
        self.int_status |= EMAC_INT_RECEIVE
        status = (len(on_wire) << RDES0_FL_SHIFT) | RDES0_FS | RDES0_LS
        self._write_word(desc, status)           # OWN cleared: the CPU's again
        if self.rx_count <= 24:
            log.info("EMAC RX #%d: %d bytes into 0x%08x", self.rx_count,
                     len(frame), buf)

    def deliver(self, frame: bytes) -> None:
        """Queue an Ethernet frame for the firmware to receive."""
        self.rx_queue.append(bytes(frame))

    def _write_word(self, addr: int, value: int) -> None:
        if self._backend is None:
            return
        try:
            self._backend.write_memory(addr, 4, value & 0xFFFFFFFF)
        except Exception:                        # noqa: BLE001
            pass
