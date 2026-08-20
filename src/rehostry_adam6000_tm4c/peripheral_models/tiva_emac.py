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

AND RECYCLING IS NOT OPTIONAL. Handing the descriptor back is only half of what
the DMA does; it also raises transmit-complete, and that bit is the *only* thing
that runs this driver's reclaim. Without it the ring's pbuf pointers are never
cleared and `tivaif_transmit` refuses every frame after one lap -- the device
answers the first request after boot and then goes deaf. Both the reclaim
(STATIC_TXBUF below) and the ring length (`_ring_len`) were wrong here, and the
symptom of each was the same silence.
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

# THE RECLAIM GATE. `HAL_ADAM_STATIC_TXBUF=1` withholds transmit-complete, which
# is the FALSIFICATION KNOB for the leak this model used to have: the driver's
# only reclaim path is gated on this bit, so without it nothing is ever freed
# and the device goes deaf. It is off by default -- the model reports
# transmit-complete, as the silicon does.
#
# THE ASSUMPTION THAT WAS WRONG. This model previously left the bit unasserted
# and said so in a comment: "transmit buffers are not reclaimed, which for a
# short session costs memory and nothing else". That is false, and the firmware
# says why. `tivaif_transmit` at 0x0001CC06 refuses to send at all when the
# descriptor it is about to write still carries a pbuf:
#
#     1cc0e:  ldr   r1, [r0]          ; pTxDescList->pDescriptors
#     1cc10:  ldr   r0, [r0, #0xc]    ; ->ui32Write
#     1cc12:  mul   r0, r8, r0        ; * 0x24 (36 bytes/descriptor)
#     1cc1a:  ldr   r0, [sb, #0x20]   ; pDescriptors[write].pBuf
#     1cc1e:  cmp   r0, #0
#     1cc22:  beq   0x1cc4c           ; free -> go on
#     1cc24:  bl    pbuf_free         ; NOT free -> drop the frame, return -1
#
# and it also sizes the free run from ui32Read, which only the reclaim advances:
#
#     1cc52:  ldr   r2, [r1, #8]      ; ui32Read
#     1cc54:  ldr   r1, [r1, #0xc]    ; ui32Write
#     1cc5e:  rsb   r1, r1, #0x18     ; 24 - write   (NUM_TX_DESCRIPTORS = 24)
#
# `pBuf` is cleared, and `ui32Read` advanced, in exactly one place --
# `tivaif_process_transmit` at 0x0001CD6A -- and `tivaif_interrupt` at
# 0x0001D1B2 reaches it only when bit 0 of the DMA status word is set:
#
#     1d1b2:  lsls  r0, r5, #0x1f     ; bit 0 == EMAC_INT_TRANSMIT
#     1d1b4:  bpl   0x1d1c2           ; clear -> skip the reclaim entirely
#     1d1bc:  mov   r0, r6            ; pIF
#     1d1be:  bl    0x1cd6a           ; tivaif_process_transmit
#
# So withholding the bit does not cost memory: it costs the device its
# transmitter, one ring-lap after boot.
STATIC_TXBUF = os.environ.get("HAL_ADAM_STATIC_TXBUF") == "1"

# THE SECOND KNOB, for the second defect. `HAL_ADAM_EMAC_NO_CURSOR=1` restores
# the ring walk this model used to do -- scan from index 0, use the first slot
# the DMA owns -- which deadlocks against the driver's own read index (see
# TivaEmac._walk). A third is already available as `HAL_ADAM_EMAC_RING_LEN=16`,
# which pins the ring scan back to the fixed 16 the model shipped with.
# Each one, alone, ends the conversation; that is what makes each fix testable.
NO_CURSOR = os.environ.get("HAL_ADAM_EMAC_NO_CURSOR") == "1"

# Descriptor word 0, bit 31: 1 = the DMA owns it, 0 = the CPU owns it.
DES0_OWN = 1 << 31
# Receive status: frame length in bits 16..29, plus "first" and "last" flags.
RDES0_FL_SHIFT = 16
RDES0_FS = 1 << 9
RDES0_LS = 1 << 8
# RDES1 bit 14, "second address chained". The driver stamps it into word 1 of
# every receive descriptor it arms, and transmit descriptors never carry it --
# so it is what tells the two rings apart, per descriptor.
RDES1_RCH = 1 << 14
# Transmit control: first/last segment, and the interrupt-on-completion flag.
TDES0_LS = 1 << 29
TDES0_FS = 1 << 28
# Buffer sizes live in word 1, 11 bits each.
DES1_SIZE_MASK = 0x1FFF

MAX_FRAME = 1536
# An upper bound on how far the chain-walk below will follow a ring, so a
# malformed link field cannot turn into an unbounded scan.
MAX_RING = 64

# The device's own MAC. 00:D0:C9 is Advantech's real OUI; the low three octets
# come from the firmware's configuration, which on a blank unit reads back as
# 0xFE 0xFF 0xFF -- exactly what it printed on the console as
# "MACID:0.d0.c9.fe.ff.ff".
DEVICE_MAC = bytes.fromhex(os.environ.get("HAL_ADAM_MAC", "00d0c9feffff"))
# Fallback ring length, used only if the descriptor chain cannot be followed
# (see TivaEmac._ring_len). It is NOT the ring size: this device's transmit ring
# is 24 descriptors, and scanning a fixed 16 of them is what silently stranded
# descriptors 16..23 -- the firmware kept handing them to a DMA engine that
# never looked, and the device stopped transmitting after exactly 16 frames.
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
        self.tx_irq_pending = False
        self.tx_reclaims = 0
        self._ring_lens: Dict[int, int] = {}
        # One DMA cursor per ring -- see _walk. The hardware has exactly this.
        self._cursors: Dict[int, int] = {}
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

    def _ring_len(self, base: int) -> int:
        """How many descriptors are in the ring at ``base``.

        MEASURED FROM THE FIRMWARE'S OWN CHAIN, not assumed. Both rings are
        built in *chained* mode -- the transmit descriptors carry
        DES0_TX_CTRL_CHAINED (0x00100000, visible in the ring dump as the `D` of
        0xF0D00000) and the receive ones DES1_RX_CTRL_CHAINED (0x4000, the `4`
        of 0x00004300) -- and a chained descriptor's word 3 is the address of
        the next one, with the last linking back to the first. Following that
        link until it closes gives the exact count:

            EMAC: ring at 0x20020f60 first words: ... 20020f84 ...
            0x20020f84 - 0x20020f60 = 36 = the descriptor stride

        A fixed scan was the alternative and it was wrong. The transmit ring is
        24 descriptors -- the firmware's own wrap constant, `rsb r1, r1, #0x18`
        at 0x0001CC5E and `cmp sb, #0x18` at 0x0001CCDC -- so scanning 16 left
        eight of them permanently owned by a DMA engine that never serviced
        them, and the device fell silent after 16 frames.

        The count is cached only once the chain closes, so a poll that arrives
        while the driver is still building the ring does not freeze a wrong
        answer.
        """
        cached = self._ring_lens.get(base)
        if cached is not None:
            return cached
        override = os.environ.get("HAL_ADAM_EMAC_RING_LEN")
        if override:
            n = int(override, 0)
            self._ring_lens[base] = n
            return n
        addr, n = base, 0
        while n < MAX_RING:
            words = self._read_words(addr, 4)
            if len(words) < 4:
                n = 0
                break
            n += 1
            nxt = words[3]
            if nxt == base:                      # the ring closed
                break
            if nxt != addr + self.stride:        # not a contiguous chain
                n = 0
                break
            addr = nxt
        else:
            n = 0                                # never closed within MAX_RING
        if not n:
            return RING_SCAN                     # not built yet; do not cache
        self._ring_lens[base] = n
        log.info("EMAC: ring at 0x%08x is %d descriptors (followed the "
                 "firmware's own chain, %d bytes apart)", base, n, self.stride)
        return n

    # -- the frame path ----------------------------------------------------
    def poll(self) -> None:
        """Walk the rings: send what the firmware handed us, deliver what is
        queued. Called from breakpoint context, once per clock tick."""
        if self._backend is None or not self.lists:
            return
        self.dump_rings()
        if os.environ.get("HAL_ADAM_EMAC_DEBUG") == "1":
            self._dbg_polls = getattr(self, "_dbg_polls", 0) + 1
            if self._dbg_polls % 400 == 0:
                self._debug_state()
        for base in self.lists:
            self._walk(base)

    def _debug_state(self) -> None:
        """Dump both rings and the model's own cursors (HAL_ADAM_EMAC_DEBUG=1).

        THIS IS THE VIEW THAT FOUND THE DEADLOCK, and it is kept because no
        smaller one would have. Reading the descriptors alone shows owner bits
        drifting and says nothing about why; reading the *driver's* `ui32Read` /
        `ui32Write` beside them is what showed the receive index frozen at 3
        while the model kept consuming descriptors 4, 5, 6 ... -- two engines
        walking the same ring in different places.
        """
        log.error("DBG cursors=%s int_status=0x%x rxq=%d rx_irq=%s tx_irq=%s "
                  "tx=%d rx=%d", self._cursors, self.int_status,
                  len(self.rx_queue), self.rx_irq_pending, self.tx_irq_pending,
                  self.tx_count, self.rx_count)
        for base in self.lists:
            self._debug_ring(base)

    def _debug_ring(self, base: int) -> None:
        """Dump one ring's owner bits and pbuf pointers (HAL_ADAM_EMAC_DEBUG)."""
        n = self._ring_len(base)
        own = []
        pbuf = []
        for i in range(n):
            w = self._read_words(base + i * self.stride, 9)
            if len(w) < 9:
                return
            own.append("1" if w[0] & DES0_OWN else "0")
            pbuf.append("1" if w[8] else "0")
        idx = ""
        st = self._find_list_struct(base)
        if st:
            w = self._read_words(st, 4)
            if len(w) == 4:
                idx = "  list@0x%08x n=%d rd=%d wr=%d" % (st, w[1], w[2], w[3])
        log.error("DBG ring 0x%08x own=%s pbuf=%s%s", base, "".join(own),
                  "".join(pbuf), idx)

    def _find_list_struct(self, base: int) -> int:
        """Locate the driver's tDescriptorList for the ring at ``base``."""
        got = getattr(self, "_list_structs", None)
        if got is None:
            got = self._list_structs = {}
        if base in got:
            return got[base]
        n = self._ring_len(base)
        for a in range(0x20000000, 0x20010000, 4):
            w = self._read_words(a, 2)
            if len(w) == 2 and w[0] == base and w[1] == n:
                got[base] = a
                return a
        got[base] = 0
        return 0

    def _walk(self, base: int) -> None:
        """Advance this ring's DMA cursor over whatever the firmware has handed
        over, in ring order.

        THE CURSOR IS THE POINT, and its absence was a real defect. A Synopsys
        DMA holds a *current descriptor pointer* per ring; it services that one,
        moves to the next, and wraps. It never goes back and picks whichever
        descriptor happens to be free. This model used to scan from index 0
        every poll and use the first available slot, and that quietly
        deadlocked the receive path:

          * the driver reads at its own `ui32Read` and stops the moment that
            descriptor is still DMA-owned -- `ldr r0,[pDescriptors,read*0x24];
            cmp r0,#0; bmi <exit>` at 0x0001CE26;
          * the model delivered three frames into descriptors 0,1,2; the driver
            consumed them, re-armed all three and left `ui32Read` at 3;
          * the next frame went to descriptor 0, because that was the lowest
            slot the DMA "owned" again. The driver looked at descriptor 3, found
            it armed and empty, and stopped -- for good.

        `ui32Read` never moved off 3 again, every later frame landed in a slot
        the driver would not look at until it had gone all the way round, and
        the device fell silent after five exchanges. The receive ring drains one
        descriptor per retransmission and nothing is ever picked up.

        A cursor makes the two agree by construction: the DMA fills in the same
        order the driver reads, and stalls -- as the hardware does -- on the
        first descriptor the CPU still owns.

        WHICH RING IS WHICH IS READ OFF THE DESCRIPTOR, not assumed. The driver
        writes 0x4000 into word 1 of every receive descriptor when it arms one
        (`mov.w r2, #0x4000; str r2,[r0,r1]` at 0x0001CE7C, before it ORs in the
        buffer length at 0x0001CEB0) -- that is RDES1's "second address
        chained". Transmit descriptors carry their chaining flag in word 0
        instead, so word 1 bit 14 separates the two cleanly and per descriptor.
        """
        n = self._ring_len(base)
        if NO_CURSOR:
            return self._walk_no_cursor(base, n)
        cursor = self._cursors.get(base, 0)
        for _ in range(n):
            addr = base + cursor * self.stride
            words = self._read_words(addr, 4)
            if len(words) < 4 or not words[0] & DES0_OWN:
                break                    # the CPU owns it: the DMA suspends
            length = words[1] & DES1_SIZE_MASK
            buf = words[2]
            if not buf:
                break
            if words[1] & RDES1_RCH:
                # NOT BEFORE THE DRIVER HAS SPOKEN. The receive ring is armed
                # early in initialisation, long before the lwIP driver's own
                # state is built -- so a frame delivered too soon is picked up
                # by an interrupt handler that walks a struct chain nobody has
                # filled in yet, and faults on a pointer read. Waiting for the
                # device's first transmission is a sound proxy for "the driver
                # is live", and it is also physically honest: a MAC that has not
                # finished coming up does not have a link to receive on.
                if not (self.rx_queue and self.tx_count):
                    break
                if not self._receive(addr, buf, length):
                    break
            elif length:
                self._transmit(addr, buf, length, words)
            else:
                break
            cursor = (cursor + 1) % n
        self._cursors[base] = cursor

    def _walk_no_cursor(self, base: int, n: int) -> None:
        """The engine this model used to have (``HAL_ADAM_EMAC_NO_CURSOR=1``).

        FALSIFICATION KNOB. Scan from index 0 and use the first slot the DMA
        owns -- no cursor, no ring order. It looks equivalent and is not: it
        deadlocks against the driver's own read index, exactly as described in
        `_walk`. Turn it on and the sustained conversation collapses again,
        which is what makes the cursor above a claim that can be tested rather
        than an assertion.
        """
        for i in range(n):
            addr = base + i * self.stride
            words = self._read_words(addr, 4)
            if len(words) < 4 or not words[0] & DES0_OWN:
                continue
            length = words[1] & DES1_SIZE_MASK
            buf = words[2]
            if not buf:
                continue
            if words[1] & RDES1_RCH:
                if self.rx_queue and self.tx_count:
                    self._receive(addr, buf, length)
            elif length:
                self._transmit(addr, buf, length, words)

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
        if not STATIC_TXBUF:
            # The frame is on the wire, so the DMA raises transmit-complete --
            # which is the only thing that will run the driver's reclaim
            # (`tivaif_process_transmit`, 0x0001CD6A) and free the pbuf and the
            # descriptor slot for the next frame. See STATIC_TXBUF above.
            self.int_status |= EMAC_INT_TRANSMIT
            self.tx_irq_pending = True
            self.tx_reclaims += 1

    def _receive(self, desc: int, buf: int, size: int) -> bool:
        """Land one queued frame in this descriptor. False if it could not be
        placed, which stalls the cursor rather than skipping the slot."""
        frame = self.rx_queue[0]
        # THE LENGTH THE MAC REPORTS INCLUDES THE FCS, and the driver subtracts
        # four before handing the frame to lwIP. Report the payload length and
        # every frame arrives four bytes short -- for a 60-byte ARP request that
        # truncates the target address, so the device receives it, finds nothing
        # addressed to it, and stays silent. The four octets are written out too,
        # because the driver's buffer accounting expects them to be there.
        on_wire = frame + b"\x00" * 4           # placeholder FCS
        if size and len(on_wire) > size:
            return False                         # will not fit this buffer
        if self._backend is None:
            return False
        try:
            self._backend.write_memory(buf, 1, on_wire, len(on_wire))
        except Exception:                        # noqa: BLE001
            return False
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
        return True

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
