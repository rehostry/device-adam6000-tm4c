# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The uDMA channels that actually move the serial flash's data.

The byte-at-a-time SSI path (`SSIDataPut`/`SSIDataGet`) carries only short
commands. Bulk reads go through the micro-DMA: the firmware arms two channels --
14 for SSI3 receive, 15 for transmit -- points them at a buffer, enables them,
and then waits::

    while (!(uDMAIntStatus() & (1 << 14)) && elapsed(t0) <= 500)

WHY THE TIMEOUT IS NOT A WAY OUT. That 500 ms bound is fed by a counter the
SysTick handler increments, and at this point in the boot SysTick is not enabled
yet -- on real silicon the DMA finishes in microseconds, so the timeout is a
safety net that never fires and the firmware has no reason to have started a
clock. Reporting "not complete" therefore does not fall back to anything; it
hangs. The transfer has to actually happen.

WHAT MAKES THAT EASY HERE. TivaWare's `uDMAChannelTransferSet(chIdx, mode, src,
dst, size)` passes the source, destination and length **as arguments**, so this
model never has to find or parse the uDMA channel-control table in RAM. It
records what each channel was told to do, and when the firmware enables the
channels it performs the transfer against the same SPI flash model the
byte-at-a-time path uses -- so both paths see one device, and a bulk read
returns exactly what a single-byte read of the same address would.

SPI is full duplex, so a transmit and a receive armed together are ONE transfer:
each byte clocked out produces one clocked in. Running them separately would
desynchronise the flash's command state machine.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from halucinator import hal_log

from .spi_flash import get_flash

log = hal_log.getHalLogger()

# TivaWare channel-index encoding: the low five bits are the channel, and
# UDMA_ALT_SELECT (0x20) picks the alternate control structure.
CHANNEL_MASK = 0x1F

# SSI3's uDMA channels on a TM4C129x.
SSI3_RX_CHANNEL = 14
SSI3_TX_CHANNEL = 15

# SRAM, so a descriptor's address can be told from a peripheral register's.
SRAM_BASE = 0x20000000
SRAM_END = 0x20040000


def is_memory(addr: int) -> bool:
    return SRAM_BASE <= addr < SRAM_END


class Transfer:
    __slots__ = ("mode", "src", "dst", "size", "armed")

    def __init__(self, mode: int, src: int, dst: int, size: int) -> None:
        self.mode = mode
        self.src = src
        self.dst = dst
        self.size = size
        self.armed = False


class TivaUdma:
    """Just enough uDMA to carry an SPI transfer."""

    def __init__(self) -> None:
        self.channels: Dict[int, Transfer] = {}
        self.complete = 0                    # the bitmask uDMAIntStatus returns
        self.transfers = 0
        self.bytes_moved = 0

    def transfer_set(self, ch_index: int, mode: int, src: int, dst: int,
                     size: int) -> None:
        self.channels[ch_index & CHANNEL_MASK] = Transfer(mode, src, dst, size)

    def enable(self, channel: int) -> None:
        ch = self.channels.get(channel & CHANNEL_MASK)
        if ch is not None:
            ch.armed = True

    def int_clear(self, mask: int) -> None:
        self.complete &= ~mask & 0xFFFFFFFF

    # -- the transfer ------------------------------------------------------
    def run(self, backend: Any) -> None:
        """Perform any armed SSI transfer and mark its channels complete."""
        rx = self.channels.get(SSI3_RX_CHANNEL)
        tx = self.channels.get(SSI3_TX_CHANNEL)
        rx_armed = rx is not None and rx.armed
        tx_armed = tx is not None and tx.armed
        if not (rx_armed or tx_armed):
            return

        count = 0
        if rx_armed and tx_armed:
            count = min(rx.size, tx.size)
        elif rx_armed:
            count = rx.size
        else:
            count = tx.size
        if count <= 0:
            return

        # What goes out: the transmit buffer if there is one, otherwise the
        # idle level a controller clocks while reading.
        out = b"\xff" * count
        if tx_armed and is_memory(tx.src):
            got = self._read(backend, tx.src, count)
            if got:
                out = got + b"\xff" * (count - len(got))

        flash = get_flash()
        inbound = bytes(flash.xfer(b) for b in out)

        if rx_armed:
            if not is_memory(rx.dst) or not is_memory(rx.dst + count - 1):
                log.error("uDMA: refusing a %d-byte receive into 0x%08x -- "
                          "outside SRAM", count, rx.dst)
            else:
                self._write(backend, rx.dst, inbound)

        self.bytes_moved += count
        self.transfers += 1
        if self.transfers <= 24:
            log.info("uDMA: SSI3 transfer of %d bytes (tx=%s rx=%s) -- first "
                     "inbound bytes %s", count,
                     "0x%08x" % tx.src if tx_armed else "-",
                     "0x%08x" % rx.dst if rx_armed else "-",
                     inbound[:8].hex())

        for channel, entry, armed in ((SSI3_RX_CHANNEL, rx, rx_armed),
                                      (SSI3_TX_CHANNEL, tx, tx_armed)):
            if armed:
                entry.armed = False
                self.complete |= 1 << channel

    @staticmethod
    def _read(backend: Any, addr: int, length: int) -> bytes:
        try:
            return bytes(backend.read_memory(addr, 1, length, raw=True))
        except Exception:                        # noqa: BLE001
            return b""

    @staticmethod
    def _write(backend: Any, addr: int, data: bytes) -> bool:
        try:
            return bool(backend.write_memory(addr, 1, data, len(data)))
        except Exception:                        # noqa: BLE001
            return False


_UDMA: Optional[TivaUdma] = None


def get_udma() -> TivaUdma:
    global _UDMA
    if _UDMA is None:
        _UDMA = TivaUdma()
    return _UDMA
