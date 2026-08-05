# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The serial NOR flash on SSI3 -- where this device keeps its web content.

The ADAM-6000 has a second, external flash beside the microcontroller's own.
The firmware's debug strings name what lives there:
``[SIFlashRead_s] html=%X``, ``JS=%X``, ``JAR=%X``,
``SFLASH_PROG_START_ADDR=%X`` -- the web UI, and the bootloader's
application/backup marks.

HOW THE FIRMWARE TALKS TO IT. Not through registers: it drives SSI3
(0x4000B000) with chip-select on GPIO Q pin 1, through TivaWare's ROM
(``SSIDataPut`` / ``SSIDataGet`` / ``GPIOPinWrite``), so this model hangs off the
ROM API handlers rather than off an MMIO offset. See
bp_handlers/tiva_rom_api.py.

WHAT IS MODELLED. A standard SPI NOR command set -- JEDEC id, status, read,
write-enable, page program, erase -- over a backing store that starts **erased**
(all 0xFF), because that is the honest state of a part whose contents we do not
have. The firmware finds no web content and no application mark, and behaves
the way it would in front of a blank flash. Anything else would be inventing
vendor data and presenting it as the device's.

The store is writable and persists for the life of the run, so the firmware's
own erase/program path is exercised rather than stubbed.
"""
from __future__ import annotations

import os
from typing import List, Optional

from halucinator import hal_log

log = hal_log.getHalLogger()

# SPI NOR commands, from the JEDEC-standard set every part in this class shares.
CMD_WRITE_STATUS = 0x01
CMD_PAGE_PROGRAM = 0x02
CMD_READ = 0x03
CMD_WRITE_DISABLE = 0x04
CMD_READ_STATUS1 = 0x05
CMD_WRITE_ENABLE = 0x06
CMD_FAST_READ = 0x0B
CMD_SECTOR_ERASE = 0x20
CMD_READ_STATUS2 = 0x35
CMD_BLOCK_ERASE_32K = 0x52
CMD_CHIP_ERASE = 0x60
CMD_READ_JEDEC = 0x9F
CMD_RELEASE_POWERDOWN = 0xAB
CMD_READ_ID = 0x90
CMD_BLOCK_ERASE_64K = 0xD8
CMD_CHIP_ERASE_ALT = 0xC7

# THE SIZE IS DERIVED FROM THE FIRMWARE'S OWN READ ADDRESSES, not guessed. The
# boot reads a directory at 0x7FF000 and a signature at 0x490000; both are past
# the end of a 4 MB part, and a 4 MB model silently wraps them into the wrong
# sectors. The smallest part consistent with what the firmware addresses is
# 8 MB, so: capacity byte 0x17 (W25Q64) rather than 0x16 (W25Q32). The
# manufacturer and type bytes are inherited assumptions -- this firmware never
# reads the JEDEC id (0x9F is never issued; the boot uses the legacy 0x90), so
# nothing observable depends on them.
JEDEC_ID = (0xEF, 0x40, 0x17)

# THE LEGACY 0x90 COMMAND RETURNS A DIFFERENT FIELD, and conflating the two
# breaks the boot. 0x9F reports manufacturer/type/**capacity**; 0x90 reports
# manufacturer/**device id**, and for this family they differ by one:
# W25Q64 is capacity 0x17 but device id 0x16. This model used to answer 0x90
# with the capacity byte, which happened to work only while the capacity was
# also set (wrongly) to a 4 MB part's.
#
# The firmware settles it. It issues 0x90 (never 0x9F) and refuses to come up
# unless the device id is 0x16 -- `Boot_ SFinit()  fail !` otherwise. Device id
# 0x16 is a W25Q64, which is 8 MB, which is exactly the size its own read
# addresses (0x7FF000, 0x490000) already implied. Two independent pieces of
# evidence for the same part.
DEVICE_ID = 0x16
FLASH_SIZE = 8 * 1024 * 1024

# Where the device profile lives, recovered from GetDevInfo at 0x0002AC3C:
#
#   r0 = 0x50000; r1 = 4; bl spi_read      -- a 32-bit length at 0x50000
#   cmp r0, #0x3FFD; bcc ok                -- it must be < 16381 or the profile
#                                             is rejected ("GetDevInfo() Err:
#                                             ulLen=-1" is blank flash's
#                                             0xFFFFFFFF printed signed)
#   r0 = 0x50004; r1 = len; bl spi_read    -- then the record itself
#   bl 0x45D74                             -- which parses it as XML
#
PROFILE_LEN_ADDR = 0x50000
PROFILE_ADDR = 0x50004
PROFILE_MAX_LEN = 0x3FFD
SECTOR_SIZE = 4096
PAGE_SIZE = 256

# How many read commands to log (0 = none). The firmware's read map is how the
# off-chip layout was recovered; see _addr_complete.
LOG_READS = int(os.environ.get("HAL_ADAM_SFLASH_LOG", "0"), 0)
LOG_CMDS = int(os.environ.get("HAL_ADAM_SFLASH_CMDLOG", "0"), 0)

STATUS_BUSY = 1 << 0
STATUS_WEL = 1 << 1

# Commands that take a 24-bit address before their data phase.
ADDRESSED = {CMD_READ, CMD_FAST_READ, CMD_PAGE_PROGRAM, CMD_SECTOR_ERASE,
             CMD_BLOCK_ERASE_32K, CMD_BLOCK_ERASE_64K}


class SpiNorFlash:
    """One SPI NOR device, driven a byte at a time."""

    def __init__(self, size: int = FLASH_SIZE, fill: int = 0xFF) -> None:
        self.size = size
        # 0xFF is erased NOR, which is the honest state of a part whose contents
        # we do not have. The fill is a knob only so a run can *prove* whether a
        # value the firmware ends up using came from here or from somewhere else
        # -- change it and see whether the bad pointer changes with it.
        self.data = bytearray(bytes([fill]) * size)
        self.selected = False
        self.cmd: Optional[int] = None
        self.phase = 0                 # bytes seen since the command
        self.addr = 0
        self.wel = False
        self.reads = 0
        self.programs = 0
        self.erases = 0
        self.commands: List[int] = []
        self.read_cmds = 0
        self.cmd_count = 0
        log.info("SPI-NOR: %d MB, erased (0xFF) -- the vendor's web content is "
                 "not shipped with this device", size // (1024 * 1024))

    # -- chip select -------------------------------------------------------
    def select(self, active: bool) -> None:
        """CS asserted (active low on the wire; `active` is the logical sense).

        Deasserting ends the command, which is what makes a NOR flash's protocol
        self-framing -- there is no length field anywhere.
        """
        if active and not self.selected:
            self.cmd = None
            self.phase = 0
            self.addr = 0
        self.selected = active

    # -- the shift register ------------------------------------------------
    def xfer(self, out: int) -> int:
        """Clock one byte out of the host; return the byte clocked back in."""
        out &= 0xFF
        if not self.selected:
            return 0xFF
        if self.cmd is None:
            self.cmd = out
            self.phase = 0
            self.commands.append(out)
            if len(self.commands) > 64:
                del self.commands[0]
            if LOG_CMDS:
                self.cmd_count += 1
                if self.cmd_count <= LOG_CMDS:
                    log.info("SPI-NOR cmd #%d 0x%02x", self.cmd_count, out)
            return self._on_command(out)
        self.phase += 1
        return self._on_data(out)

    def _on_command(self, cmd: int) -> int:
        if cmd == CMD_WRITE_ENABLE:
            self.wel = True
        elif cmd == CMD_WRITE_DISABLE:
            self.wel = False
        elif cmd in (CMD_CHIP_ERASE, CMD_CHIP_ERASE_ALT) and self.wel:
            self.data[:] = b"\xff" * self.size
            self.erases += 1
            self.wel = False
        return 0xFF

    def _on_data(self, out: int) -> int:
        cmd = self.cmd
        if cmd == CMD_READ_STATUS1:
            # Never busy: an erase or program has already completed by the time
            # the firmware asks. Leaving BUSY set would spin its wait loop.
            return (STATUS_WEL if self.wel else 0)
        if cmd == CMD_READ_STATUS2:
            return 0
        if cmd == CMD_READ_JEDEC:
            return JEDEC_ID[(self.phase - 1) % 3]
        if cmd in (CMD_READ_ID, CMD_RELEASE_POWERDOWN):
            # Legacy id: three address bytes, then manufacturer and device id
            # repeating. NOT the capacity byte -- see DEVICE_ID above.
            if self.phase <= 3:
                return 0xFF
            return JEDEC_ID[0] if (self.phase - 4) % 2 == 0 else DEVICE_ID

        if cmd in ADDRESSED:
            if self.phase <= 3:                    # 24-bit address
                self.addr = ((self.addr << 8) | out) & 0xFFFFFF
                if self.phase == 3:
                    self._addr_complete()
                return 0xFF
            if cmd == CMD_FAST_READ and self.phase == 4:
                return 0xFF                        # the dummy byte
            if cmd in (CMD_READ, CMD_FAST_READ):
                val = self.data[self.addr % self.size]
                self.addr += 1
                self.reads += 1
                return val
            if cmd == CMD_PAGE_PROGRAM and self.wel:
                # NOR programming can only clear bits.
                i = self.addr % self.size
                self.data[i] &= out
                self.programs += 1
                # Programming wraps within a 256-byte page, as the part does.
                page = i & ~(PAGE_SIZE - 1)
                self.addr = page | ((i + 1) & (PAGE_SIZE - 1))
                return 0xFF
        return 0xFF

    def _addr_complete(self) -> None:
        cmd = self.cmd
        # WHAT THE FIRMWARE ASKS THE FLASH FOR is the map of this device's
        # off-chip layout, and the firmware is the only authority on it: the
        # profile, web content and application-image marks all live here at
        # addresses the image does not spell out. One line per read command,
        # capped, is how that layout was recovered.
        if cmd in (CMD_READ, CMD_FAST_READ) and LOG_READS:
            self.read_cmds += 1
            if self.read_cmds <= LOG_READS:
                log.info("SPI-NOR read #%d @0x%06x", self.read_cmds, self.addr)
        if cmd == CMD_SECTOR_ERASE and self.wel:
            base = (self.addr // SECTOR_SIZE) * SECTOR_SIZE
            self.data[base:base + SECTOR_SIZE] = b"\xff" * SECTOR_SIZE
            self.erases += 1
            self.wel = False
        elif cmd in (CMD_BLOCK_ERASE_32K, CMD_BLOCK_ERASE_64K) and self.wel:
            span = 32768 if cmd == CMD_BLOCK_ERASE_32K else 65536
            base = (self.addr // span) * span
            self.data[base:base + span] = b"\xff" * span
            self.erases += 1
            self.wel = False


_FLASH: Optional[SpiNorFlash] = None


def _provision(flash: "SpiNorFlash") -> None:
    """Put a device profile where `GetDevInfo` looks for one.

    See peripheral_models/device_profile.py for what is derived and what is
    chosen; the short version is that the *format and placement* come from the
    firmware's own parser, and the *values* come from Advantech's published
    ADAM-6050 specification.
    """
    from . import device_profile
    if not device_profile.provisioned():
        log.info("SPI-NOR: left erased (HAL_ADAM_SFLASH_BLANK=1) -- the module "
                 "will report no model and no I/O points")
        return
    record = device_profile.profile_xml()
    if len(record) >= PROFILE_MAX_LEN:
        log.error("SPI-NOR: profile is %d bytes; the firmware rejects anything "
                  "at or above %d", len(record), PROFILE_MAX_LEN)
        return
    flash.data[PROFILE_LEN_ADDR:PROFILE_LEN_ADDR + 4] = \
        len(record).to_bytes(4, "little")
    flash.data[PROFILE_ADDR:PROFILE_ADDR + len(record)] = record
    log.info("SPI-NOR: provisioned a %d-byte device profile at 0x%06x "
             "(model %d, %d DI + %d DO) -- NOT vendor data; see "
             "device_profile.py", len(record), PROFILE_ADDR,
             device_profile.MODEL, device_profile.DI_CHANNELS,
             device_profile.DO_CHANNELS)


def get_flash() -> SpiNorFlash:
    global _FLASH
    if _FLASH is None:
        _FLASH = SpiNorFlash(
            int(os.environ.get("HAL_ADAM_SFLASH_SIZE", str(FLASH_SIZE)), 0),
            int(os.environ.get("HAL_ADAM_SFLASH_FILL", "0xFF"), 0))
        _provision(_FLASH)
    return _FLASH
