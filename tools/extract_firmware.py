#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify the vendor firmware image and derive this device's recovered-symbol map.

THIS IS A RAW VENDOR IMAGE. Advantech ships `ADAM6000_DIO_v615B23_UT.bin` as a
flat flash image with no ELF, no symbol table and no container header -- the file
*is* the flash contents from address 0. So there is nothing to unpack; the job
here is entirely verification, and every name this device uses is one **we**
assigned to an address found by analysis, pinned to the bytes of its own first
instruction so a different firmware revision fails loudly instead of intercepting
whatever now lives there.

Writes into src/rehostry_adam6000_tm4c/configs/:

  adam6000_tm4c.bin         the image, copied verbatim
  adam6000_tm4c_addrs.yaml  decimal-addr -> name, for intercept resolution

WHAT IS CHECKED (any failure is fatal):

 1. sha256 of the vendor image exactly as distributed.
 2. The Cortex-M vector table: initial SP, reset vector, and that every unused
    slot points at the one shared default handler.
 3. That exactly one external interrupt is live, and that it is **IRQ 40** --
    which on a TM4C129x is the Ethernet MAC. That single fact is most of the
    SoC identification (see below).
 4. Build landmarks, including the vendor's own build path and the strings this
    device's static prediction is written against.
 5. Every recovered symbol's guard bytes.

THE SoC WAS IDENTIFIED, NOT ASSUMED. There is no part number in the image, but:
  * GPIO ports **A through Q** are addressed (0x40061000..0x40066000 = K/L/M/N/
    P/Q). Only the TM4C129x family has ports past J.
  * **EMAC0 at 0x400EC000** -- an on-chip Ethernet MAC, which in the Tiva line
    exists only on the Connected (129x) series.
  * SYSCTL at 0x400FE000 and the APB/AHB GPIO aliases are TI Tiva throughout.
  * The one live external interrupt is 40, which is TM4C129x's EMAC0.
  * The image contains the literal string `Cortex-M4`, and TivaWare's Hungarian
    notation (`g_ui32IPMode`) all over its debug output.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import sys

# The image is the flash contents from zero: the vector table is at file offset
# 0 and the reset handler's literal pool resolves only under this base.
FLASH_BASE = 0x00000000

EXPECT_SHA256 = \
    "5081b9fe6541e214f907895355043d7f726f3e385ddec521954745afc2b61b1d"
EXPECT_SIZE = 430636

EXPECT_INIT_SP = 0x2001C46C       # vector[0] -- inside the TM4C129x's 256 KB SRAM
EXPECT_RESET = 0x0000F0A9         # vector[1] -- Reset_Handler | Thumb

# THE IMAGE HAS TWO VECTOR TABLES. The bootloader's is at 0, the application's
# at 0x00010000, and the application relocates to its own by writing VTOR. That
# is not a detail: both tables have a live entry for IRQ 40, so dispatching
# through the wrong one still "works" -- it just runs the bootloader's Ethernet
# driver, whose interface struct the application never initialises, and the
# first received frame faults in a way that looks like a descriptor bug. The
# rehost forwards VTOR to the backend (peripheral_models/cortexm_ppb.py); this
# is what pins the table it forwards to.
APP_TABLE = 0x00010000
EXPECT_APP_INIT_SP = 0x20028670
EXPECT_APP_RESET = 0x000684CD
EXPECT_APP_IRQ40 = 0x0001D5ED     # the application's EMAC0 handler | Thumb
EXPECT_DEFAULT_HANDLER = 0x0000F0C1
EXPECT_SYSTICK = 0x00007CDD       # vector[15] -- a real handler, not the default

# 112 external interrupt slots, of which exactly one is live.
EXPECT_EXT_IRQS = 112
EMAC0_IRQ = 40
EXPECT_IRQ_HANDLERS = {EMAC0_IRQ: 0x00006B2D}

LANDMARKS = {
    0x0002DDD0: b"Cortex-M4",
    0x00006D08: b"[lwIPInit] g_ui32IPMode = %d",
    0x000084B8: b"ADAM6050 Digital I/O Module",
    0x0003161E: b"ADAM-6000D A1.04B00",
    0x000299F8: b"[Gen_1]usMBTCPFlag = %x",
    0x00068478: b"HTTP/1.1 401 Unauthorized",
    0x00066AB4: (b"D:\\ADAM-6000DIO_V615\\Code\\Lib\\mbedtls-3.6.0"
                 b"\\library\\pkparse.c"),
}

RECOVERED_SYMBOLS = {
    0x0000F0A8: ("reset_handler", bytes.fromhex("0348")),
    0x00007CDC: ("systick_handler", bytes.fromhex("30b5")),
    0x00006B2C: ("emac0_irq_handler", bytes.fromhex("feb5")),
    0x0000F0BC: ("nmi_spin", bytes.fromhex("fee7")),
    0x0000F0BE: ("hardfault_spin", bytes.fromhex("fee7")),
    # The SHARED default handler: every exception slot that is not NMI,
    # HardFault or SysTick points here, including all 111 unused external IRQs.
    # It is a `b .`, so reaching it is a silent hang rather than a crash.
    0x0000F0C0: ("default_handler_spin", bytes.fromhex("fee7")),
    # A second `b .`, in the middle of the lwIP init path. Nothing in the image
    # branches or points to it, so it is reached indirectly -- worth a probe.
    0x0001D5B2: ("lwip_trap_spin", bytes.fromhex("fee7")),
    # The lwIP driver's receive walk. It faults two instructions in, on a ring
    # manager pointer read out of a global -- so the probe reads that chain.
    0x000064C4: ("lwip_rx_walk", bytes.fromhex("2de9f14f")),
    # The word-copy loop that overwrites the lwIP interface struct with 0xFF.
    0x00045160: ("bss_copy_loop", bytes.fromhex("50f8046b")),
    # The inner call of the firmware's millisecond delay loop (0x0001E898).
    # The loop spins on a SysTick-driven counter and makes no ROM calls, so a
    # clock paced off ROM calls never advances and the delay never expires.
    0x00032568: ("hal_delay_yield", bytes.fromhex("15f0c4bf")),
}

# Size of the generated `bx lr` stub region. Must match the config's
# `rom_stubs` region and tiva_rom.py's STUB_SIZE.
ROM_STUB_SIZE = 0x4000
ROM_STUB_BASE = 0x01010000
ROM_ENTRIES_PER_TABLE = 64

# SYNTHETIC symbols: landing pads for TivaWare ROM calls. These addresses are
# not in the firmware -- they are ours, handed to the firmware by
# peripheral_models/tiva_rom.py when it answers the ROM API table -- so unlike
# RECOVERED_SYMBOLS there are no bytes to guard. What IS pinned is the identity:
# each was named from the arguments at its call site, and the comment records
# the evidence.
#
#   (api table, entry) -> name
ROM_STUBS = {
    # APITABLE[1] is the UART table.
    (1, 0): "rom_UARTCharPut",        # tail-called with (UART0 base, char)
    (1, 5): "rom_UARTConfigSetExpClk",  # called with (base, clk, 115200, 0x60)
    (1, 7): "rom_UARTEnable",         # called with (base) right after config
    (1, 26): "rom_UARTBusy",          # spun on: `do {} while (f(base) != 0)`
    # APITABLE[4] is the GPIO table.
    (4, 0): "rom_GPIOPinWrite",       # `f(0x40066000, 2, 0)` -- the flash's
                                      # chip select, driven around every SPI
                                      # transaction
    (4, 21): "rom_GPIOPinTypeUART",   # called with (0x40004000 = GPIO A, 0x3)
    (4, 26): "rom_GPIOPinConfigure",  # called with 0x00000001 / 0x00000401,
                                      # which are TivaWare's GPIO_PA0_U0RX and
                                      # GPIO_PA1_U0TX pin-mux encodings
    # APITABLE[2] is the SSI table. SSI3 (0x4000B000) carries the serial NOR
    # flash, with chip-select on GPIO Q pin 1 (0x40066000, pins=2).
    (2, 0): "rom_SSIDataPut",         # `f(base, byte)` in the transfer helper
    (2, 9): "rom_SSIDataGet",         # `f(base, &byte)` right after the put
    # APITABLE[17] is the uDMA table, and it is how the serial flash is really
    # read -- the byte-at-a-time SSI path is only used for short commands.
    (17, 0): "rom_uDMAChannelTransferSet",  # five args: (chIdx, mode, src, dst,
                                            # size) -- the 5th on the stack
    (17, 5): "rom_uDMAChannelEnable",       # called once per channel, with 14
                                            # and 15 (SSI3 RX and TX)
    (17, 19): "rom_uDMAIntStatus",          # no args; the firmware tests bit 14
                                            # in `while (!(f() & 1<<14) &&
                                            # elapsed <= 500)`
    (17, 20): "rom_uDMAIntClear",           # called with the mask 0xC000,
                                            # i.e. channels 14 and 15
    # APITABLE[42] is the EMAC table. The firmware drives the Ethernet MAC
    # ENTIRELY through the ROM -- it never touches an EMAC register directly --
    # so this table is the whole network seam.
    (42, 0): "rom_EMACIntStatus",     # the EMAC ISR's first act: f(base, 1),
                                      # and the result is passed straight to
                                      # entry 9 to acknowledge it
    (42, 9): "rom_EMACIntClear",      # f(base, status)
    (42, 1): "rom_EMACAddrGet",       # f(base, 0, ptr) -- writes six bytes into
                                      # a struct field, i.e. the MAC the driver
                                      # then hands to lwIP
    (42, 15): "rom_EMACPHYRead",       # f(base, 0, reg) for regs 1/10/17/18/19;
                                       # reg 1 is BMSR and its result is masked
                                       # with 0x20, the auto-negotiation-
                                       # complete bit
    (42, 16): "rom_EMACPHYWrite",      # f(base, 0, reg, value)
    (42, 22): "rom_EMACDescriptorListSetA",  # f(base, ptr) in the init pair
    (42, 31): "rom_EMACDescriptorListSetB",  # f(base, ptr), tail-called
    # APITABLE[13] is the SysCtl table.
    (13, 4): "rom_SysCtlPeripheralPresent",  # `if (f(EMAC0) == 0) b .`  -- the
                                             # firmware hangs forever if its
                                             # Ethernet MAC reports absent
    (13, 5): "rom_SysCtlPeripheralReset",    # called just before Enable
    (13, 6): "rom_SysCtlPeripheralEnable",   # called with 0xF0000800, a
                                             # SYSCTL_PERIPH_* constant
    (13, 35): "rom_SysCtlPeripheralReady",   # `do {} while (!f(periph))` right
                                             # after Reset+Enable
}


def rom_stub_addr(table: int, entry: int) -> int:
    """Must match tiva_rom.py:stub_for (a test pins the two together)."""
    return ROM_STUB_BASE + (table * ROM_ENTRIES_PER_TABLE + entry) * 4

DEFAULT_IMAGE = ("/Users/user/Development/firmware-incoming/F4-ics-metering/"
                 "advantech-adam6000-dio-v615/adam6000_dio_v615B23.bin")


class Fail(Exception):
    pass


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", nargs="?", default=DEFAULT_IMAGE,
                    help="path to the vendor .bin")
    ap.add_argument("--outdir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src", "rehostry_adam6000_tm4c", "configs"))
    a = ap.parse_args()
    try:
        return run(a)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def run(a: argparse.Namespace) -> int:
    raw = open(a.image, "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    print(f"image sha256 {got}  ({len(raw)} bytes)")
    if got != EXPECT_SHA256:
        raise Fail(f"sha256 mismatch\n  expected {EXPECT_SHA256}\n"
                   f"  This is not the pinned Advantech release; every address "
                   f"below would be wrong. See PROVENANCE.md.")
    if len(raw) != EXPECT_SIZE:
        raise Fail(f"size {len(raw)}, expected {EXPECT_SIZE}")

    # --- 2. vector table --------------------------------------------------
    init_sp, reset = struct.unpack_from("<II", raw, 0)
    if (init_sp, reset) != (EXPECT_INIT_SP, EXPECT_RESET):
        raise Fail(f"vector table mismatch -- got SP 0x{init_sp:08x} reset "
                   f"0x{reset:08x}, expected SP 0x{EXPECT_INIT_SP:08x} reset "
                   f"0x{EXPECT_RESET:08x}")
    systick = struct.unpack_from("<I", raw, 15 * 4)[0]
    if systick != EXPECT_SYSTICK:
        raise Fail(f"SysTick vector is 0x{systick:08x}, expected "
                   f"0x{EXPECT_SYSTICK:08x}")
    print(f"  vector table OK: init_SP 0x{init_sp:08x} reset 0x{reset:08x} "
          f"systick 0x{systick:08x}")

    app_sp, app_reset = struct.unpack_from("<II", raw, APP_TABLE)
    app_irq40 = struct.unpack_from("<I", raw, APP_TABLE + (16 + 40) * 4)[0]
    if (app_sp, app_reset, app_irq40) != (EXPECT_APP_INIT_SP,
                                          EXPECT_APP_RESET,
                                          EXPECT_APP_IRQ40):
        raise Fail(
            f"application vector table at 0x{APP_TABLE:08x} mismatch -- got "
            f"SP 0x{app_sp:08x} reset 0x{app_reset:08x} irq40 "
            f"0x{app_irq40:08x}, expected SP 0x{EXPECT_APP_INIT_SP:08x} reset "
            f"0x{EXPECT_APP_RESET:08x} irq40 0x{EXPECT_APP_IRQ40:08x}.\n"
            f"       Interrupts are dispatched through this table once the "
            f"firmware writes VTOR; see PROVENANCE.md.")
    print(f"  application vector table OK at 0x{APP_TABLE:08x}: init_SP "
          f"0x{app_sp:08x} reset 0x{app_reset:08x} EMAC0 0x{app_irq40:08x}")

    # --- 3. the interrupt fingerprint -------------------------------------
    vec = struct.unpack_from(f"<{EXPECT_EXT_IRQS}I", raw, 64)
    live = {i: v for i, v in enumerate(vec)
            if v not in (0, EXPECT_DEFAULT_HANDLER)}
    if live != EXPECT_IRQ_HANDLERS:
        raise Fail(f"the set of live external interrupts changed: got "
                   f"{ {k: hex(v) for k, v in live.items()} }, expected "
                   f"{ {k: hex(v) for k, v in EXPECT_IRQ_HANDLERS.items()} }")
    # The slot after the table must NOT look like a vector, or the table is
    # longer than assumed and the "only one live IRQ" claim is not what it seems.
    after = struct.unpack_from("<I", raw, 64 + EXPECT_EXT_IRQS * 4)[0]
    if after == 0 or (after & 1 and after < len(raw)):
        raise Fail(f"the word after the vector table (0x{after:08x}) still "
                   f"looks like a handler -- the table is longer than "
                   f"{EXPECT_EXT_IRQS} entries")
    print(f"  {EXPECT_EXT_IRQS} external IRQ slots, exactly one live: "
          f"IRQ {EMAC0_IRQ} (EMAC0, the Ethernet MAC) -> "
          f"0x{EXPECT_IRQ_HANDLERS[EMAC0_IRQ]:08x}")

    # --- 4. landmarks -----------------------------------------------------
    for addr, want in sorted(LANDMARKS.items()):
        off = addr - FLASH_BASE
        if raw[off:off + len(want)] != want:
            raise Fail(f"landmark at 0x{addr:08x} is not {want!r} "
                       f"(found {raw[off:off + len(want)]!r})")
    print(f"  {len(LANDMARKS)} build landmarks OK")

    # --- 5. recovered symbols ---------------------------------------------
    for addr, (name, guard) in sorted(RECOVERED_SYMBOLS.items()):
        off = addr - FLASH_BASE
        found = raw[off:off + len(guard)]
        if found != guard:
            raise Fail(f"recovered symbol {name} @0x{addr:08x}: expected first "
                       f"bytes {guard.hex()}, found {found.hex()}.\n"
                       f"       These names are assigned by analysis, not read "
                       f"from a symbol table; the guard is what stops this "
                       f"device intercepting the wrong function.")
    print(f"  {len(RECOVERED_SYMBOLS)} recovered symbols OK (byte-pinned)")

    outdir = a.outdir
    os.makedirs(outdir, exist_ok=True)
    bin_path = os.path.join(outdir, "adam6000_tm4c.bin")
    shutil.copyfile(a.image, bin_path)
    print(f"wrote {bin_path}")

    # --- the ROM stub blob ------------------------------------------------
    # The firmware calls TivaWare driverlib through the on-chip ROM, which we
    # do not have. peripheral_models/tiva_rom.py answers the ROM's API table
    # with pointers into this region, one distinct address per (table, entry),
    # so an unimplemented ROM call lands on its own `bx lr` and returns
    # immediately instead of branching into whatever the busy-wait breaker last
    # returned. (That is not a hypothetical: with the ROM unmodelled the
    # firmware dereferenced a breaker value into its own vector table and
    # called the default handler, which is a `b .`.)
    #
    # Each stub is `movs r0, #0` + `bx lr` -- four bytes, which is exactly the
    # spacing of one API-table entry.
    #
    # RETURNING ZERO IS THE WHOLE POINT, and a bare `bx lr` is actively wrong.
    # `bx lr` leaves r0 holding the function's FIRST ARGUMENT, which for
    # driverlib is almost always a peripheral base address -- a large non-zero
    # number. Firmware polls driverlib constantly in the shape
    # `while (SomethingBusy(base))` / `while (DataGetNonBlocking(base, &x))`,
    # and every one of those loops then spins forever. It cost two of them here
    # (UARTBusy, and an SSI FIFO drain) before the default was changed; zero is
    # the right answer for "not busy", "nothing available" and "no error" alike.
    # A call that genuinely must return non-zero announces itself, and gets a
    # handler in bp_handlers/tiva_rom_api.py.
    stub_path = os.path.join(outdir, "rom_stubs.bin")
    with open(stub_path, "wb") as fh:
        fh.write(bytes.fromhex("00207047") * (ROM_STUB_SIZE // 4))
    print(f"wrote {stub_path}  ({ROM_STUB_SIZE} bytes: "
          f"`movs r0,#0; bx lr` per entry)")

    yaml_path = os.path.join(outdir, "adam6000_tm4c_addrs.yaml")
    with open(yaml_path, "w") as fh:
        fh.write("# Generated by tools/extract_firmware.py -- do not edit.\n"
                 "#\n"
                 "# RECOVERED symbols: names assigned by analysis of a stripped\n"
                 "# vendor image, each pinned to its first instruction's bytes\n"
                 "# by the extractor. Not from any build's symbol table.\n"
                 "symbols:\n")
        for addr in sorted(RECOVERED_SYMBOLS):
            fh.write(f"  {addr}: {RECOVERED_SYMBOLS[addr][0]}\n")
        fh.write("  # --- synthetic: TivaWare ROM call landing pads ---\n")
        for (table, entry), name in sorted(ROM_STUBS.items()):
            fh.write(f"  {rom_stub_addr(table, entry)}: {name}"
                     f"   # APITABLE[{table}] entry {entry}\n")
    print(f"wrote {yaml_path}  ({len(RECOVERED_SYMBOLS)} recovered + "
          f"{len(ROM_STUBS)} synthetic ROM stubs)")
    for (table, entry), name in sorted(ROM_STUBS.items()):
        print(f"    0x{rom_stub_addr(table, entry):08x}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
