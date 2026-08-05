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
    0x0000F0BC: ("fault_handler_spin", bytes.fromhex("fee7")),
}

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
    print(f"wrote {yaml_path}  ({len(RECOVERED_SYMBOLS)} symbols)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
