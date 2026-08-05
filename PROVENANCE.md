<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Provenance — adam6000-tm4c firmware

## The binary

- **Upstream:** a vendor firmware release for the Advantech ADAM-6000 series
  digital-I/O modules, `adam6000_dio_v615B23.bin`. It is a full flash image: an
  Advantech bootloader at `0x00000000` and the application at `0x00010000`.
- **Target:** Texas Instruments TM4C129x (ARM Cortex-M4F), bare-metal with
  lwIP. The firmware is a Modbus/TCP + SNMP + HTTP remote-I/O server.
- **Build origin:** the image identifies itself on its own console —
  `BL: Advantech ADAM-6000D A1.03B10!!` for the bootloader and
  `6000_DIO V6.15B23 start!!` for the application.
- **Hashes:**
  - source image `adam6000_dio_v615B23.bin` — sha256
    `5081b9fe6541e214f907895355043d7f726f3e385ddec521954745afc2b61b1d`
    (430,636 bytes). Pinned as `EXPECT_SHA256` in
    `tools/extract_firmware.py`; the extractor refuses any other image.
  - generated `rom_stubs.bin` — sha256
    `ebb27c27169d1aa6553a3ee5766aa22238716adf193ce204336248d5646c7ca6`
    (16,384 bytes). Not vendor content: 4,096 copies of
    `movs r0,#0 ; bx lr`, the landing pads for unimplemented ROM calls.

**The binaries are not committed.** `.gitignore` excludes `*.bin`/`*.elf`/
`*.hex`; regenerate them with `tools/extract_firmware.py`.

## How the target was identified

There is no part number anywhere in the image. It was resolved from what the
firmware addresses:

- **GPIO ports A through Q** are used (`0x40061000`..`0x40066000` = K/L/M/N/P/Q).
  Only the TM4C129x family has ports past J.
- A **masked driverlib ROM** is called through `ROM_APITABLE` at `0x01000010`,
  which is the TivaWare convention and exists only on TI Tiva parts.
- **APITABLE\[42\]** is the EMAC table, and the firmware fetches entries from it
  (`EMACIntStatus`, `EMACPHYRead/Write`, `EMACDescriptorListSet*`) — so the part
  has the integrated Ethernet MAC+PHY, i.e. a TM4C129x rather than a TM4C123x.
- The vector table at `0x00000000` gives `init_SP = 0x2001C46C` and
  `Reset = 0x0000F0A9`; the application's table at `0x00010000` gives
  `init_SP = 0x20028670` and `Reset = 0x000684CD`.

`tools/extract_firmware.py` re-derives all of this on every run and guards it:
the SHA-256, both vector tables' first two words, seven build landmarks
(including the version strings above), the set of live ISRs, and nine
byte-pinned recovered symbols. A recovered symbol whose first instruction bytes
do not match is a hard failure, not a warning — these names are assigned by
analysis of a stripped image, not read from a symbol table, and the guard is
what stops the device intercepting the wrong function.

## The falsifiable prediction

Derived statically from the image, **before the first boot**, and recorded in
`tools/extract_firmware.py`:

1. `init_SP = 0x2001C46C`, `Reset = 0x0000F0A9` — the CPU starts in the
   bootloader, not the application.
2. **Exactly one** external interrupt is live in the bootloader's vector table:
   IRQ **40**, handler `0x00006B2D`. Every other external vector points at a
   single shared `b .` at `0x0000F0C1`. IRQ 40 on a TM4C129x is EMAC0, so the
   device's only interrupt source is Ethernet.
3. The firmware would call driverlib through the masked ROM rather than
   touching EMAC registers directly, so the ROM API table — not the MAC's
   register file — would be the seam the rehost has to answer.

All three held. (2) is the sharpest: the run's ROM trace shows the firmware
fetching table 42's entries and no other interrupt ever arming, and the
`NVIC: firmware armed IRQ 40` line is the only one of its kind.

**Recorded as observed, not predicted**, to keep the distinction honest: the
device's IP (10.0.0.1) and MAC OUI (`00:D0:C9`) were read off the firmware's
console after boot. They are still non-circular — 10.0.0.1 is Advantech's
documented factory default and `00:D0:C9` is Advantech's registered OUI, and
neither value is written into the guest by any host code — but they were not
predicted in advance.

## Licensing

This re-host package is **AGPL-3.0-or-later**.

The firmware binaries are **not committed** to this repository. They are
Advantech's proprietary firmware, redistributable only by Advantech; obtain a
copy from the vendor and generate the packaged artefacts locally with
`tools/extract_firmware.py`. No vendor bytes appear in this repository — the
only binary the tooling produces from scratch is `rom_stubs.bin`, which is
generated instruction sequence, not vendor content.
