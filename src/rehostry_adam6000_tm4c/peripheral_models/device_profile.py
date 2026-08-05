# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The device profile that lives in the serial flash -- and does not ship.

WHAT THIS IS AND IS NOT. An ADAM-6000 module keeps its identity off-chip: model
number, hardware revision, how many pins it has and which of them are inputs.
The vendor firmware image does not contain any of it, so a rehost given a blank
flash boots into a module that does not know what it is -- `GetDevInfo() Err`,
`g_usModel = 255`, zero I/O points -- and rejects every Modbus data address,
because it has none.

This module writes a profile into the modelled flash so the firmware finds one.
That is a deliberate modelling decision and it needs its boundary stated
plainly:

  * **The format is derived, not invented.** Every element and attribute name
    below was recovered from the firmware's own XML handlers (the string table
    at 0x00045DEC..0x00045E4C, dispatched from 0x00045C8C), and the placement
    -- a 32-bit length at flash 0x50000 followed by the record at 0x50004, with
    the length rejected unless it is below 0x3FFD -- was read out of
    `GetDevInfo` at 0x0002AC3C. The firmware itself is the authority, and it
    accepts or rejects what is written here on its own terms.

  * **The values are from Advantech's published specification** for the
    ADAM-6050: 12 digital inputs and 6 digital outputs, 18 pins in total.
    They are not recovered from any device.

  * **This is not vendor data.** It is a plausible profile in the vendor's
    format. Nothing here was read off real hardware, and a finding that depends
    on a specific field value is a property of this file, not of the product.
    Set ``HAL_ADAM_SFLASH_BLANK=1`` to get the as-shipped behaviour back -- an
    erased flash and a module that reports nothing -- and check anything that
    matters against both.
"""
from __future__ import annotations

import os

# Advantech's published channel counts for the ADAM-6050.
MODEL = int(os.environ.get("HAL_ADAM_MODEL", "6050"), 0)
DI_CHANNELS = int(os.environ.get("HAL_ADAM_DI", "12"), 0)
DO_CHANNELS = int(os.environ.get("HAL_ADAM_DO", "6"), 0)
TOTAL_PINS = DI_CHANNELS + DO_CHANNELS
# NOT COSMETIC. The hardware version selects the stride of the pin arrays:
# 0x0002A33A memcmps it against "A1000" (stride 2) and then "A2000" (stride 1),
# and if it matches neither the stride stays **zero** -- so the loop that walks
# the channels at 0x0002A370 advances by nothing and never terminates. A
# plausible-looking "A1.0" hangs the boot after lwIP with no message at all.
# Stride 2 matches the two-byte (port, pin) entries the pin lists decode into.
HW_VERSION = os.environ.get("HAL_ADAM_HWVER", "A1000")


def pin_list(port_pins) -> str:
    """The firmware's pin-list grammar, decoded from the parser at 0x004599B0.

    Each entry is exactly **three characters**: a port letter A..Q (validated
    as `c - 'A' < 17`), a pin digit 0..7 (`c - '0' < 8`), then one separator
    character, which the parser skips without inspecting. It stops when the
    separator position holds NUL, so the last entry carries no separator.
    These are GPIO port/pin assignments, not channel counts.
    """
    return ",".join("%s%d" % (port, pin) for port, pin in port_pins)


# WHICH PHYSICAL PINS the real module wires its channels to is not recoverable
# from the firmware -- it is exactly the information the profile exists to
# carry. These are plausible assignments in the correct grammar, nothing more.
DI_PINS = [("A", n) for n in range(8)] + [("B", n) for n in range(4)]
DO_PINS = [("C", n) for n in range(6)]


def profile_xml() -> bytes:
    """The profile record, in the form the firmware's parser accepts.

    Structure, all of it read out of the firmware rather than guessed:

      * root element `ADAM` (the only name the handler at 0x00045D04 accepts);
      * `module` and `DIO` are **siblings** under it, not nested -- the handler
        it returns (0x00045C8C) matches both at the same level;
      * their children are **leaf elements carrying text**, not attributes: the
        kind-3 callback receives an element name and its character data, and
        the model name is built as the literal "ADAM" followed by `id`, which
        is why an unprovisioned module calls itself ADAM6000;
      * each `DIO` block carries a `type` of **"DI"** or **"DO"** -- the apply
        step at 0x00045930 selects on it, and only the second path writes
        `ucTotal_StatusPins`, so a profile without it parses cleanly and
        populates nothing;
      * `statusPin` / `pins` / `ledpins` take pin lists in the grammar above;
      * `EtherIC` accepts a single character and sets a flag bit when it is
        '1'; `HWver` and `id` are limited to eight characters.

    Verified by the firmware's own acceptance. With this record it prints
    " Copy OK >> model (0), bDO_OCP=1", resolves `g_usModel` to 0 (the index of
    "6050" in its own table of 6050/6051/6052/6060/6066) and enumerates its
    channels::

        @0x20015e40 [ADAM6050]:  HvA1.0
          I[12] 1: 0.0 0.1 0.2 0.3 0.4 0.5 0.6 0.7 1.0 1.1 1.2 1.3
          O[6]  0: 2.0 2.1 2.2 2.3 2.4 2.5

    which is an ADAM-6050: twelve digital inputs and six digital outputs.
    """
    override = os.environ.get("HAL_ADAM_PROFILE_XML")
    if override:
        return override.encode()
    return (
        '<ADAM>'
        f'<module><id>{MODEL}</id><HWver>{HW_VERSION}</HWver>'
        '<EtherIC>1</EtherIC></module>'
        f'<DIO><type>DI</type><total>{DI_CHANNELS}</total>'
        f'<pins>{pin_list(DI_PINS)}</pins>'
        f'<statusPin>{pin_list(DI_PINS)}</statusPin>'
        f'<statusTotal>{DI_CHANNELS}</statusTotal></DIO>'
        f'<DIO><type>DO</type><total>{DO_CHANNELS}</total>'
        f'<pins>{pin_list(DO_PINS)}</pins>'
        f'<statusPin>{pin_list(DO_PINS)}</statusPin>'
        f'<statusTotal>{DO_CHANNELS}</statusTotal></DIO>'
        '</ADAM>'
    ).encode()


def provisioned() -> bool:
    """OPT-IN, and off by default, because it is not finished.

    With a profile in place the firmware accepts it -- " Copy OK", the model
    name resolves to ADAM6050, the pin list parses -- but the channel counts
    still do not populate (`ucTotal_StatusPins = 0`, `model (0)`) and the boot
    does not reach "IP ready.". Until that is understood, the default stays at
    the as-shipped erased part, which boots and answers. Set
    ``HAL_ADAM_PROFILE=1`` to continue the work.
    """
    return os.environ.get("HAL_ADAM_PROFILE") == "1"
