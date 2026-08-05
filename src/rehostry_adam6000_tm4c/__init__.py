# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""rehostry-adam6000-tm4c -- the Advantech ADAM-6050 Ethernet remote digital-I/O
module (TI TM4C129x, Cortex-M4F) as a standalone HALucinator device.

Bare-metal TivaWare with lwIP, an HTTP server, Modbus/TCP, SNMP and mbedTLS.
The firmware is vendor-supplied and NOT redistributed here -- regenerate it with
`tools/extract_firmware.py` (see PROVENANCE.md).
"""
from . import paths, spawn
from .binding import make_device

DEVICE_NAME = "adam6000-tm4c"

__version__ = "0.0.1"

__all__ = ["paths", "spawn", "make_device", "DEVICE_NAME", "__version__"]
