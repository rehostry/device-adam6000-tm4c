# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Resource paths for the packaged HALucinator configs (+ firmware, if it is
redistributable).

Everything the device needs to run ships inside the installed package. These
helpers resolve those paths from the *installed* location via
``importlib.resources``, so the device runs from anywhere -- no cwd assumptions,
no `project.` PYTHONPATH hack.

TODO: rename the config basenames below to your device's, and set the firmware
basename. If your firmware is NOT redistributable, it will NOT be committed
(.gitignore excludes *.bin/*.elf) -- the user regenerates it with
`tools/extract_firmware.py` into configs/ before running.
"""
from __future__ import annotations

import importlib.resources as _ir
from pathlib import Path

PACKAGE = "rehostry_adam6000_tm4c"

# The config files handed to `halucinator.main -c ...`, in load order. This is
# the base (headless) run; any host-bridge overlay is appended on demand -- see
# BRIDGE_CONFIG / config_paths(bridge=True).
# TODO: name your real config + derived addr map.
CONFIG_FILES = [
    "adam6000_tm4c_config.yaml",
    "adam6000_tm4c_addrs.yaml",
]

# Optional overlay that bridges a firmware seam (e.g. a UART ring buffer) to a
# host TCP server. Layered on top of CONFIG_FILES. Delete if your device has no
# host-facing seam.
# TODO: name your bridge overlay, or remove bridge support entirely.
BRIDGE_CONFIG = "adam6000_tm4c_bridge.yaml"

# TODO: your firmware basename (committed only if redistributable -- see
# PROVENANCE.md). Non-redistributable firmware is regenerated into configs/.
FIRMWARE_BIN = "adam6000_tm4c.bin"
FIRMWARE_ELF = "adam6000_tm4c.elf"


def configs_dir() -> Path:
    """Absolute path to the packaged configs/ dir (also where firmware lives)."""
    return Path(str(_ir.files(PACKAGE))) / "configs"


def config_paths(bridge: bool = False) -> list[Path]:
    files = list(CONFIG_FILES)
    if bridge:
        files.append(BRIDGE_CONFIG)
    return [configs_dir() / f for f in files]


def firmware_bin() -> Path:
    return configs_dir() / FIRMWARE_BIN


def firmware_elf() -> Path:
    return configs_dir() / FIRMWARE_ELF


def firmware_present() -> bool:
    return firmware_bin().is_file()
