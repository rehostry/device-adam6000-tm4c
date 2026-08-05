# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Orchestrator binding: expose this device to rehostry/orchestrator.

This is the adapter a co-simulation scenario imports. It depends on the
orchestrator package (`rehostry`), so it's an OPTIONAL extra -- the device runs
fine standalone (via the CLI) without it. The import is lazy so merely importing
`rehostry_adam6000_tm4c` never requires the orchestrator to be installed.

The DEVICE descriptor below is what a co-simulation scenario reads to find
`from .binding import make_device` in __init__.py + the `orchestrator` extra in
pyproject.toml) if you do not need co-simulation.
"""
from __future__ import annotations

from typing import Optional

from . import paths, spawn

# Static description of the device (also what a future halucinator entry-point
# plugin hook would advertise).
DEVICE = {
    "name": "adam6000-tm4c",
    "uart_seam": spawn.UART_SEAM,           # TODO: your seam id
    "config_files": paths.CONFIG_FILES,
    "bridge_config": paths.BRIDGE_CONFIG,
    "bridge_port": spawn.BRIDGE_PORT,        # host TCP server, if any
    "telemetry": "TODO: one-line description of the host-facing seam",
}


def make_device(name: str = "adam6000-tm4c",
                halucinator_src: Optional[str] = None,
                bridge: bool = True,
                python: Optional[str] = None, log_path: Optional[str] = None):
    """Build a rehostry.Device for this device, wired with the spawn recipe.

    Requires the `rehostry` orchestrator package
    (install `rehostry-adam6000-tm4c[orchestrator]`).
    """
    try:
        from rehostry import Device, SpawnSpec
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "make_device needs the orchestrator: pip install 'rehostry-adam6000-tm4c[orchestrator]'"
        ) from e

    spec = SpawnSpec(
        argv=spawn.spawn_argv(python=python, bridge=bridge),
        cwd=spawn.spawn_cwd(),
        env=spawn.spawn_env(halucinator_src=halucinator_src),
        log_path=log_path,
        readiness_marker=None,
        join_delay=6.0,
    )
    return Device(name, None, uart_id=spawn.BRIDGE_PORT, spawn=spec)
