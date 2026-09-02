# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The single source of truth for *how to run this device* under HALucinator.

Both the standalone CLI (`rehostry-adam6000-tm4c run`) and the orchestrator binding
build their HALucinator invocation from here, so there is exactly one spawn
recipe: HALucinator is run on the **unicorn** backend with this device's
config(s), optionally overlaying a host bridge.

HALucinator is a *runtime* dependency reached as a separate process; it is not
imported here. It must be importable by the spawned interpreter, which is the
*installed* ``halucinator`` in the running interpreter's environment
(``sys.executable``, overridable via the ``HAL_PY`` env var). We deliberately do
NOT splice any source tree onto PYTHONPATH: a polluted ``HALUCINATOR_SRC`` /
``PYTHONPATH`` must never resurrect an out-of-tree core, so both are stripped
from the child env (see :func:`spawn_env`).
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from . import paths

# The device's real seam: Ethernet. Frames are bridged in and out of the EMAC0
# model, and a minimal host-side network peer carries Modbus/TCP over them.
BRIDGE_PORT_ENV = "HAL_ADAM_BRIDGE_PORT"
DEFAULT_BRIDGE_PORT = 21060
# A DEFAULT, not a pin: the same env var the bridge model reads
# (bp_handlers/modbus_bridge.py) selects the port on BOTH sides, so a client
# built from this constant follows the emulator wherever it binds.
BRIDGE_PORT = int(os.environ.get(BRIDGE_PORT_ENV, str(DEFAULT_BRIDGE_PORT)), 0)
# Symbolic seam id (e.g. the driver methods the bridge hooks), for the binding.
UART_SEAM = "EMAC0 @0x400EC000 (the Ethernet MAC) + UART0 debug console"


# ZMQ peripheral-bus ports. HALucinator's peripheral_server.start() BINDS the
# machine-global ipc endpoints /tmp/IoServer2Halucinator<rx> and
# /tmp/Halucinator2IoServer<tx>; its own defaults are 5555/5556, so two devices
# left on the default silently share one bus and inject each other's peripheral
# messages into the wrong guest. This device therefore owns a distinct default
# pair, overridable via the env vars below.
# TODO: pick a pair no other device in the fleet uses; rename the env vars.
DEFAULT_RX_PORT = int(os.environ.get("HAL_ADAM_RX_PORT", "5840"))
DEFAULT_TX_PORT = int(os.environ.get("HAL_ADAM_TX_PORT", "5841"))


def spawn_argv(python: Optional[str] = None, emulator: str = "unicorn",
               bridge: bool = False,
               rx_port: Optional[int] = None,
               tx_port: Optional[int] = None) -> list[str]:
    """argv for ``python -m halucinator.main`` with this device's configs.

    Config files are passed by basename and resolved against :func:`spawn_cwd`.
    With ``bridge=True`` the host-bridge overlay is appended. The provisioned
    overlay is appended whenever a device profile is in play, so every entry
    point gets it -- forgetting it is silent: the boot simply stops inside a
    delay loop before lwIP finishes.
    """
    from .peripheral_models import device_profile
    argv = [python or os.environ.get("HAL_PY") or sys.executable,
            "-m", "halucinator.main"]
    extra = []
    if device_profile.provisioned():
        extra.append(paths.PROFILE_CONFIG)
    if bridge:
        extra.append(paths.BRIDGE_CONFIG)
    for f in (paths.CONFIG_FILES + extra):
        argv += ["-c", f]
    argv += ["--emulator", emulator]
    if rx_port is None:
        rx_port = DEFAULT_RX_PORT
    if tx_port is None:
        tx_port = DEFAULT_TX_PORT
    argv += ["--rx_port", str(rx_port), "--tx_port", str(tx_port)]
    return argv


def spawn_cwd() -> str:
    """Run from the packaged configs dir so config basenames + the relative
    ``file: adam6000_tm4c.bin`` in the memory config resolve."""
    return str(paths.configs_dir())


def spawn_env(halucinator_src: Optional[str] = None,
              extra: Optional[dict] = None) -> dict:
    """Environment for the spawned HALucinator process.

    The child runs the *installed* ``halucinator@dev``, so we defensively strip
    ``HALUCINATOR_SRC`` and ``PYTHONPATH`` from the inherited environment: a
    polluted value must not resurrect an out-of-tree core. The
    ``halucinator_src`` argument is accepted for API compatibility but ignored.
    Force unbuffered output so the console streams promptly.
    """
    env = dict(os.environ)
    env.pop("HALUCINATOR_SRC", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONUNBUFFERED"] = "1"
    # A 430 KB image with a handful of breakpoints: the default global
    # per-instruction hook dominates runtime.
    env.setdefault("HAL_FAST_BP", "1")
    # ARMv7E-M with an FPU: the reset handler's first act is to enable CP10/CP11.
    env.setdefault("HAL_CORTEXM_CPU_MODEL", "UC_CPU_ARM_CORTEX_M4")
    # Bound the emulator's instruction chunks so it returns to its dispatch
    # loop and can drain a queued interrupt (playbook §2.99).
    env.setdefault("HAL_IRQ_CHUNK", "20000")
    if extra:
        env.update(extra)
    return env
