# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The catch-all, under a name that is NOT ``AutoPeripheral``.

The core keys a global ``skip_svc`` off the *class name* ``AutoPeripheral``
(playbook §2.11). This firmware is bare-metal TivaWare with no RTOS, so the flag
would be harmless today -- but it is global, it would silently follow any later
config change, and the cost of not tripping it is one subclass. A test pins the
name.
"""
from __future__ import annotations

from halucinator.peripheral_models.auto_model import AutoPeripheral


class SocCatchAll(AutoPeripheral):
    """Records MMIO and applies the busy-wait breaker, under a safe name."""
