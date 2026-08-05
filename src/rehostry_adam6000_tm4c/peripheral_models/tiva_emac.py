# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""EMAC0 -- the TM4C129x's on-chip Ethernet MAC and PHY. (bring-up in progress)"""
from __future__ import annotations

from typing import Any, Optional

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

EMAC_IRQ = 40


class TivaEmac(SocCatchAll):
    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self._backend: Optional[Any] = None

    def set_backend(self, backend: Any) -> None:
        self._backend = backend
