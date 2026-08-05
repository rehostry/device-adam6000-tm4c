# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The UART0 debug console, as a sink the rest of the device can share.

The firmware does not touch UART data registers directly -- it calls TivaWare's
`ROM_UARTCharPut` (see bp_handlers/tiva_rom_api.py), so the console's seam is a
ROM entry rather than an MMIO offset. This holds the bytes either way, so the
headless run, the log and a future TCP bridge all see the same stream and there
is no second code path for the thing evidence rests on.
"""
from __future__ import annotations

import os
from typing import Callable, List, Optional

from halucinator import hal_log

log = hal_log.getHalLogger()


class Console:
    """Collects console bytes; logs whole lines, and feeds an optional sink."""

    def __init__(self) -> None:
        self.tx_bytes = 0
        self.lines: List[str] = []
        self._line = bytearray()
        self._last_flush = -1
        self._sink: Optional[Callable[[bytes], None]] = None
        self._echo = os.environ.get("HAL_ADAM_CONSOLE_ECHO", "1") == "1"

    def set_sink(self, sink: Callable[[bytes], None]) -> None:
        self._sink = sink

    def putc(self, byte: int) -> None:
        byte &= 0xFF
        self.tx_bytes += 1
        if self._sink is not None:
            self._sink(bytes([byte]))
        if not self._echo:
            return
        if byte == 0x0A:
            self.flush()
        elif byte != 0x0D:
            self._line.append(byte)

    def flush_idle(self) -> None:
        """Emit a partial line the firmware has stopped adding to.

        Debug output here is `printf`-style with no trailing newline on the
        important lines -- `[lwIPInit] g_ui32IPMode = %d, ...` ends mid-sentence
        -- so a strictly newline-buffered log loses exactly the messages that
        say where the boot got to. Flushing only once a whole call has passed
        with no new byte distinguishes "still printing" from "waiting".
        """
        if self._line and self.tx_bytes == self._last_flush:
            self.flush()
        self._last_flush = self.tx_bytes

    def flush(self) -> None:
        if self._line:
            text = bytes(self._line).decode("latin1")
            self.lines.append(text)
            if len(self.lines) > 500:
                del self.lines[0]
            log.info("CONSOLE %s", text)
            self._line.clear()


_CONSOLE = Console()


def get_console() -> Console:
    return _CONSOLE
