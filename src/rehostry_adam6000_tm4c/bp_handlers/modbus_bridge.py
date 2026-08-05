# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bridges a host TCP socket to the device's Modbus/TCP server over the wire.

The device is a Modbus server on port 502, reachable only over Ethernet -- so
between a host tool and that server sit an EMAC, a descriptor ring, ARP, IPv4
and TCP, all of them modelled. This exposes the far end of that path as an
ordinary socket, so an attack (or `mbpoll`, or anything else) can speak
Modbus/TCP to the rehosted device without knowing any of it is there.

Every byte still crosses the whole stack: host socket -> the modelled peer's TCP
-> IPv4 -> an Ethernet frame -> the EMAC's receive descriptor ring -> lwIP ->
the firmware's Modbus server, and back. Nothing short-circuits.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from typing import Any, List, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

from ..peripheral_models.net_peer import get_peer

log = hal_log.getHalLogger()

DEFAULT_PORT = 21060
MODBUS_TCP_PORT = 502


def bridge_port() -> int:
    return int(os.environ.get("HAL_ADAM_BRIDGE_PORT", str(DEFAULT_PORT)), 0)


_BRIDGE: Optional["ModbusBridge"] = None


def get_bridge() -> Optional["ModbusBridge"]:
    return _BRIDGE


class ModbusBridge(BPHandler):
    """A TCP server whose traffic is carried to the device as Ethernet."""

    def __init__(self, **kwargs: Any) -> None:
        global _BRIDGE
        _BRIDGE = self
        self._want_reconnect = False
        self._local_port = 40000
        self.port = bridge_port()
        self.clients: List[socket.socket] = []
        self._started = False
        self._lock = threading.Lock()
        self.to_device = 0
        self.to_host = 0

    # -- from the device ---------------------------------------------------
    def pump(self) -> None:
        """Move anything the device sent up to the attached host socket.

        Called from breakpoint context, so it never races the guest.
        """
        peer = get_peer()
        if self._want_reconnect:
            self._want_reconnect = False
            self._local_port += 1
            log.info("ModbusBridge: opening a connection to %s:%d from port %d",
                     ".".join(str(b) for b in peer.device_ip),
                     MODBUS_TCP_PORT, self._local_port)
            peer.connect(MODBUS_TCP_PORT, local_port=self._local_port)
        data = peer.take_rx()
        if not data:
            return
        self.to_host += len(data)
        with self._lock:
            dead = []
            for sock in self.clients:
                try:
                    sock.sendall(data)
                except OSError:
                    dead.append(sock)
            for sock in dead:
                self.clients.remove(sock)

    # -- from the host -----------------------------------------------------
    def _serve(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", self.port))
        except OSError as exc:
            log.error("ModbusBridge: cannot bind tcp/%d (%s)", self.port, exc)
            return
        srv.listen(4)
        log.info("ModbusBridge: Modbus/TCP on tcp/%d -- carried to the device "
                 "over modelled Ethernet to %s:%d", self.port,
                 get_peer().device_ip and ".".join(
                     str(b) for b in get_peer().device_ip), MODBUS_TCP_PORT)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self._lock:
                self.clients.append(conn)
                # A fresh host client gets a fresh connection to the device.
                # Done from `pump`, on the emulator's thread, because opening
                # one writes peer state the guest is concurrently reading.
                self._want_reconnect = True
            threading.Thread(target=self._read_client, args=(conn,),
                             daemon=True).start()

    def _read_client(self, conn: socket.socket) -> None:
        peer = get_peer()
        # A new host connection means a new connection to the device's server.
        peer.arp_request()
        deadline = time.time() + 20
        while peer.device_mac is None and time.time() < deadline:
            time.sleep(0.1)
        peer.connect(MODBUS_TCP_PORT)
        while True:
            try:
                data = conn.recv(1024)
            except OSError:
                data = b""
            if not data:
                with self._lock:
                    if conn in self.clients:
                        self.clients.remove(conn)
                try:
                    conn.close()
                except OSError:
                    pass
                return
            self.to_device += len(data)
            peer.send(data)

    # -- the seam ----------------------------------------------------------
    @bp_handler(["rom_SysCtlPeripheralReady"])
    def start(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """Start the server once, early, on a call the boot makes anyway.

        This handler shares its symbol with TivaRomApi's -- intercepts append
        across a config, they do not override (playbook §2.4) -- so both run and
        the ROM call still returns 1.
        """
        if not self._started:
            self._started = True
            threading.Thread(target=self._serve, daemon=True).start()
        self.pump()
        return True, 1
