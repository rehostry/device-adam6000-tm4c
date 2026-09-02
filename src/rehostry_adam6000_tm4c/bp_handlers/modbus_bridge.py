# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bridges host TCP sockets to the device's own servers over the modelled wire.

The device is a server -- Modbus/TCP on 502 and an HTTP configuration server on
80 -- reachable only over Ethernet, so between a host tool and either of them
sit an EMAC, a descriptor ring, ARP, IPv4 and TCP, all of them modelled. This
exposes the far end of that path as ordinary sockets, so an attack (or
`mbpoll`, or `curl`) can speak to the rehosted device without knowing any of it
is there.

Every byte still crosses the whole stack: host socket -> a modelled peer's TCP
-> IPv4 -> an Ethernet frame -> the EMAC's receive descriptor ring -> lwIP ->
the firmware's own server, and back. Nothing short-circuits.

**ONE BRIDGE PER SERVICE, AND ONE MACHINE PER BRIDGE.** This used to be a
single host port wired to the literal constant 502, which is why the only
server anyone could reach was Modbus -- `net_peer.connect()` has always taken a
port and only this caller was fixed. Each service now has its own host port,
its own device port, and, crucially, **its own modelled peer with its own MAC
and its own IP**. That is not decoration: it is what makes the two services
separable in the model rather than only in our naming. Two peers can hold two
established connections at once, so one server can be answering while the other
is quiescent, and switching one off leaves the other's round trip untouched.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

from ..peripheral_models.net_peer import get_peer

log = hal_log.getHalLogger()

DEFAULT_PORT = 21060
MODBUS_TCP_PORT = 502
HTTP_TCP_PORT = 80


def bridge_port() -> int:
    return int(os.environ.get("HAL_ADAM_BRIDGE_PORT", str(DEFAULT_PORT)), 0)


def device_port() -> int:
    """Which of the device's servers the primary bridge connects to.

    A DISCRIMINATION LEVER, not a feature. `net_peer.connect()` has always
    taken a port; only this caller was a literal, so the only server anyone
    could ever reach was Modbus/TCP. Pointing it at 80 asks lwIP a question it
    answers unambiguously: a listening PCB replies SYN/ACK, and nothing
    listening replies RST. See STATUS.md -- the answer was SYN/ACK, and then a
    6463-byte page.
    """
    return int(os.environ.get("HAL_ADAM_DEVICE_PORT", str(MODBUS_TCP_PORT)), 0)


def http_bridge_port() -> int:
    """Host port for the HTTP service, or 0 to leave that service off.

    Off by default so a run that only wants Modbus is byte-identical to what
    this device did before it learned to bridge two servers.
    """
    return int(os.environ.get("HAL_ADAM_HTTP_BRIDGE_PORT", "0"), 0)


_BRIDGE: Optional["ModbusBridge"] = None


def get_bridge() -> Optional["ModbusBridge"]:
    return _BRIDGE


class _Service:
    """One host TCP port, wired to one device port through one modelled peer."""

    def __init__(self, name: str, host_port: int, dev_port: int,
                 peer_name: str) -> None:
        self.name = name
        self.host_port = host_port
        self.dev_port = dev_port
        self.peer_name = peer_name
        self.clients: List[socket.socket] = []
        self.lock = threading.Lock()
        self.want_reconnect = False
        self.local_port = 40000 + (0 if peer_name == "default" else 1000)
        self.to_device = 0
        self.to_host = 0

    @property
    def peer(self):
        return get_peer(self.peer_name)


class ModbusBridge(BPHandler):
    """TCP servers whose traffic is carried to the device as Ethernet."""

    def __init__(self, **kwargs: Any) -> None:
        global _BRIDGE
        _BRIDGE = self
        self.port = bridge_port()
        self._started = False
        self.services: List[_Service] = [
            _Service("modbus", self.port, device_port(), "default"),
        ]
        http_port = http_bridge_port()
        if http_port:
            self.services.append(
                _Service("http", http_port, HTTP_TCP_PORT, "http"))
        # Back-compat for anything that read these off the bridge.
        self.clients = self.services[0].clients
        self._lock = self.services[0].lock
        self.to_device = 0
        self.to_host = 0

    def service(self, name: str) -> Optional[_Service]:
        for svc in self.services:
            if svc.name == name:
                return svc
        return None

    # -- from the device ---------------------------------------------------
    def pump(self) -> None:
        """Move anything the device sent up to the attached host sockets.

        Called from breakpoint context, so it never races the guest -- which is
        why the reconnects happen here and not on a client thread: opening one
        writes peer state the guest is concurrently reading.
        """
        for svc in self.services:
            peer = svc.peer
            if svc.want_reconnect:
                svc.want_reconnect = False
                svc.local_port += 1
                log.info("Bridge[%s]: opening a connection to %s:%d from "
                         "port %d", svc.name,
                         ".".join(str(b) for b in peer.device_ip),
                         svc.dev_port, svc.local_port)
                peer.connect(svc.dev_port, local_port=svc.local_port)
            data = peer.take_rx()
            if not data:
                continue
            svc.to_host += len(data)
            self.to_host += len(data)
            with svc.lock:
                dead = []
                for sock in svc.clients:
                    try:
                        sock.sendall(data)
                    except OSError:
                        dead.append(sock)
                for sock in dead:
                    svc.clients.remove(sock)

    # -- from the host -----------------------------------------------------
    def _serve(self, svc: _Service) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", svc.host_port))
        except OSError as exc:
            log.error("Bridge[%s]: cannot bind tcp/%d (%s)", svc.name,
                      svc.host_port, exc)
            return
        srv.listen(4)
        peer = svc.peer
        log.info("Bridge[%s]: tcp/%d -- carried over modelled Ethernet from "
                 "%s (%s) to %s:%d", svc.name, svc.host_port,
                 ".".join(str(b) for b in peer.ip), peer.mac.hex(":"),
                 ".".join(str(b) for b in peer.device_ip), svc.dev_port)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with svc.lock:
                svc.clients.append(conn)
                # A fresh host client gets a fresh connection to the device's
                # server. Done from `pump`, on the emulator's thread.
                svc.want_reconnect = True
            threading.Thread(target=self._read_client, args=(conn, svc),
                             daemon=True).start()

    def _read_client(self, conn: socket.socket, svc: _Service) -> None:
        peer = svc.peer
        # A new host connection means a new connection to the device's server.
        peer.arp_request()
        deadline = time.time() + 20
        while peer.device_mac is None and time.time() < deadline:
            time.sleep(0.1)
        while True:
            try:
                data = conn.recv(1024)
            except OSError:
                data = b""
            if not data:
                with svc.lock:
                    if conn in svc.clients:
                        svc.clients.remove(conn)
                try:
                    conn.close()
                except OSError:
                    pass
                return
            svc.to_device += len(data)
            self.to_device += len(data)
            peer.send(data)

    # -- the seam ----------------------------------------------------------
    @bp_handler(["rom_SysCtlPeripheralReady"])
    def start(self, qemu: Any, bp_addr: int) -> Tuple[bool, Optional[int]]:
        """Start the servers once, early, on a call the boot makes anyway.

        This handler shares its symbol with TivaRomApi's -- intercepts append
        across a config, they do not override (playbook §2.4) -- so both run and
        the ROM call still returns 1.
        """
        if not self._started:
            self._started = True
            for svc in self.services:
                threading.Thread(target=self._serve, args=(svc,),
                                 daemon=True).start()
        self.pump()
        return True, 1
