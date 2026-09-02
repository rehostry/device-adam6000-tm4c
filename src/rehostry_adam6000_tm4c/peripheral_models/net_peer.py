# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Other machines on the wire: ARP, IPv4 and enough TCP to carry a session.

WHY THIS EXISTS. The EMAC model moves Ethernet frames in and out of the
firmware's DMA rings, which proves the MAC works and nothing else. Everything
this device is *for* -- Modbus/TCP on port 502, the web UI, SNMP -- lives above
a TCP connection, and a TCP connection needs something at the other end. The
firmware will not open one; it is a server.

So this is a deliberately small peer. It is **host-side**: it does not execute,
it holds one connection at a time, and it implements exactly the parts of the
stack a single well-behaved conversation needs -- because the medium here is
lossless and in-order, so retransmission, windows and congestion control have
nothing to do.

THERE IS MORE THAN ONE OF THEM, AND THAT IS THE POINT. This module used to
expose a single global peer, so every one of the device's servers had to be
reached from the same machine, one connection at a time -- which meant the
Modbus master and the web client were, in the model, indistinguishable. They
are not indistinguishable on a plant network: a SCADA master and an engineer's
browser are different hosts with different MACs and different addresses, and
the device demultiplexes them in lwIP. `get_peer(name)` returns one peer per
name, each with its OWN MAC and OWN IP, and each filters frames on them
already (`on_device_frame` and `_on_ipv4` both check). The EMAC model fans
every transmitted frame out to all of them.

This is what makes the two servers separable *in the model* rather than only
in our naming: with two peers registered, one can hold an established
connection to :502 while the other holds one to :80, and disabling either
leaves the other's round trip untouched.

WHAT IT MUST GET RIGHT. lwIP validates checksums and sequence numbers, so the
IP header checksum and the TCP checksum over its pseudo-header have to be
correct or every segment is dropped silently -- which looks exactly like a
device that is not listening. That is the only fiddly part, and it is the part
worth testing without an emulator.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from halucinator import hal_log

log = hal_log.getHalLogger()

ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
IP_PROTO_TCP = 6
IP_PROTO_ICMP = 1

ARP_REQUEST = 1
ARP_REPLY = 2

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

BROADCAST = b"\xff" * 6

# The peers' identities. Locally-administered MACs, and addresses on the same
# /24 as the device's factory default of 10.0.0.1. The DEFAULT peer keeps the
# exact MAC and IP it always had, so the Modbus path is byte-identical to
# before this file learned to hold more than one machine.
PEER_MAC = bytes.fromhex(os.environ.get("HAL_ADAM_PEER_MAC", "0200005e1002"))
PEER_IP = os.environ.get("HAL_ADAM_PEER_IP", "10.0.0.2")
DEVICE_IP = os.environ.get("HAL_ADAM_DEVICE_IP", "10.0.0.1")

#: One entry per modelled machine on the segment. A name that is not in here
#: raises rather than silently aliasing the default -- a second "peer" that is
#: really the first one under another name is exactly the collapse this whole
#: mechanism exists to prevent.
PEER_IDENTITIES = {
    "default": (PEER_MAC, PEER_IP),
    "http": (bytes.fromhex(os.environ.get("HAL_ADAM_HTTP_PEER_MAC",
                                          "0200005e1003")),
             os.environ.get("HAL_ADAM_HTTP_PEER_IP", "10.0.0.3")),
}


def ip_to_bytes(text: str) -> bytes:
    return bytes(int(p) for p in text.split("."))


def checksum(data: bytes) -> int:
    """The one's-complement sum every IP-family header uses."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i:i + 2], "big")
                for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class NetPeer:
    """A single host on the same segment as the device."""

    def __init__(self, send: Optional[Callable[[bytes], None]] = None,
                 name: str = "default") -> None:
        mac, ip = PEER_IDENTITIES[name]
        self.name = name
        self.mac = mac
        self.ip = ip_to_bytes(ip)
        self.device_ip = ip_to_bytes(DEVICE_IP)
        self.device_mac: Optional[bytes] = None
        self._send = send
        # One TCP connection.
        self.local_port = 0
        self.remote_port = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.state = "CLOSED"
        self.rx_data = bytearray()
        self.pending_tx = bytearray()
        # Retransmission state: one segment in flight, resent until acked.
        self.unacked = b""
        self.unacked_seq = 0
        self.rto = 0
        self.retransmits = 0
        self.polls = 0
        self.syn_rto = 0
        self.syn_retransmits = 0
        self.segments_in = 0
        self.segments_out = 0
        self.retry_connect = False
        self.retry_polls = 0
        self.rto_polls = int(os.environ.get("HAL_ADAM_RTO_POLLS", "400"), 0)
        # GENEROUS ON PURPOSE. Right after boot this device copies its whole
        # firmware image to the serial flash ("Backup_FW_Image success"), and
        # while it does, the stack is served rarely enough that a handful of
        # retries expire before the first request is ever looked at.
        self.rto_budget = int(os.environ.get("HAL_ADAM_RTO_BUDGET", "200"), 0)
        self.frames_in = 0
        self.frames_out = 0
        self.arp_replies = 0

    def set_send(self, send: Callable[[bytes], None]) -> None:
        self._send = send

    def ensure_send(self, send: Callable[[bytes], None]) -> None:
        """Attach the transmit path if this peer does not have one yet.

        Peers can be created after the EMAC model is built (the bridge makes
        the HTTP one when it starts), so the fan-out attaches lazily rather
        than assuming every peer existed at construction time.
        """
        if self._send is None:
            self._send = send

    def _emit(self, frame: bytes) -> None:
        self.frames_out += 1
        if self._send is not None:
            self._send(frame)

    # ---- Ethernet --------------------------------------------------------
    def _eth(self, dst: bytes, ethertype: int, payload: bytes) -> bytes:
        frame = dst + self.mac + ethertype.to_bytes(2, "big") + payload
        # Pad to the 60-byte minimum; the MAC would append the FCS.
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        return frame

    def on_device_frame(self, frame: bytes) -> None:
        """A frame the firmware transmitted. Answer it if it is ours."""
        self.frames_in += 1
        if len(frame) < 14:
            return
        dst, src = frame[0:6], frame[6:12]
        ethertype = int.from_bytes(frame[12:14], "big")
        body = frame[14:]
        if self.frames_in <= 12:
            kind = {ETH_ARP: "ARP", ETH_IPV4: "IPv4"}.get(ethertype,
                                                          "0x%04x" % ethertype)
            note = ""
            if ethertype == ETH_ARP and len(body) >= 28:
                note = " op=%d target=%s" % (
                    int.from_bytes(body[6:8], "big"),
                    ".".join(str(b) for b in body[24:28]))
            log.info("PEER saw: %s dst=%s src=%s%s", kind, dst.hex(":"),
                     src.hex(":"), note)
        if dst != BROADCAST and dst != self.mac:
            if self.frames_in <= 12:
                log.info("PEER: ignored -- not addressed to %s",
                         self.mac.hex(":"))
            return
        if ethertype == ETH_ARP:
            self._on_arp(src, body)
        elif ethertype == ETH_IPV4:
            self._on_ipv4(src, body)

    # ---- ARP -------------------------------------------------------------
    def _on_arp(self, src_mac: bytes, body: bytes) -> None:
        if len(body) < 28:
            return
        op = int.from_bytes(body[6:8], "big")
        sender_mac, sender_ip = body[8:14], body[14:18]
        target_ip = body[24:28]
        if sender_ip == self.device_ip and sender_mac != b"\x00" * 6:
            self.device_mac = sender_mac
        if op != ARP_REQUEST or target_ip != self.ip:
            return
        reply = (b"\x00\x01" + b"\x08\x00" + b"\x06\x04"
                 + ARP_REPLY.to_bytes(2, "big")
                 + self.mac + self.ip + sender_mac + sender_ip)
        self.arp_replies += 1
        self._emit(self._eth(sender_mac, ETH_ARP, reply))

    def arp_request(self) -> None:
        """Ask for the device's MAC, so a connection can be opened to it."""
        body = (b"\x00\x01" + b"\x08\x00" + b"\x06\x04"
                + ARP_REQUEST.to_bytes(2, "big")
                + self.mac + self.ip + b"\x00" * 6 + self.device_ip)
        self._emit(self._eth(BROADCAST, ETH_ARP, body))

    # ---- IPv4 / TCP ------------------------------------------------------
    def _ipv4(self, proto: int, payload: bytes) -> bytes:
        total = 20 + len(payload)
        header = bytearray(
            b"\x45\x00" + total.to_bytes(2, "big")
            + b"\x00\x00" + b"\x40\x00" + bytes([64, proto]) + b"\x00\x00"
            + self.ip + self.device_ip)
        header[10:12] = checksum(bytes(header)).to_bytes(2, "big")
        return bytes(header) + payload

    def _tcp(self, flags: int, payload: bytes = b"") -> bytes:
        header = bytearray(
            self.local_port.to_bytes(2, "big")
            + self.remote_port.to_bytes(2, "big")
            + self.snd_nxt.to_bytes(4, "big")
            + self.rcv_nxt.to_bytes(4, "big")
            + bytes([5 << 4, flags])
            + (8192).to_bytes(2, "big") + b"\x00\x00" + b"\x00\x00")
        pseudo = (self.ip + self.device_ip + b"\x00" + bytes([IP_PROTO_TCP])
                  + (len(header) + len(payload)).to_bytes(2, "big"))
        header[16:18] = checksum(pseudo + bytes(header)
                                 + payload).to_bytes(2, "big")
        return bytes(header) + payload

    def _send_tcp(self, flags: int, payload: bytes = b"") -> None:
        if self.device_mac is None:
            return
        self.segments_out += 1
        if self.segments_out <= 8:
            log.info("PEER -> device: TCP flags=0x%02x seq=0x%x len=%d",
                     flags, self.snd_nxt, len(payload))
        self._emit(self._eth(self.device_mac, ETH_IPV4,
                             self._ipv4(IP_PROTO_TCP, self._tcp(flags,
                                                                payload))))

    def connect(self, port: int, local_port: int = 40000) -> None:
        """Open a connection to one of the device's servers."""
        self.remote_port = port
        self.local_port = local_port
        self.snd_nxt = 0x1000
        self.rcv_nxt = 0
        self.state = "SYN_SENT"
        self.unacked = b""
        self.rx_data.clear()
        self.syn_rto = 0
        self.syn_retransmits = 0
        self._send_tcp(TCP_SYN)
        self.snd_nxt += 1

    def send(self, data: bytes) -> None:
        """Queue application data; sent once the connection is established."""
        self.pending_tx.extend(data)
        self._flush()

    def _flush(self) -> None:
        """Send what is queued -- one segment in flight at a time.

        A PEER WITHOUT RETRANSMISSION IS NOT A TCP PEER, and on a rehost that
        matters more than on a wire, because the device drops frames for
        reasons the wire never has: a buffer the firmware has not recycled yet,
        an interrupt that arrived while the stack was mid-update. Without this
        the first lost segment ends the conversation and the symptom is a
        device that completes a handshake and then says nothing -- which reads
        like an unimplemented server.
        """
        if self.state != "ESTABLISHED" or self.unacked or not self.pending_tx:
            return
        payload = bytes(self.pending_tx)
        self.pending_tx.clear()
        self.unacked = payload
        self.unacked_seq = self.snd_nxt
        self.rto = 0
        self.retransmits = 0
        self._send_tcp(TCP_PSH | TCP_ACK, payload)
        self.snd_nxt = (self.snd_nxt + len(payload)) & 0xFFFFFFFF

    def on_poll(self) -> None:
        """Called from the device's own pump; retransmit if nothing was acked."""
        self.polls += 1
        if self.polls % 20000 == 0:
            log.info("PEER: poll %d -- state=%s unacked=%d rto=%d "
                     "retransmits=%d pending=%d", self.polls, self.state,
                     len(self.unacked), self.rto, self.retransmits,
                     len(self.pending_tx))
        # THE HANDSHAKE NEEDS RETRIES TOO. A SYN sent once, into a device that
        # is still copying its firmware image to serial flash, is a connection
        # that never opens -- and the failure looks identical to a device with
        # no server listening.
        if self.state == "CLOSED" and self.retry_connect:
            self.retry_polls += 1
            if self.retry_polls >= self.rto_polls * 4:
                self.retry_polls = 0
                self.connect(self.remote_port, self.local_port + 1)
            return
        if self.state == "SYN_SENT":
            self.syn_rto += 1
            if self.syn_rto >= self.rto_polls:
                self.syn_rto = 0
                self.syn_retransmits += 1
                if self.syn_retransmits <= self.rto_budget:
                    log.info("PEER: retransmit SYN #%d", self.syn_retransmits)
                    saved, self.snd_nxt = self.snd_nxt, self.snd_nxt - 1
                    self._send_tcp(TCP_SYN)
                    self.snd_nxt = saved
            return
        if not self.unacked:
            return
        self.rto += 1
        if self.rto < self.rto_polls:
            return
        self.rto = 0
        self.retransmits += 1
        if self.retransmits > self.rto_budget:
            return
        if self.retransmits <= 3 or self.retransmits % 25 == 0:
            log.info("PEER: retransmit #%d of %d bytes at seq=0x%x",
                     self.retransmits, len(self.unacked), self.unacked_seq)
        saved, self.snd_nxt = self.snd_nxt, self.unacked_seq
        self._send_tcp(TCP_PSH | TCP_ACK, self.unacked)
        self.snd_nxt = saved

    def _on_ipv4(self, src_mac: bytes, body: bytes) -> None:
        if len(body) < 20:
            return
        ihl = (body[0] & 0x0F) * 4
        proto = body[9]
        src_ip, dst_ip = body[12:16], body[16:20]
        if dst_ip != self.ip or proto != IP_PROTO_TCP:
            return
        self.device_mac = src_mac
        self._on_tcp(body[ihl:])

    def _on_tcp(self, seg: bytes) -> None:
        if len(seg) < 20:
            return
        sport = int.from_bytes(seg[0:2], "big")
        dport = int.from_bytes(seg[2:4], "big")
        seq = int.from_bytes(seg[4:8], "big")
        flags = seg[13]
        offset = (seg[12] >> 4) * 4
        payload = seg[offset:]
        names = [n for b, n in ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"),
                                (0x01, "FIN"), (0x04, "RST"))
                 if flags & b]
        # Log every segment that carries something, and the first few bare
        # ACKs. A stalled exchange produces hundreds of identical duplicate
        # ACKs, and logging all of them buries the one line that matters.
        self.segments_in += 1
        if payload or self.segments_in <= 12:
            log.info("PEER: TCP %d->%d [%s] seq=0x%x ack=0x%x len=%d "
                     "win=%d (state %s, our snd_nxt=0x%x)", sport, dport,
                     "|".join(names) or "-", seq,
                     int.from_bytes(seg[8:12], "big"), len(payload),
                     int.from_bytes(seg[14:16], "big"), self.state,
                     self.snd_nxt)
        if dport != self.local_port or sport != self.remote_port:
            return

        if flags & TCP_RST:
            # NOT FATAL. A reset means nothing is listening *yet*: the bridge
            # opens its connection as soon as the device has an address, and on
            # a slow boot the Modbus server binds well after that.
            self.state = "CLOSED"
            self.retry_connect = True
            self.retry_polls = 0
            log.info("PEER: reset by the device -- nothing listening on %d "
                     "yet, will retry", self.remote_port)
            return
        ack = int.from_bytes(seg[8:12], "big")
        if self.unacked and \
                ((ack - (self.unacked_seq + len(self.unacked))) &
                 0xFFFFFFFF) < 0x80000000:
            self.unacked = b""
            self._flush()
        if self.state == "SYN_SENT" and flags & TCP_SYN and flags & TCP_ACK:
            self.rcv_nxt = (seq + 1) & 0xFFFFFFFF
            self.state = "ESTABLISHED"
            self._send_tcp(TCP_ACK)
            self._flush()
            return
        if payload:
            # Lossless and in-order, so anything that arrives is the next thing.
            self.rcv_nxt = (seq + len(payload)) & 0xFFFFFFFF
            self.rx_data.extend(payload)
            self._send_tcp(TCP_ACK)
        if flags & TCP_FIN:
            self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFFFFFF
            self._send_tcp(TCP_ACK | TCP_FIN)
            self.snd_nxt += 1
            self.state = "CLOSED"

    def take_rx(self) -> bytes:
        data = bytes(self.rx_data)
        self.rx_data.clear()
        return data


_PEERS: Dict[str, NetPeer] = {}


def get_peer(name: str = "default") -> NetPeer:
    """The modelled machine called ``name``. Created on first use.

    ``name`` must be a key of :data:`PEER_IDENTITIES`; an unknown name raises
    instead of falling back to the default, because a peer that silently
    aliases another is not a second peer.
    """
    if name not in PEER_IDENTITIES:
        raise KeyError("no modelled peer %r; known peers: %s"
                       % (name, ", ".join(sorted(PEER_IDENTITIES))))
    peer = _PEERS.get(name)
    if peer is None:
        peer = _PEERS[name] = NetPeer(name=name)
    return peer


def all_peers() -> List[NetPeer]:
    """Every machine currently modelled on the segment, in creation order.

    The EMAC hands each transmitted frame to all of them; each ignores what is
    not addressed to its own MAC/IP, exactly as a real NIC would.
    """
    return list(_PEERS.values())


def reset_peers() -> None:
    """Drop every modelled machine. For tests only."""
    _PEERS.clear()
