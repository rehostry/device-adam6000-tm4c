# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The attack: unauthenticated Modbus/TCP writes an output on a live I/O module.

WHAT THE DEVICE IS. An Advantech ADAM-6050 is a remote digital-I/O module: 12
inputs and 6 outputs on a DIN rail, wired to real things. Its Modbus/TCP server
on port 502 is how a PLC or SCADA host reads those inputs and drives those
outputs.

WHAT THE VULNERABILITY IS. **Modbus/TCP has no authentication.** None: no
credential, no session, no signature -- the protocol predates the idea that the
network might be hostile, and the ADAM-6000's server implements it faithfully.
Anyone who can open a TCP connection to port 502 can read every input and write
every output. On this device an output coil is a relay contact, so a single
five-byte request is a physical action.

That is not a defect in this firmware; it is what Modbus is. The finding is that
this is a device sold to sit on a plant network and drive equipment, and its
control interface is a socket that will do what anyone tells it.

THE ORACLE IS A SUSTAINED CONVERSATION WITH ONE GUEST. Forty requests, every
one of them different in transaction id, unit id, function code, address and
quantity, down a single TCP connection to a single booted device. Every reply
has to carry its own request's transaction and unit id back, echo its function
byte (plain when the device can answer, with the error bit when it cannot), and
-- when it answers with data -- be sized from the quantity field that request
chose. All of it travels the whole modelled stack: the firmware's Modbus server
-> lwIP -> the EMAC's transmit descriptor ring -> an Ethernet frame -> the
modelled peer's TCP/IPv4 -> this socket. Nothing short-circuits, and nothing on
the host decides the answer.

WHY N > 1 IS THE WHOLE POINT. This module used to boot a fresh device for each
probe and ask it one question. `landed = all(checks)` looked like a strong
conjunction and was not: each clause was answered by a different device on its
first exchange, so the oracle could not have noticed that no guest ever answered
a second question -- which, for three separate reasons in the MAC model, none of
them did. See STATUS.md.

A negative control runs throughout: function code 0x41 is not a Modbus function
and must always come back as an exception with code 1 (illegal function), while
a supported function aimed at an address this module does not have must come
back as code 2 (illegal data address). A rehost that echoed bytes, or a bridge
answering on the firmware's behalf, would not tell those apart.

THE FALSIFICATION KNOB. Both controls above run *inside* every attack arm, so
neither is something a reader can turn off from outside and watch the verdict
collapse. ``--control=withhold`` is that external knob: the device boots
identically, lwIP reaches "IP ready." identically, the harness attaches to the
bridge identically -- and then the Modbus request frames, the one stimulus the
whole verdict rests on, are never put on the wire. The socket is read anyway,
so an emulator or a bridge that had learned to answer on the firmware's behalf
would still be caught producing replies to questions nobody asked. Under the
knob `sustained_round_trips` must be 0, `landed` false, the milestone M3, and
the process must exit non-zero.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

from . import paths, spawn

MODBUS_UNIT = 1

# Function codes.
FN_READ_COILS = 0x01
FN_READ_DISCRETE_INPUTS = 0x02
FN_READ_HOLDING = 0x03
FN_WRITE_SINGLE_COIL = 0x05
# Not implemented by this device -- the negative control.
FN_BOGUS = 0x41

COIL_ON = 0xFF00
COIL_OFF = 0x0000

# The output coil the attack drives. An ADAM-6050 has six outputs (DO0..DO5).
TARGET_COIL = int(os.environ.get("HAL_ADAM_TARGET_COIL", "0"), 0)

# The external falsification knob. An UNRECOGNISED value must never fall
# through to the real attack -- a mistyped control that quietly runs the live
# path reads as "the control does not discriminate", which is damning and false
# (playbook §2.200). `CONTROL_MODES` is the whole authority; anything else
# raises, and argparse `choices=` refuses it at the command line.
CONTROL_MODES = ("none", "withhold")

# WHICH LINKS AN ARM MAY TOUCH -- the M5 independence lever. `modbus` never
# opens the HTTP bridge socket and `http` never sends a Modbus frame, so each
# arm has to reach M4 on its own. This is the operational test, and it is the
# only one a harness can actually run.
INTERFACE_SETS = ("both", "modbus", "http")

# HOW MANY HTTP EXCHANGES, and why this number. The httpd answers
# `Connection: close` and sends FIN, so **every round is its own TCP
# connection with its own handshake** -- a much stronger repeat than N messages
# down one socket, and a server that had gone deaf could not complete round 2's
# handshake at all. Six rounds walks the 404/501/200 cycle twice, so every
# status the parser can choose is demanded more than once and no two
# consecutive rounds expect the same answer.
HTTP_ROUNDS = int(os.environ.get("HAL_ADAM_HTTP_ROUNDS", "6"), 0)
MIN_HTTP_ROUNDS = 3          # one full cycle; below this the cycle is untested

# Derived from this device's own timings, not guessed: a warm HTTP exchange on
# this rehost takes ~3.3 s wall (measured, eight consecutive rounds), and the
# first one after boot takes ~30 s because the peer's SYN and first segment are
# retransmitted while the firmware is still copying its image to serial flash.
# 150 s therefore leaves ~5x headroom on the slow first round and ~45x on the
# rest. A bound is a classifier: too tight and a working server reads as dead.
HTTP_FIRST_TIMEOUT = float(os.environ.get("HAL_ADAM_HTTP_FIRST_TIMEOUT", "150"))
HTTP_TIMEOUT = float(os.environ.get("HAL_ADAM_HTTP_TIMEOUT", "90"))


def mbap(txn: int, pdu: bytes, unit: int = MODBUS_UNIT) -> bytes:
    """Wrap a PDU in the Modbus/TCP header: transaction, protocol, length, unit."""
    return struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit) + pdu


class DeviceScenario:
    """Boots the rehost with its Ethernet bridge and speaks Modbus to it."""

    def __init__(self, bridge_port: int = spawn.BRIDGE_PORT,
                 python: Optional[str] = None,
                 log_dir: Optional[str] = None) -> None:
        self.bridge_port = bridge_port
        self.python = python or os.environ.get("HAL_PY") or sys.executable
        # ONE LOG PER RUN, NOT ONE PER MACHINE. The emulator log is where
        # `console()` reads the firmware's own output, so two arms sharing
        # /tmp/adam6000_tm4c_attack.log grade each other's boot -- which is
        # exactly how a control arm can come out looking like the attack arm.
        self.log_dir = log_dir or os.environ.get("HAL_ADAM_LOG_DIR") or "/tmp"
        self.host = "127.0.0.1"
        self._procs: List[subprocess.Popen] = []
        self.sock: Optional[socket.socket] = None
        self.txn = 0
        self.transcript: List[Dict[str, str]] = []
        self.log = os.path.join(self.log_dir, "adam6000_tm4c_attack.log")

    # ---- process management ----------------------------------------------
    def _spawn(self, argv, cwd, env, logpath) -> subprocess.Popen:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=open(logpath, "w"),
                             stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        self._procs.append(p)
        return p

    def teardown(self) -> None:
        """Kill ONLY what this scenario started -- never a global pkill
        (playbook §2.10): other sessions run their own emulators."""
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        for p in self._procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except Exception:            # noqa: BLE001
                    p.kill()
        self._procs.clear()

    def shutdown(self) -> None:
        self.teardown()

    def _log_has(self, needle: str) -> bool:
        try:
            return needle in open(self.log, errors="replace").read()
        except OSError:
            return False

    def console(self) -> List[str]:
        """The firmware's own boot output, as the UART model logged it."""
        out = []
        try:
            for line in open(self.log, errors="replace"):
                if "CONSOLE " in line:
                    out.append(line.split("CONSOLE ", 1)[1].rstrip())
        except OSError:
            pass
        return out

    # ---- boot -------------------------------------------------------------
    def boot(self, on_stage: Callable, attach: bool = True) -> bool:
        """Boot the guest; with ``attach`` also open the Modbus client socket.

        `attach=False` matters for the M5 independence arm. Readiness is the
        firmware's own "IP ready." in the log, not the socket -- so the HTTP-only
        arm can decline to open a Modbus connection at all. It used to open one
        regardless, which meant that arm still made the device complete a TCP
        handshake on tcp/502, and "this arm never touches Modbus" was very
        slightly untrue. An independence claim has to be exactly true.
        """
        if not paths.firmware_present():
            on_stage("error", note="firmware not found at %s -- regenerate it "
                                   "with tools/extract_firmware.py"
                                   % paths.firmware_bin())
            return False
        # Derived from the bridge port so several devices can run at once --
        # `run_attack` boots one per probe, and a shared rx/tx port makes all
        # but the first fail to bind and never reach "IP ready.".
        argv = spawn.spawn_argv(python=self.python, emulator="unicorn",
                                bridge=True,
                                rx_port=self.bridge_port + 1000,
                                tx_port=self.bridge_port + 2000)
        env = spawn.spawn_env(extra={
            "PYTHONUNBUFFERED": "1",
            "HAL_ADAM_BRIDGE_PORT": str(self.bridge_port),
        })
        on_stage("boot", note="booting the ADAM-6050 firmware ...")
        p = self._spawn(argv, spawn.spawn_cwd(), env, self.log)

        # The readiness marker is the firmware's own: lwIP announcing itself.
        # macOS has no timeout(1), so the bound is here.
        deadline = time.time() + 420
        while time.time() < deadline:
            if p.poll() is not None:
                on_stage("error", note="HALucinator exited during boot "
                                       "(see %s)" % self.log)
                return False
            if self._log_has("IP ready."):
                break
            time.sleep(2)
        else:
            on_stage("error", note="the firmware never reached 'IP ready.'")
            return False
        on_stage("boot", note="firmware is up: lwIP reports 'IP ready.'")

        if not attach:
            on_stage("boot", note="ARM: not attaching to the Modbus bridge -- "
                                  "no connection is opened to tcp/502")
            return True

        for _ in range(120):
            try:
                self.sock = socket.create_connection(
                    (self.host, self.bridge_port), timeout=5)
                self.sock.settimeout(None)
                break
            except OSError:
                time.sleep(1)
        if self.sock is None:
            on_stage("error", note="could not attach to tcp/%d"
                               % self.bridge_port)
            return False
        on_stage("boot", note="Modbus/TCP bridged on tcp/%d"
                          % self.bridge_port)
        return True

    # ---- Modbus -----------------------------------------------------------
    def request(self, pdu: bytes, timeout: float = 90.0) -> Optional[bytes]:
        """Send one Modbus PDU; return the response PDU, or None on timeout.

        Completion is the MBAP length field, not a fixed wait: the response
        arrives whenever the firmware's own stack gets round to it, and a fixed
        sleep would either truncate it or waste the difference.
        """
        assert self.sock is not None
        self.txn = (self.txn + 1) & 0xFFFF
        frame = mbap(self.txn, pdu)
        self.sock.sendall(frame)
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(0.5, deadline - time.time()))
            try:
                data = self.sock.recv(512)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            buf.extend(data)
            if len(buf) >= 6:
                need = 6 + struct.unpack(">H", bytes(buf[4:6]))[0]
                if len(buf) >= need:
                    break
        if len(buf) < 8:
            self.transcript.append({"sent": frame.hex(), "recv": buf.hex()})
            return None
        self.transcript.append({"sent": frame.hex(), "recv": bytes(buf).hex()})
        return bytes(buf[7:])

    def exchange(self, txn: int, unit: int, pdu: bytes,
                 timeout: float = 30.0) -> Optional[bytes]:
        """One request/response, with the **whole** ADU returned.

        `request` above hides the MBAP header, which is exactly the part that
        makes a reply attributable to its own request: an oracle that only ever
        sees the PDU cannot tell a fresh answer from a stale one still sitting
        in a buffer. Everything here that varies per request -- the transaction
        id, the unit id, the function code -- has to come back.
        """
        assert self.sock is not None
        frame = mbap(txn, pdu, unit=unit)
        self.sock.sendall(frame)
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(0.5, deadline - time.time()))
            try:
                data = self.sock.recv(512)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            buf.extend(data)
            if len(buf) >= 6:
                need = 6 + struct.unpack(">H", bytes(buf[4:6]))[0]
                if len(buf) >= need:
                    break
        self.transcript.append({"sent": frame.hex(), "recv": bytes(buf).hex()})
        return bytes(buf) if len(buf) >= 8 else None

    def listen_only(self, timeout: float = 8.0) -> Optional[bytes]:
        """The withheld-stimulus arm of `exchange`: read, but never send.

        Everything else is identical -- same socket, same booted guest, same
        completion rule on the MBAP length field. The ONLY difference is that
        no request frame is transmitted. Anything that comes back here is a
        reply to a question nobody asked, so the read is kept rather than
        skipped: it is what would catch a bridge answering on the firmware's
        behalf.
        """
        assert self.sock is not None
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(0.5, deadline - time.time()))
            try:
                data = self.sock.recv(512)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            buf.extend(data)
            if len(buf) >= 6:
                need = 6 + struct.unpack(">H", bytes(buf[4:6]))[0]
                if len(buf) >= need:
                    break
        self.transcript.append({"sent": "", "recv": bytes(buf).hex()})
        return bytes(buf) if len(buf) >= 8 else None

    def read_coils(self, start: int, count: int) -> Optional[List[int]]:
        pdu = self.request(struct.pack(">BHH", FN_READ_COILS, start, count))
        if not pdu or pdu[0] != FN_READ_COILS or len(pdu) < 2:
            return None
        data = pdu[2:2 + pdu[1]]
        return [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]

    def write_coil(self, coil: int, on: bool) -> bool:
        value = COIL_ON if on else COIL_OFF
        pdu = self.request(struct.pack(">BHH", FN_WRITE_SINGLE_COIL, coil,
                                       value))
        # A Modbus write echoes the request back on success.
        return bool(pdu and pdu[0] == FN_WRITE_SINGLE_COIL
                    and struct.unpack(">H", pdu[3:5])[0] == value)

    # ---- state, for the panel --------------------------------------------
    def read_state(self) -> Dict:
        """What the device says about itself -- from its console, not Modbus.

        NOT A MODBUS READ, because there is nothing to read: this module's I/O
        profile lives in a serial flash the vendor image does not carry, so it
        reports zero I/O points and every data address is illegal. Everything
        here is the firmware's own console output. (This used to be justified by
        the device only answering once per boot -- that was a defect in the MAC
        model, not a property of the firmware, and it is fixed.)
        """
        facts: Dict = {"ip": None, "mac": None, "model": None,
                       "io_points": None, "profile_in_serial_flash": None,
                       "stack_up": False}
        for line in self.console():
            if "MACID:" in line:
                facts["mac"] = line.split("MACID:", 1)[1].strip()
            elif "g_ui32IPAddr=" in line:
                raw = line.split("g_ui32IPAddr=", 1)[1].split(",")[0].strip()
                try:
                    value = int(raw, 16)
                    facts["ip"] = ".".join(str((value >> shift) & 0xFF)
                                           for shift in (0, 8, 16, 24))
                except ValueError:
                    pass
            elif "g_usModel = " in line:
                facts["model"] = line.split("=", 1)[1].strip()
            elif "ucTotal_StatusPins = " in line:
                facts["io_points"] = line.split("=", 1)[1].strip()
            elif "GetDevInfo() Err" in line:
                facts["profile_in_serial_flash"] = "missing (flash is blank)"
            elif "IP ready." in line:
                facts["stack_up"] = True
        facts["console_tail"] = self.console()[-6:]
        return facts

    # ---- the attack -------------------------------------------------------
    def attack(self, on_stage: Optional[Callable] = None) -> Dict:
        """A sustained conversation with **one** guest, and what came back.

        ONE GUEST, MANY QUESTIONS. Asking a freshly-booted device a single
        question and grading the answer cannot distinguish a working server
        from one that answers once and dies -- and this rehost was the second
        kind, for a reason that was entirely in the MAC model (see
        `peripheral_models/tiva_emac.py`). So the probe set below runs down one
        TCP connection to one guest, and the count that survives is reported.
        """
        return converse(self, on_stage)


# Each probe: a label, the PDU, the function byte the device should echo with
# the error bit set, and the exception code it should choose.
PROBES: List[Tuple[str, bytes, int, int]] = [
    ("read coils", struct.pack(">BHH", FN_READ_COILS, 0, 8), 0x81, 2),
    ("read discrete inputs",
     struct.pack(">BHH", FN_READ_DISCRETE_INPUTS, 0, 12), 0x82, 2),
    ("read holding registers",
     struct.pack(">BHH", FN_READ_HOLDING, 0, 2), 0x83, 2),
    ("write single coil",
     struct.pack(">BHH", FN_WRITE_SINGLE_COIL, 0, COIL_OFF), 0x85, 2),
    # The negative control: 0x41 is not a Modbus function code at all, and it
    # must be refused differently from a real one aimed at a bad address.
    ("bogus function 0x41", struct.pack(">BHH", FN_BOGUS, 0, 1), 0xC1, 1),
]

# HOW MANY REQUESTS ONE GUEST MUST SURVIVE, and why this number. The firmware's
# transmit ring is **24 descriptors** -- its own wrap constant, `rsb r1, r1,
# #0x18` at 0x0001CC5E and `cmp sb, #0x18` at 0x0001CCDC -- and each Modbus
# exchange costs at least one transmit descriptor (the response) plus the ACKs
# around it. A run of 40 therefore laps that ring several times over, which is
# precisely what the old rehost could not do: nothing was ever reclaimed, so it
# fell silent at the first lap. Anything at or below 24 could pass on a ring
# that is never recycled, so it would not be a test.
SUSTAINED_N = int(os.environ.get("HAL_ADAM_SUSTAINED_N", "40"), 0)
TX_RING_DESCRIPTORS = 24


def _probe_for(i: int) -> Tuple[int, int, bytes, int, int, str]:
    """Request number ``i``: transaction id, unit id, PDU, and what it must
    come back as.

    FRESH CONTENT EVERY TIME. The transaction id, the unit id, the function
    code and the address all vary with ``i``, and all four are checked in the
    reply. A device that had stopped listening and was replaying a buffered
    answer would fail on the first of them; so would a host-side bridge that
    had learned to answer on the firmware's behalf.
    """
    label, pdu, want_fc, want_code = PROBES[i % len(PROBES)]
    txn = (0xB100 + i * 37) & 0xFFFF
    unit = (i % 247) + 1
    # Walk the address space as well, so no two requests of the same function
    # are byte-identical. Every address on this module is illegal (its I/O
    # profile is in the blank serial flash), so the expected answer does not
    # change -- but the bytes on the wire do.
    addr = (i * 29) & 0x7FFF
    fc = pdu[0]
    if fc == FN_WRITE_SINGLE_COIL:
        # Keep the value legal (0x0000 / 0xFF00) so the refusal stays
        # "illegal data address" and not "illegal data value".
        body = struct.pack(">BHH", fc, addr, COIL_ON if i % 2 else COIL_OFF)
    elif fc == FN_BOGUS:
        body = struct.pack(">BHH", fc, addr, 1)
    else:
        body = struct.pack(">BHH", fc, addr, (i % 8) + 1)
    return txn, unit, body, want_fc, want_code, label


def _check_success(fc: int, request_pdu: bytes,
                   adu: bytes) -> Optional[str]:
    """Is this successful reply well formed *for the request that caused it*?

    THIS IS WHERE A REPLAY WOULD DIE. The byte count of a read response is not
    a constant: it is computed from the quantity field of the request, and this
    run picks a different quantity for almost every request. A canned answer,
    or a stale one still in a buffer, cannot satisfy it -- and neither can a
    host-side bridge that has not parsed the request.

    Returns None if the reply is sound, or a description of what is wrong.
    """
    addr, qty = struct.unpack(">HH", request_pdu[1:5])
    body = adu[7:]                               # the response PDU
    if fc in (FN_READ_COILS, FN_READ_DISCRETE_INPUTS):
        want = (qty + 7) // 8                    # bits, packed
    elif fc == FN_READ_HOLDING:
        want = qty * 2                           # 16-bit registers
    elif fc == FN_WRITE_SINGLE_COIL:
        # A write echoes the request's address and value verbatim.
        if len(body) != 5:
            return "write echo is %d PDU bytes, expected 5" % len(body)
        got_addr, got_val = struct.unpack(">HH", body[1:5])
        if (got_addr, got_val) != (addr, qty):
            return ("write echo is addr 0x%04x value 0x%04x, sent addr 0x%04x "
                    "value 0x%04x" % (got_addr, got_val, addr, qty))
        return None
    else:
        return "function 0x%02x answered successfully; it is not a Modbus " \
               "function and must be refused" % fc
    if len(body) < 2:
        return "response PDU is %d bytes" % len(body)
    got = body[1]
    if got != want:
        return ("byte count is %d, but %d were asked for -- expected %d"
                % (got, qty, want))
    if len(body) != 2 + want:
        return ("byte count says %d but the PDU carries %d"
                % (want, len(body) - 2))
    return None


def converse(dev: "DeviceScenario", on_stage: Optional[Callable] = None,
             count: int = SUSTAINED_N, control: str = "none") -> Dict:
    """Ask ONE booted guest ``count`` questions down one connection.

    Returns the graded result. `run_attack` and the panel both go through here,
    so there is one oracle and not two.

    ``control``:
      ``"none"``     the real attack.
      ``"withhold"`` the external falsification control: the request frames are
                     never transmitted. The guest is booted, the socket is open
                     and is still read -- only the stimulus is withheld. Must
                     yield ``booted: true`` with ``landed: false``.

    The oracle below is UNCHANGED between the two arms: the same checks are
    evaluated on whatever came back. A control that scored itself with a
    different predicate would not be a control.
    """
    if control not in CONTROL_MODES:
        raise ValueError("unknown control mode %r; expected one of %s"
                         % (control, ", ".join(CONTROL_MODES)))

    def _stage(name: str, **kw) -> None:
        if on_stage:
            on_stage(name, **kw)

    checks: Dict[str, bool] = {}
    detail: Dict[str, str] = {}
    ok_streak = 0
    first_miss: Optional[int] = None
    replayed = False
    misattributed = False
    wrong_fc = False
    malformed: List[str] = []
    bogus_not_refused = False
    seen_codes: Dict[int, int] = {}
    successes = 0
    exceptions = 0
    previous: Optional[bytes] = None

    if control == "withhold":
        _stage("request", note="CONTROL: the %d Modbus requests are NOT "
                               "transmitted; the socket is read anyway, so a "
                               "reply to a question nobody asked would still "
                               "be caught" % count)
    else:
        _stage("request", note="%d unauthenticated Modbus requests down one "
                               "connection to one guest -- no credential, no "
                               "session, no handshake beyond TCP" % count)
    for i in range(count):
        txn, unit, pdu, _want_fc, want_code, label = _probe_for(i)
        if control == "withhold":
            # The withheld stimulus, and NOTHING else: same guest, same open
            # socket, same completion rule -- the request bytes simply never
            # leave the host.
            adu = dev.listen_only()
        else:
            adu = dev.exchange(txn, unit, pdu)
        if adu is None or len(adu) < 9:
            first_miss = i
            detail["request %02d %s" % (i, label)] = "<nothing>"
            _stage("request", note="request %d went unanswered" % i)
            break
        got_txn = struct.unpack(">H", adu[0:2])[0]
        if got_txn != txn or adu[6] != unit:
            misattributed = True
            first_miss = i
            detail["request %02d %s" % (i, label)] = (adu.hex()
                                                      + "   MISATTRIBUTED")
            break
        if adu == previous:
            replayed = True
        previous = adu
        fc = pdu[0]
        note = ""
        if adu[7] == fc | 0x80:
            # An exception: function byte echoed with the error bit set.
            exceptions += 1
            seen_codes[adu[8]] = seen_codes.get(adu[8], 0) + 1
            note = "exception %d" % adu[8]
            if fc == FN_BOGUS and adu[8] != want_code:
                bogus_not_refused = True
                note += "  (0x41 must be refused as illegal function)"
        elif adu[7] == fc:
            # A SUCCESSFUL ANSWER, which this device does give for some
            # addresses -- see _check_success. Not every address on this
            # module is illegal, and an oracle that insisted on an exception
            # would fail on the firmware being MORE capable than expected.
            successes += 1
            if fc == FN_BOGUS:
                bogus_not_refused = True     # 0x41 must never succeed
            problem = _check_success(fc, pdu, adu)
            if problem:
                malformed.append("request %d: %s" % (i, problem))
                note = "malformed success: " + problem
            else:
                note = "answered, %d PDU bytes" % (len(adu) - 7)
        else:
            wrong_fc = True
            note = ("neither 0x%02x nor 0x%02x -- got 0x%02x"
                    % (fc, fc | 0x80, adu[7]))
        ok_streak += 1
        detail["request %02d %s" % (i, label)] = "%s   %s" % (adu.hex(), note)

    # THE COUNT IS THE HEADLINE, and it is a check, not a footnote.
    checks["answered %d consecutive requests on one guest" % count] = (
        ok_streak >= count)
    checks["every reply carried its own request's transaction and unit id"] = (
        not misattributed and ok_streak > 0)
    checks["no reply was a repeat of the one before it"] = (
        not replayed and ok_streak > 0)
    checks["every reply's function byte is its request's, plain or with the "
           "error bit"] = not wrong_fc and ok_streak > 0
    # THE STRUCTURE IS SIZED FROM THE REQUEST. A successful read's byte count
    # is computed from the quantity field this run chose, so a canned or
    # replayed answer cannot satisfy it.
    checks["successful answers are sized from the request's own quantity "
           "field"] = not malformed and ok_streak > 0
    # The negative control: 0x41 is not a Modbus function, and a real parser
    # refuses it differently from a supported function aimed at a bad address.
    checks["0x41 is always refused as illegal function (1)"] = (
        not bogus_not_refused and seen_codes.get(1, 0) > 0)
    checks["a real parser: unsupported (1) and unusable (2) differ"] = (
        seen_codes.get(1, 0) > 0 and seen_codes.get(2, 0) > 0)
    # THE RING WAS RECYCLED. Below 24 exchanges the transmit ring need never
    # have wrapped, so the sustained result would prove nothing about reclaim.
    checks["the transmit ring was lapped (>%d exchanges)"
           % TX_RING_DESCRIPTORS] = ok_streak > TX_RING_DESCRIPTORS

    console = "\n".join(dev.console())
    checks["the module reports no I/O profile, and says why"] = (
        "GetDevInfo() Err" in console and "g_usModel = 255" in console
        and "ucTotal_StatusPins = 0" in console)
    checks["the stack is the firmware's own"] = (
        "IP ready." in console and "ip=100000a" in console)

    # THE SEAM, named for what it is. Bytes IN: `count` Modbus/TCP PDUs from an
    # anonymous peer, every one of them different, down a single TCP connection
    # to a single guest. Bytes OUT: the vendor's own Modbus parser's replies --
    # each carrying back that request's transaction id and unit id, echoing its
    # function byte (plain when it can answer, with the error bit when it
    # cannot), sizing successful answers from the quantity field this run chose,
    # and CHOOSING between exception codes: illegal function (1) for 0x41, which
    # is not a Modbus function at all, illegal data address (2) for a supported
    # function aimed at an address this module does not have. Every one of them
    # crossed lwIP, the EMAC transmit ring, an Ethernet frame and the modelled
    # peer's TCP/IPv4. The console lines ("IP ready.", the model/pin counts) are
    # M2/M3 corroboration and are NOT the seam.
    modbus_round_trip = bool(
        ok_streak >= count
        and ok_streak > TX_RING_DESCRIPTORS
        and not misattributed and not replayed
        and not wrong_fc and not malformed and not bogus_not_refused
        and checks["a real parser: unsupported (1) and unusable (2) differ"])
    _stage("request", note="%d/%d answered; first unanswered request: %s"
                           % (ok_streak, count,
                              "none" if first_miss is None else first_miss))
    return {"booted": "IP ready." in console,
            "landed": all(checks.values()),
            "control_mode": control,
            "modbus_round_trip": modbus_round_trip,
            # THE COUNT, in the result itself.
            "sustained_round_trips": ok_streak,
            "requests_attempted": count,
            "first_unanswered_request": first_miss,
            "tx_ring_descriptors": TX_RING_DESCRIPTORS,
            "answers_with_data": successes,
            "answers_that_were_exceptions": exceptions,
            "exception_codes_seen": seen_codes,
            "malformed_answers": malformed,
            "checks": checks,
            "responses": detail}


# ---------------------------------------------------------------------------
# The HTTP arm
# ---------------------------------------------------------------------------
# WHY THIS ORACLE IS NOT A COPY OF THE MODBUS ONE. The Modbus oracle asserts
# "no reply was a repeat of the one before it", which it can, because every
# Modbus reply carries back that request's own transaction id. **This server
# does not echo anything of the request**: two 404s are byte-identical, and a
# borrowed `replayed` term would score a perfectly working httpd at zero. (A
# sibling device in this fleet lost a genuine result to exactly that import.)
#
# What this server DOES do is *choose*, from bytes the attacker supplies, among
# three answers its own code holds -- and compute the length of one of them:
#
#   GET /<nonce>       -> 404 File not found     (a URI it does not have)
#   ZORK-<nonce> /     -> 501 Not implemented    (a method it does not know)
#   GET /              -> 200 OK + Content-Length: N + exactly N body bytes
#
# That is the same discrimination argument the Modbus arm rests on (exception 1
# for an unsupported function vs exception 2 for an unusable address), and it is
# the attributor here: the shapes are cycled so **no two consecutive rounds
# expect the same status**, which a stuck or replaying server cannot satisfy.
# Nothing host-side parses HTTP -- the bridge and the peer move bytes -- and the
# root page, the status lines and the `Server:` banner are all in the firmware
# image (the page at image offset 0x5e65c) and in no host-side file.

#: label, request template (``%N%`` is the per-round nonce), expected status.
HTTP_SHAPES: List[Tuple[str, str, int]] = [
    ("absent URI  -> 404",
     "GET /nosuchfile-%N% HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n", 404),
    ("unknown method -> 501",
     "ZORK%N% / HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n", 501),
    ("root page  -> 200",
     "GET / HTTP/1.0\r\nHost: 10.0.0.1\r\nX-Probe-Nonce: %N%\r\n\r\n", 200),
]


def _http_nonce(run_id: int, i: int) -> str:
    """A per-round quantity that exists nowhere in the image, model or config."""
    return "%04X%04X" % (run_id & 0xFFFF, (0x9E37 * (i + 1)) & 0xFFFF)


def _parse_http(raw: bytes) -> Dict[str, object]:
    """Status code, headers and body of one reply. No validation here."""
    out: Dict[str, object] = {"status": None, "headers": {}, "body_len": 0,
                              "content_length": None, "raw_len": len(raw)}
    if b"\r\n\r\n" not in raw:
        return out
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    first = lines[0].decode("latin-1")
    if first.startswith("HTTP/1."):
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            out["status"] = int(parts[1])
    hdrs = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.decode("latin-1").strip().lower()] = \
                v.decode("latin-1").strip()
    out["headers"] = hdrs
    out["body_len"] = len(body)
    if "content-length" in hdrs and hdrs["content-length"].isdigit():
        out["content_length"] = int(hdrs["content-length"])
    return out


def converse_http(host_port: int, on_stage: Optional[Callable] = None,
                  rounds: int = HTTP_ROUNDS, control: str = "none",
                  run_id: int = 0) -> Dict:
    """Ask the device's own web server ``rounds`` questions, one connection each.

    ``control="withhold"`` opens each connection exactly as the real arm does
    and then never transmits the request line. The socket is still read, so a
    bridge or emulator that had learned to answer on the firmware's behalf would
    be caught replying to a question nobody asked.
    """
    if control not in CONTROL_MODES:
        raise ValueError("unknown control mode %r" % (control,))

    def _stage(name: str, **kw) -> None:
        if on_stage:
            on_stage(name, **kw)

    passed = 0
    statuses: List[Optional[int]] = []
    detail: Dict[str, str] = {}
    wrong_status: List[str] = []
    bad_length: List[str] = []
    identical_consecutive = False
    previous: Optional[bytes] = None
    statuses_seen: Dict[int, int] = {}

    _stage("http", note=("CONTROL: %d HTTP requests are NOT transmitted; each "
                         "connection is still opened and read"
                         if control == "withhold" else
                         "%d unauthenticated HTTP requests, each on its own "
                         "fresh TCP connection to the device's web server")
                        % rounds)

    for i in range(rounds):
        label, template, want = HTTP_SHAPES[i % len(HTTP_SHAPES)]
        nonce = _http_nonce(run_id, i)
        req = template.replace("%N%", nonce).encode()
        budget = HTTP_FIRST_TIMEOUT if i == 0 else HTTP_TIMEOUT
        raw = b""
        try:
            sock = socket.create_connection(("127.0.0.1", host_port),
                                            timeout=30)
        except OSError as exc:
            detail["round %d %s" % (i, label)] = "connect failed: %s" % exc
            break
        try:
            sock.settimeout(budget)
            if control != "withhold":
                sock.sendall(req)
            deadline = time.time() + budget
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                raw += chunk
                parsed = _parse_http(raw)
                cl = parsed["content_length"]
                if parsed["status"] is not None and (
                        cl is None or parsed["body_len"] >= cl):
                    break
        finally:
            try:
                sock.close()
            except OSError:
                pass

        parsed = _parse_http(raw)
        got = parsed["status"]
        statuses.append(got)
        if got is None:
            detail["round %d %s" % (i, label)] = (
                "<nothing>" if not raw else "unparseable: %r" % raw[:60])
            _stage("http", note="round %d went unanswered" % i)
            break
        statuses_seen[got] = statuses_seen.get(got, 0) + 1
        note = "%d" % got
        if got != want:
            wrong_status.append("round %d (%s): got %d, the firmware must "
                                "answer %d" % (i, label, got, want))
            note += "  WRONG (wanted %d)" % want
        # THE LENGTH IS THE FIRMWARE'S ARITHMETIC. A 200 must declare a
        # Content-Length and then deliver exactly that many bytes; nothing
        # host-side computes it, and a canned answer cannot track it.
        if got == 200:
            cl = parsed["content_length"]
            if cl is None:
                bad_length.append("round %d: a 200 with no Content-Length" % i)
                note += "  no Content-Length"
            elif parsed["body_len"] != cl:
                bad_length.append("round %d: Content-Length %s but %d body "
                                  "bytes" % (cl, parsed["body_len"]))
                note += "  length mismatch"
            else:
                note += ", %d body bytes as declared" % cl
        if previous is not None and raw == previous:
            # The shapes are cycled so consecutive rounds NEVER expect the same
            # status; two identical consecutive replies therefore mean the
            # server stopped reading and started repeating.
            identical_consecutive = True
            note += "  IDENTICAL TO THE ROUND BEFORE"
        previous = raw
        detail["round %d %s" % (i, label)] = "%s   [%s]" % (
            raw.split(b"\r\n", 1)[0].decode("latin-1"), note)
        passed += 1

    # RULE 2: N OF N, never `>= 1`. And `all()` over an empty list is
    # vacuously True, so the round count is its own explicit term -- a run with
    # `--http-rounds 0` must NOT pass, and there is a test that says so.
    enough = rounds >= MIN_HTTP_ROUNDS
    checks = {
        "answered %d of %d HTTP rounds, each on its own connection"
        % (passed, rounds): bool(rounds > 0 and passed == rounds),
        "at least %d rounds were demanded (the cycle is exercised)"
        % MIN_HTTP_ROUNDS: enough,
        "every reply carried the status its own request shape demands":
            bool(passed > 0 and not wrong_status),
        "a real parser: absent URI (404), unknown method (501) and the root "
        "page (200) are told apart":
            len({s for s in statuses if s is not None}) >= 3,
        "every 200 declared a Content-Length and delivered exactly that many "
        "bytes": bool(passed > 0 and not bad_length),
        "no reply repeated the one before it (consecutive rounds demand "
        "different statuses)": bool(passed > 0 and not identical_consecutive),
    }
    http_round_trip = all(checks.values()) and passed == rounds and enough \
        and rounds > 0
    _stage("http", note="%d/%d HTTP rounds answered; statuses %s"
                        % (passed, rounds, statuses_seen))
    return {"http_round_trip": bool(http_round_trip),
            "http_rounds_passed": passed,
            "http_rounds_attempted": rounds,
            "http_statuses_seen": statuses_seen,
            "http_wrong_status": wrong_status,
            "http_bad_length": bad_length,
            "http_checks": checks,
            "http_responses": detail}


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------
#: THE RUNG IS DERIVED. It was the string literal ``"M4"`` -- a hard ceiling
#: that no amount of evidence could raise, three lines below a `landed` that
#: already conjoined everything. That is the defect this table removes: the
#: milestone is now read out of the evidence, and `RESULT:` carries it on the
#: default path, so a header can no longer disagree with its own run.
#:
#: M4 is "a protocol round trip", and EITHER server qualifies -- which is what
#: makes the independence arms readable: `--interfaces http` must still reach
#: M4 with no Modbus frame ever sent, and `--interfaces modbus` must still
#: reach M4 with the HTTP bridge never opened.
LADDER = (
    ("M1", "console_alive"),
    ("M3", "peripheral_driven"),
    ("M4", "round_trip"),
    ("M5", "multi_interface"),
)

#: **Rule 1: this does not shrink if we implement less.** The source is
#: Advantech's own published capability set for the ADAM-6000 series -- the
#: family is sold as a Modbus/TCP remote-I/O module with a built-in web
#: configuration server, an SNMP agent and an MQTT client -- and this image
#: corroborates all four in its own strings and its own console
#: (`[snmp] enable snmp = 1`, `g_sDevSetting.pMqttSettTbl.ucEnMqtt`,
#: `Server: ADAM-6000/8.1.0019`). Two of the four are graded. **The other two
#: are left IN the denominator**: SNMP is UDP/161 and this rehost's peer models
#: no UDP at all, and MQTT is an outbound client that would need a broker --
#: both are ungraded, neither is refuted, and dropping them to make 2/2 out of
#: 2/4 would be precisely the ratio-widening Rule 1 forbids.
#:
#: WHICH KEYS COLLAPSE, and why. `*_round_trip` keys are NOT interfaces:
#:
#:   * ONE interface, Modbus/TCP on 502 -- `modbus_round_trip`,
#:     `sustained_round_trips`, `answers_with_data`,
#:     `answers_that_were_exceptions`, `exception_codes_seen`. The five PROBES
#:     shapes are five *function codes* down one connection to one server:
#:     commands, not interfaces.
#:   * ONE interface, HTTP on 80 -- `http_round_trip`, `http_rounds_passed`,
#:     `http_statuses_seen`. The three request shapes are three *request
#:     types* against one server: 404/501/200 is one parser discriminating,
#:     not three links.
#:   * NOT interfaces at all -- `booted`, `tx_ring_descriptors`, the EMAC's
#:     frame and ARP counters. Those are wire-level facts. ARP is link-layer
#:     plumbing underneath *both* services, not a third service.
#:
#: HONEST LIMIT ON THE INDEPENDENCE CLAIM, stated because it is load-bearing.
#: The two servers are separable in the ways a harness can test: they are two
#: separately-bound lwIP listening PCBs, two application parsers, and they are
#: driven here by **two separately-modelled machines** with different MACs
#: (02:00:00:5e:10:02 / :03) and different IPs (10.0.0.2 / 10.0.0.3), so one
#: can answer while the other is quiescent and disabling either leaves the
#: other's round trip untouched. What they are NOT is two *buses*: they share
#: one EMAC, one lwIP, one driver and one live interrupt vector (IRQ 40 is the
#: only one this image arms), and the firmware is bare-metal, so RULES §1a's
#: second evidence form -- different drivers, IRQ vectors or RTOS tasks -- is
#: NOT satisfied and is not claimed. The claim rests on §1a's first form plus
#: the mandatory operational test.
INTERFACE_INVENTORY = {
    "links": [
        "Modbus/TCP server, tcp/502 (graded)",
        "HTTP configuration server, tcp/80 (graded)",
        "SNMP agent, udp/161 (ungraded: this rehost's peer models no UDP; "
        "the firmware's own console reports it enabled)",
        "MQTT client to an external broker (ungraded: outbound, and no broker "
        "is modelled)",
    ],
    "count": 4,
    "graded": 2,
    "m5_defined": True,
    "source": "Advantech's published ADAM-6000-series capability set "
              "(Modbus/TCP + web configuration server + SNMP agent + MQTT "
              "client), corroborated by this image's own strings and console",
    "collapsed": {
        "modbus_tcp_502": ["modbus_round_trip", "sustained_round_trips",
                           "answers_with_data",
                           "answers_that_were_exceptions",
                           "exception_codes_seen"],
        "http_80": ["http_round_trip", "http_rounds_passed",
                    "http_statuses_seen"],
        "not_interfaces": ["booted", "tx_ring_descriptors", "arp_replies",
                           "frames_in", "frames_out"],
    },
    "shared_substrate": "one EMAC0, one lwIP, one driver, one live IRQ (40), "
                        "no RTOS -- so RULES 1a evidence form 2 does not "
                        "apply and is not claimed",
}

#: Bulky keys kept off the one-line RESULT:. Everything else is emitted --
#: including every HTTP key and the rung itself.
RESULT_BULK = {"responses", "http_responses", "transcript"}


def grade(res: Dict[str, object]) -> Tuple[str, Dict[str, bool]]:
    """Derive (milestone, per-rung truth) from what this run measured.

    M1 and M3 are deliberately DIFFERENT keys. `booted` here has always meant
    "lwIP said IP ready.", which is already M3 -- the firmware configured and
    operated its Ethernet MAC. M1 is the weaker, earlier fact: the guest ran
    its own code far enough to print its own start banner. Grading both off one
    key would make M1 and M3 the same rung.
    """
    res["peripheral_driven"] = bool(res.get("booted"))
    # M3 implies M1: a device that brought lwIP up self-evidently ran.
    res["console_alive"] = bool(res.get("console_alive")
                                or res.get("booted"))
    res["round_trip"] = bool(res.get("modbus_round_trip")
                             or res.get("http_round_trip"))
    res["multi_interface"] = bool(res.get("modbus_round_trip")
                                  and res.get("http_round_trip"))
    met = {rung: bool(res.get(key)) for rung, key in LADDER}
    milestone = "M0"
    for rung, key in LADDER:
        if not res.get(key):
            break
        milestone = rung
    return milestone, met


def ladder_report(res: Dict[str, object]) -> str:
    lines = ["", "LADDER (rung derived from evidence, never written down)"]
    met = res.get("rungs_met") or {}
    for rung, key in LADDER:
        lines.append("  %-3s %-20s %s" % (rung, key,
                                          "PASS" if met.get(rung) else "--"))
    inv = INTERFACE_INVENTORY
    lines.append("  inventory (%d published, %d graded; source: %s):"
                 % (inv["count"], inv["graded"], inv["source"]))
    for link in inv["links"]:
        lines.append("      - %s" % link)
    lines.append("  collapses: modbus_tcp_502 <- %d keys; http_80 <- %d keys; "
                 "%d wire facts are not interfaces"
                 % (len(inv["collapsed"]["modbus_tcp_502"]),
                    len(inv["collapsed"]["http_80"]),
                    len(inv["collapsed"]["not_interfaces"])))
    lines.append("  shared substrate: %s" % inv["shared_substrate"])
    lines.append("  arm: interfaces=%s  control=%s"
                 % (res.get("interfaces_exercised"), res.get("control_mode")))
    lines.append("  evidence: Modbus %s/%s answered; HTTP %s/%s answered, "
                 "statuses %s"
                 % (res.get("sustained_round_trips"),
                    res.get("requests_attempted"),
                    res.get("http_rounds_passed"),
                    res.get("http_rounds_attempted"),
                    res.get("http_statuses_seen")))
    lines.append("  MILESTONE: %s" % res.get("milestone"))
    return "\n".join(lines)


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None,
               control: str = "none",
               interfaces: str = "both",
               rounds: Optional[int] = None,
               http_rounds: Optional[int] = None) -> Dict:
    """Boot ONE device and hold conversations with the servers it runs.

    ONE GUEST, NOT ONE PER PROBE. This used to boot a separate device for each
    of five probes, because the rehost answered the first request after boot
    and nothing after it -- so `landed = all(checks)` read like a conjunction
    while every clause was answered by a different device on its first
    exchange. That structure could not have detected the defect it was working
    around. It is gone: every question below is put to the same guest.

    ``interfaces`` is the M5 independence lever and it is enforced here, not
    merely reported: ``"modbus"`` never opens the HTTP bridge port at all (the
    bridge is not even told to bind it), and ``"http"`` never transmits a
    Modbus frame. Each arm has to reach M4 on its own.
    """
    if control not in CONTROL_MODES:
        raise ValueError("unknown control mode %r; expected one of %s"
                         % (control, ", ".join(CONTROL_MODES)))
    if interfaces not in INTERFACE_SETS:
        raise ValueError("unknown interface set %r; expected one of %s"
                         % (interfaces, ", ".join(INTERFACE_SETS)))
    n_modbus = SUSTAINED_N if rounds is None else rounds
    n_http = HTTP_ROUNDS if http_rounds is None else http_rounds

    def _stage(name: str, **kw) -> None:
        if on_stage:
            on_stage(name, **kw)

    port = int(os.environ.get("HAL_ADAM_ATTACK_PORT", "21300"), 0)
    http_port = int(os.environ.get("HAL_ADAM_HTTP_ATTACK_PORT",
                                   str(port + 1)), 0)
    want_modbus = interfaces in ("both", "modbus")
    want_http = interfaces in ("both", "http")

    res: Dict[str, object] = {
        "booted": False, "landed": False,
        "control_mode": control,
        "interfaces_exercised": interfaces,
        "modbus_round_trip": False,
        "http_round_trip": False,
        "sustained_round_trips": 0,
        "requests_attempted": n_modbus if want_modbus else 0,
        "http_rounds_passed": 0,
        "http_rounds_attempted": n_http if want_http else 0,
        "first_unanswered_request": None,
        "tx_ring_descriptors": TX_RING_DESCRIPTORS,
        "checks": {}, "responses": {},
    }

    # THE HTTP BRIDGE IS ONLY BOUND WHEN THIS ARM MAY USE IT. That is what
    # makes `--interfaces modbus` a real disabling and not a polite request:
    # with the env var unset the bridge builds no HTTP service, opens no second
    # peer, and the device's web server is never contacted at all.
    env_http = os.environ.get("HAL_ADAM_HTTP_BRIDGE_PORT")
    if want_http:
        os.environ["HAL_ADAM_HTTP_BRIDGE_PORT"] = str(http_port)
    else:
        os.environ.pop("HAL_ADAM_HTTP_BRIDGE_PORT", None)

    dev = DeviceScenario(bridge_port=port, log_dir=log_dir)
    try:
        if not dev.boot(on_stage or (lambda *a, **k: None),
                        attach=want_modbus):
            res["checks"] = {"the device booted": False}
            res["log"] = dev.log
            res["milestone"], res["rungs_met"] = grade(res)
            res["interfaces"] = INTERFACE_INVENTORY
            return res
        console = "\n".join(dev.console())
        res["console_alive"] = "6000_DIO" in console

        if want_modbus:
            res.update(converse(dev, on_stage, count=n_modbus,
                                control=control))
        else:
            _stage("modbus", note="ARM: the Modbus seam is not touched by "
                                  "this run -- no frame is transmitted to "
                                  "tcp/502")
            res["booted"] = "IP ready." in console

        if want_http:
            res.update(converse_http(http_port, on_stage, rounds=n_http,
                                     control=control, run_id=os.getpid()))
        else:
            _stage("http", note="ARM: the HTTP bridge was never bound -- the "
                                "device's web server is not contacted")
    finally:
        dev.teardown()
        if env_http is None:
            os.environ.pop("HAL_ADAM_HTTP_BRIDGE_PORT", None)
        else:
            os.environ["HAL_ADAM_HTTP_BRIDGE_PORT"] = env_http

    # `landed` is the conjunction of whatever this arm actually exercised. An
    # arm that touches one server is not penalised for not touching the other;
    # that is the point of the lever.
    parts = []
    if want_modbus:
        parts.append(bool(res.get("landed")) and bool(
            res.get("modbus_round_trip")))
    if want_http:
        parts.append(bool(res.get("http_round_trip")))
    res["landed"] = bool(parts) and all(parts)

    res["log"] = dev.log
    # DERIVED, never asserted. This line used to be the string literal "M4" --
    # a ceiling no evidence could lift.
    res["milestone"], res["rungs_met"] = grade(res)
    res["interfaces"] = INTERFACE_INVENTORY
    return res


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-adam6000-tm4c-attack",
        description="Unauthenticated Modbus/TCP and HTTP against the "
                    "ADAM-6050 rehost; verified from the firmware's own "
                    "replies.")
    p.add_argument("--control", default="none", choices=CONTROL_MODES,
                   help="'none' = the real attack; 'withhold' = the "
                        "falsification control (the request bytes are never "
                        "transmitted on either seam; every connection is "
                        "still opened and still read)")
    p.add_argument("--log-dir", default=None)
    p.add_argument("--interfaces", default="both", choices=INTERFACE_SETS,
                   help="which of the device's servers this arm may touch. "
                        "'modbus' never binds the HTTP bridge and 'http' "
                        "never sends a Modbus frame: this is the M5 "
                        "independence test, and each arm must still reach M4 "
                        "on its own")
    p.add_argument("--rounds", type=int, default=None,
                   help="Modbus requests on one connection (default %d)"
                        % SUSTAINED_N)
    p.add_argument("--http-rounds", type=int, default=None,
                   help="HTTP exchanges, one fresh connection each (default "
                        "%d; 0 demonstrates the empty-list guard)"
                        % HTTP_ROUNDS)
    p.add_argument("--ladder", action="store_true",
                   help="also print the derived rung table (the RESULT line "
                        "carries the rung either way)")
    # Reject unknown argv rather than ignoring it. This main() used to take no
    # argv at all, so a documented-looking flag was silently dropped and the
    # REAL attack ran and was reported as a control (playbook §2.200).
    args = p.parse_args(argv)

    def on_stage(name: str, **kw) -> None:
        print("[%s] %s" % (name, kw.get("note", "")), file=sys.stderr)

    print("[mode] control=%r (%s)  interfaces=%r"
          % (args.control,
             "REAL ATTACK" if args.control == "none" else "NEGATIVE CONTROL",
             args.interfaces),
          file=sys.stderr)
    result = run_attack(on_stage=on_stage, log_dir=args.log_dir,
                        control=args.control, interfaces=args.interfaces,
                        rounds=args.rounds, http_rounds=args.http_rounds)
    print()
    for name, ok in result.get("checks", {}).items():
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    for name, ok in result.get("http_checks", {}).items():
        print("  [%s] HTTP: %s" % ("PASS" if ok else "FAIL", name))
    print()
    for label, reply in result.get("responses", {}).items():
        print("  %-34s -> %s" % (label, reply))
    for label, reply in result.get("http_responses", {}).items():
        print("  %-34s -> %s" % (label, reply))
    print("\n  sustained Modbus round trips on one guest: %d/%d"
          % (result.get("sustained_round_trips", 0),
             result.get("requests_attempted", 0)))
    print("  of those: %d carried data, %d were exceptions %s"
          % (result.get("answers_with_data", 0),
             result.get("answers_that_were_exceptions", 0),
             result.get("exception_codes_seen", {})))
    print("  HTTP rounds answered (one connection each): %d/%d, statuses %s"
          % (result.get("http_rounds_passed", 0),
             result.get("http_rounds_attempted", 0),
             result.get("http_statuses_seen", {})))
    # THE RUNG IS ON THE DEFAULT PATH. `--ladder` only adds the table; it does
    # not change what RESULT: says, so a header can never disagree with a run.
    if args.ladder:
        print(ladder_report(result))
    print("\nRESULT: " + json.dumps(
        {k: v for k, v in result.items() if k not in RESULT_BULK},
        sort_keys=True, default=str))
    # Non-zero below M4. Compare the RUNG, not the string: a run that grades
    # M5 must not exit 1 and be read as a failure.
    import re as _re
    _m = _re.match(r"M(\d+)", result.get("milestone") or "")
    return 0 if (result.get("landed") and _m and int(_m.group(1)) >= 4) else 1


if __name__ == "__main__":
    sys.exit(main())
