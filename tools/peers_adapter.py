# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""rehostry-peers adapter for device-adam6000-tm4c (batch s1011, fuzz reach).

HOW THIS ROW'S NETWORK REACHES THE HOST (read from the row, not assumed):
FORWARDED HOST PORTS. The EMAC0 model (`tiva_emac`) moves frames through the
guest's DMA rings; `net_peer` models other machines on the segment (one MAC +
IP per machine, TCP, and -- added for this batch -- UDP); the intercept
`bp_handlers/modbus_bridge.ModbusBridge` (overlay `adam6000_tm4c_bridge.yaml`)
binds one 127.0.0.1 port per service and relays it through that service's own
peer. Before this batch only tcp/502 and tcp/80 could be bridged;
`HAL_ADAM_SERVICES="name:hostport:devport[:udp],..."` now adds any TCP or UDP
device port, each on its own peer. The bridge is pumped from the firmware's own
`rom_SysCtlPeripheralReady` calls. rehostry-peers' `SocketTransport` with a
port map is the whole client side; there is no control channel on this row.

⚠ A TCP port nothing listens on is NOT surfaced as a refusal on the host side:
the peer treats the device's RST as "not yet" and retries for ever. The RST is
visible in the emulator log (`PEER: reset by the device`), and that is where
this adapter reads it from.

rehostry-peers is imported by PATH INSERT (REHOSTRY_PEERS_SRC); the emulator
child gets the same directory on PYTHONPATH for `rehostry_peers.guesthook`.

Usage (interpreter: any python that can import this row's src; the CHILD is
HAL_PY, default the row's last-graded venv venvs-on-9bde2c0.noindex/adam6000-a71)::

    python tools/peers_adapter.py reach <entry> --out DIR
    python tools/peers_adapter.py fuzz <entry> <hex> --out DIR
    python tools/peers_adapter.py discover --out DIR [entries...]
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROW = os.path.dirname(HERE)
REPO = os.path.dirname(ROW)
PEERS_SRC = os.environ.get("REHOSTRY_PEERS_SRC",
                           os.path.join(REPO, "rehostry-peers", "src"))
sys.path.insert(0, PEERS_SRC)
sys.path.insert(0, os.path.join(ROW, "src"))

from rehostry_peers import adapter as A  # noqa: E402
from rehostry_peers.clients import http, modbus, snmp  # noqa: E402
from rehostry_peers.clients.raw import RawUdp  # noqa: E402
from rehostry_peers.guesthook import HitReader, overlay_yaml  # noqa: E402
from rehostry_peers.transport import SocketTransport  # noqa: E402

DEFAULT_HAL_PY = os.path.join(REPO, "venvs-on-9bde2c0.noindex",
                              "adam6000-a71", "bin", "python")

#: Lane s1011-laneB block 39950-40049; this row takes 39960-39979.
PORT_LO, PORT_HI = 39950, 40049
MODBUS_HOST, HTTP_HOST = 39960, 39961
RX_PORT, TX_PORT = 39978, 39979
#: name -> (host port, device port, proto). Device ports for the UDP services
#: are the image's own defaults, read live from g_sDevSetting (see STATUS).
EXTRA: Dict[str, tuple] = {
    "snmp": (39962, 161, "udp"),
    "ascii_udp": (39963, 1025, "udp"),
    "probe5168_udp": (39965, 5168, "udp"),
}
PCHOOK_BASE = 0x60000000          # nothing is mapped there on this board

HANDLERS: Dict[str, List[int]] = {
    "modbus_tcp_502": [0x0003EB64],
    "http_config_server_80": [0x00036518],
    "snmp_agent_161": [0x0001914C],
    "ascii_command_service": [0x0003E0B8],
    "gcl_peer_service": [0x0003E0B8],
}
#: Thumb function entries (r2 `aaa`), each one whose entry ran ONLY in that
#: service's coverage window (adam-disc3: idle + 5 windows, one boot).
HANDLER_NOTES: Dict[str, str] = {
    "modbus_tcp_502": "Modbus PDU dispatcher: `tbh` switch of 17 cases on "
                      "the function code; entry ran only in the modbus window",
    "http_config_server_80": "HTTP request parser: compares the request "
                             "against the image's 'GET /','HEAD /','POST /',"
                             "'OPTIONS /' table (literal 0x669E8)",
    "snmp_agent_161": "SNMP message handler: calls the two large functions "
                      "(0x19750, 0x1A16C) that ran only in the snmp window; "
                      "no string anchor",
    "ascii_command_service": "ASCII command dispatcher: checks the '01' "
                             "address and the leading '#','$','%','?','@'; "
                             "called from the udp/GCLport receive loop "
                             "0x4698C",
    "gcl_peer_service": "SAME handler as ascii_command_service: the only "
                        "socket bound on GCLport (g_sDevSetting+0x126 = 1025) "
                        "is the 0x4698C receive loop, which hands every "
                        "datagram to 0x3E0B8. One observation, two entries",
}


def _hex(b: bytes, n: int = 200) -> str:
    return b[:n].hex()


def transport() -> SocketTransport:
    udp = {}
    tcp = {502: MODBUS_HOST, 80: HTTP_HOST}
    for name, (hp, dp, proto) in EXTRA.items():
        (udp if proto == "udp" else tcp)[dp] = hp
    return SocketTransport("127.0.0.1", tcp_map=tcp, udp_map=udp)


# ---------------------------------------------------------------- drivers
#: ONE Modbus connection per guest, kept open. The bridge does not carry a
#: host-side close to the device (no FIN), and the firmware serves one
#: Modbus client at a time: measured, a second connection after the first was
#: dropped host-side got no answer in 150 s. So drive, inject and liveness
#: share one connection.
_MB: Dict[int, "modbus.ModbusTcpClient"] = {}


def _mb(t) -> "modbus.ModbusTcpClient":
    c = _MB.get(id(t))
    if c is None:
        c = _MB[id(t)] = modbus.ModbusTcpClient(t, 502, timeout=150)
    return c


def _mb_drive(t):
    r = _mb(t).request(modbus.read_holding(0, 4))
    return {"tid": r.tid, "function": r.function,
            "exception": r.exception, "raw": _hex(r.raw)}


def _mb_inject(t, data):
    return {"reply": _hex(_mb(t).raw(data, timeout=60))}


def _mb_live(t) -> bool:
    r = _mb(t).request(bytes([0x41, 0, 0, 0, 1]))    # not a Modbus function
    return r.function == 0x41 and r.exception == 1


def _http_drive(t):
    tok = "nosuch-%s" % secrets.token_hex(6)
    r = http.HttpClient(t, 80, timeout=150, quiet=3).get("/" + tok)
    return {"status": r.status, "server": r.header("Server"),
            "bytes": len(r.raw)}


def _http_inject(t, data):
    return {"reply": _hex(http.HttpClient(t, 80, timeout=60, quiet=3).raw(data))}


def _http_live(t) -> bool:
    r = http.HttpClient(t, 80, timeout=90, quiet=3).request(
        "ZORK%s" % secrets.token_hex(3), "/")
    return r.status == 501


def _udp(port: int, payload: bytes):
    def drive(t):
        got: List[bytes] = []
        for _ in range(3):
            got = RawUdp(t, port).exchange(payload, timeout=10)
            if got:
                break
        return {"replies": [_hex(g) for g in got]}

    def inject(t, data):
        return {"replies": [_hex(g) for g in
                            RawUdp(t, port).exchange(data, timeout=10)]}
    return drive, inject


def _mb_as_liveness(t) -> bool:
    """For a service with no repeatable known-good exchange of its own,
    liveness is the Modbus round trip: same EMAC, same lwIP, same loop."""
    return _mb_live(t)


def services() -> List[A.Service]:
    out: List[A.Service] = []

    def add(eid, proto, port, client, drive, inject, live):
        out.append(A.Service(eid, proto, port, client, HANDLERS.get(eid, []),
                             HANDLER_NOTES.get(eid, "not derived"), drive,
                             inject, live))
    add("modbus_tcp_502", "tcp", 502, "modbus", _mb_drive, _mb_inject,
        _mb_live)
    add("http_config_server_80", "tcp", 80, "http", _http_drive,
        _http_inject, _http_live)
    msg = snmp.build_message(b"public", snmp.GET, 0x2468,
                             ["1.3.6.1.2.1.1.1.0"], snmp.V1)
    d, i = _udp(161, msg)
    add("snmp_agent_161", "udp", 161, "snmp", d, i, _mb_as_liveness)
    d, i = _udp(1025, b"$01M\r")
    add("ascii_command_service", "udp", 1025, "raw-udp", d, i,
        _mb_as_liveness)
    d, i = _udp(1025, b"$01M\r")
    add("gcl_peer_service", "udp", 1025, "raw-udp", d, i, _mb_as_liveness)
    d, i = _udp(5168, b"rehostry-probe")
    add("probe_udp_5168", "udp", 5168, "raw-udp", d, i, _mb_as_liveness)
    return out


# ---------------------------------------------------------------- boot
def _assert_ports_free(ports, wait: float = 120.0) -> None:
    """Nothing may LISTEN on our TCP ports or hold our UDP ports. A TCP port
    in TIME_WAIT from the previous boot is not "held" (the bridge binds with
    SO_REUSEADDR); measured: the first sequential run tripped on exactly
    that. A listener is detected by connecting to it."""
    end = time.time() + wait
    for p in ports:
        assert PORT_LO <= p <= PORT_HI, p
        while True:
            held = None
            c = socket.socket()
            c.settimeout(1)
            try:
                c.connect(("127.0.0.1", p))
                held = "something LISTENs on tcp/%d" % p
            except OSError:
                pass
            finally:
                c.close()
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                u.bind(("127.0.0.1", p))
            except OSError as exc:
                held = "udp/%d held: %s" % (p, exc)
            finally:
                u.close()
            if not held:
                break
            if time.time() > end:
                raise RuntimeError(held)
            time.sleep(2)


class AdamAdapter(A.RowAdapter):
    row = "device-adam6000-tm4c"

    def __init__(self, python: Optional[str] = None,
                 extra: Optional[Dict[str, tuple]] = None,
                 trace: int = 0, keepalive: Optional[bool] = None) -> None:
        self.keepalive = (os.environ.get("ADAM_KEEPALIVE", "1") == "1"
                          if keepalive is None else keepalive)
        self.python = python or os.environ.get("HAL_PY") or DEFAULT_HAL_PY
        self.extra = EXTRA if extra is None else extra
        self.trace = trace

    def services(self) -> List[A.Service]:
        return services()

    def boot(self, pcs: List[int], workdir: str) -> A.Guest:
        from rehostry_adam6000_tm4c import paths, spawn
        ports = [MODBUS_HOST, HTTP_HOST, RX_PORT, TX_PORT] + [
            v[0] for v in self.extra.values()]
        _assert_ports_free(ports)
        os.makedirs(workdir, exist_ok=True)
        hits = os.path.join(workdir, "hits.json")
        for f in os.listdir(workdir):
            if f.startswith("hits.json"):
                os.unlink(os.path.join(workdir, f))
        ov = os.path.join(workdir, "pchook_overlay.yaml")
        with open(ov, "w") as fh:
            fh.write(overlay_yaml(PCHOOK_BASE, pcs, hits, trace=self.trace))
        svc = ",".join("%s:%d:%d:%s" % (n, hp, dp, pr)
                       for n, (hp, dp, pr) in self.extra.items())
        env = spawn.spawn_env(extra={
            "HAL_ADAM_BRIDGE_PORT": str(MODBUS_HOST),
            "HAL_ADAM_HTTP_BRIDGE_PORT": str(HTTP_HOST),
            "HAL_ADAM_SERVICES": svc,
            # a host close becomes a FIN to the device (see net_peer.close)
            "HAL_ADAM_FIN_ON_CLOSE": "1"})
        env["PYTHONPATH"] = PEERS_SRC
        argv = spawn.spawn_argv(python=self.python, bridge=True,
                                rx_port=RX_PORT, tx_port=TX_PORT)
        argv += ["-c", ov]
        if self.keepalive:
            # The unprovisioned build registers neither of these; without them
            # the guest goes deaf after "Backup_FW_Image success" (STATUS,
            # s1011 section). HAL_ADAM_DELAY_TICK lets delay_yield tick here.
            ka = os.path.join(workdir, "keepalive_overlay.yaml")
            with open(ka, "w") as fh:
                fh.write("intercepts:\n"
                         "  - class: rehostry_adam6000_tm4c.bp_handlers."
                         "tiva_rom_api.TivaRomApi\n"
                         "    function: hal_delay_yield\n"
                         "  - class: rehostry_adam6000_tm4c.bp_handlers."
                         "tiva_rom_api.TivaRomApi\n"
                         "    function: main_idle_park\n")
            argv += ["-c", ka]
            env["HAL_ADAM_DELAY_TICK"] = "1"
        logpath = os.path.join(workdir, "emulator.log.txt")
        log = open(logpath, "wb")
        proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                                stdout=log, stderr=subprocess.STDOUT)
        print("BOOT pid=%d ports=%s" % (proc.pid, sorted(ports)), flush=True)

        def stop() -> None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
            log.close()
        info = {"pid": proc.pid, "python": self.python,
                "image_sha256": A.sha256_file(str(paths.firmware_bin())),
                "core_unicorn_backend_sha256": _core_sha(self.python),
                "services_env": svc, "log": logpath,
                "keepalive": self.keepalive,
                "transport": transport().describe()}
        g = A.Guest(transport=transport(), hits=HitReader(hits), info=info,
                    stop=stop, alive=lambda: proc.poll() is None)
        g.log = logpath                                    # type: ignore
        return g

    def wait_ready(self, guest: A.Guest, service: Optional[A.Service],
                   timeout: float) -> Dict[str, Any]:
        end = time.time() + timeout
        logpath = guest.log                                 # type: ignore
        while time.time() < end:
            if not guest.alive():
                raise TimeoutError("emulator exited during boot")
            try:
                if "IP ready." in open(logpath, errors="replace").read():
                    return {"ip_ready": True, "t_ready": time.time()}
            except OSError:
                pass
            time.sleep(2)
        raise TimeoutError("firmware never reached 'IP ready.'")


def log_since(guest: A.Guest, needle: str, offset: int = 0) -> List[str]:
    try:
        with open(guest.log, errors="replace") as fh:          # type: ignore
            fh.seek(offset)
            return [ln.rstrip() for ln in fh if needle in ln]
    except OSError:
        return []


def _core_sha(python: str) -> Optional[str]:
    try:
        p = subprocess.run([python, "-c", "import halucinator.backends."
                            "unicorn_backend as m;print(m.__file__)"],
                           capture_output=True, text=True, timeout=60,
                           env={k: v for k, v in os.environ.items()
                                if k not in ("PYTHONPATH", "HALUCINATOR_SRC")})
        path = p.stdout.strip().splitlines()[-1]
        return "%s %s" % (path, A.sha256_file(path))
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- discovery
#: g_sDevSetting, and the fields the image's own config-JSON formatter
#: (0x20228, format string at 0x66568) reads -- see STATUS.
DEVSET = 0x200125D0


def discover(out: str, entries: List[str], idle: float = 30.0) -> None:
    ad = AdamAdapter()
    g = ad.boot([], out)
    try:
        g.hits.require_armed()
        print("READY", ad.wait_ready(g, None, 900), flush=True)
        time.sleep(float(os.environ.get("DISCOVER_WARM", "30")))
        mem = g.hits.peek([(DEVSET + 0x124, 0x30), (DEVSET + 0x375, 1)])
        b = mem[DEVSET + 0x124]
        cfg = {"DSport": struct.unpack_from("<H", b, 0)[0],
               "GCLport": struct.unpack_from("<H", b, 2)[0],
               "NetDiag": b[4] & 1,
               "MBport": struct.unpack_from("<H", b, 0x1C)[0],
               "Webport": struct.unpack_from("<H", b, 0x23)[0],
               "WebEn": b[0x25], "MBEn": mem[DEVSET + 0x375][0],
               "raw": b.hex()}
        print("DEVSETTING", json.dumps(cfg), flush=True)
        g.hits.cov_on()
        time.sleep(idle)
        cov = g.hits.cov_off("idle")
        print("idle blocks", len(cov), flush=True)
        for eid in entries:
            svc = ad.service(eid)
            off = os.path.getsize(g.log)                       # type: ignore
            g.hits.cov_on()
            t0 = time.time()
            try:
                rep = svc.wellformed(g.transport)
            except Exception as exc:  # noqa: BLE001
                rep = {"error": "%s: %s" % (type(exc).__name__, exc)}
            time.sleep(3)
            cov = g.hits.cov_off(eid)
            print("WINDOW %s %.1fs blocks=%d reply=%s icmp=%s rst=%s" % (
                eid, time.time() - t0, len(cov), json.dumps(rep)[:300],
                log_since(g, "ICMP unreachable", off)[-2:],
                log_since(g, "reset by the device", off)[-2:]), flush=True)
    finally:
        g.stop()


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover")
    d.add_argument("--out", required=True)
    d.add_argument("entries", nargs="*")
    r = sub.add_parser("reach")
    r.add_argument("entry")
    r.add_argument("--out", required=True)
    f = sub.add_parser("fuzz")
    f.add_argument("entry")
    f.add_argument("hexbytes")
    f.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "discover":
        discover(a.out, a.entries or [s.entry_id for s in services()])
        return 0
    data = bytes.fromhex(a.hexbytes) if a.cmd == "fuzz" else None
    rec = A.run_entry(AdamAdapter(), a.entry, a.out, data=data)
    A.dump(rec, os.path.join(a.out, "reach-%s.json" % a.entry))
    print("RESULT " + json.dumps({k: rec.get(k) for k in (
        "entry", "reached", "live_after", "handler_hits_delta", "cross_hits",
        "reply", "harness_error", "ready_error", "error", "unexplained")},
        default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
