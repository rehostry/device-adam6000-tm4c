#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live web panel for the adam6000-tm4c re-host + its attack.

One browser tab that boots the real rehosted firmware, then shows -- live -- the
firmware's own state and the attack's before/after evidence.

Transport is plain ``/state`` POLLING (no Server-Sent Events): SSE is buffered by
tunneling proxies (e.g. Cloudflare), so an EventSource panel is a permanently
blank page remotely while it works on localhost (playbook trap 5). The page GETs
``/state`` every 1.5s and POSTs /boot /refresh /attack /stop.

    rehostry-adam6000-tm4c-panel            # or: python3 -m rehostry_adam6000_tm4c.adam6000_panel

State comes from the firmware's own console (address, MAC, model, I/O-point
count) and is rendered as JSON. A richer render -- the register/coil map in device-plc's
panel is the model). Keep the polling transport and the boot/attack wiring.

The on-page briefing block (the ``<details class="card brief">`` under
the ``<h1>``) with device-specific text -- Device / Steps / What you're seeing /
The attack / Expect (playbook §2.5-5a). A first-time viewer must understand the
device from the page alone.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attack, spawn

_LOCK = threading.Lock()
_STATE = {"busy": False, "ready": False, "stage": "idle", "log": [],
          "state": None, "attack": None}
_SC = {"scenario": None}
ARGS: argparse.Namespace


def _on_stage(name, **data):
    with _LOCK:
        _STATE["stage"] = name
        if data.get("note"):
            _STATE["log"].append({"stage": name, "note": data["note"]})
            _STATE["log"] = _STATE["log"][-60:]
        if "state" in data:
            _STATE["state"] = data["state"]
        if "result" in data:
            _STATE["attack"] = data["result"]


def _boot():
    sc = attack.DeviceScenario(bridge_port=ARGS.port, log_dir=ARGS.log_dir)
    _SC["scenario"] = sc
    try:
        with _LOCK:
            _STATE.update(busy=True, ready=False, stage="booting", log=[],
                          state=None, attack=None)
        if not sc.boot(_on_stage):
            return
        _on_stage("read", state=sc.read_state())
        with _LOCK:
            _STATE["ready"] = True
        _on_stage("ready", note="firmware live -- read the state or run the attack")
    except Exception as exc:  # noqa: BLE001
        _on_stage("error", note="error: %s" % exc)
    finally:
        with _LOCK:
            _STATE["busy"] = False


def _refresh():
    sc = _SC["scenario"]
    if sc:
        _on_stage("read", state=sc.read_state())


def _attack():
    sc = _SC["scenario"]
    if sc:
        _on_stage("attack", result=sc.attack())
        _on_stage("read", state=sc.read_state())


def _shutdown_scenario():
    sc = _SC["scenario"]
    if sc:
        sc.shutdown()
        _SC["scenario"] = None
    with _LOCK:
        _STATE.update(ready=False, stage="stopped")
    _on_stage("stopped", note="firmware stopped")


# The STATE card renders whatever `attack.DeviceScenario.read_state` returns.
# A device-specific render (a coil grid rather than JSON) would read better; the
# transport (poll /state; POST /boot /refresh /attack /stop) must stay.
PAGE = r"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>adam6000-tm4c &mdash; rehosted</title>
<style>
 body{background:#0a0a0a;color:#cdd;font:14px/1.5 -apple-system,Menlo,monospace;margin:0;padding:16px}
 .wrap{max-width:860px;margin:0 auto}
 .card{background:#141414;border:1px solid #262626;border-radius:8px;padding:14px;margin:12px 0}
 button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:9px 14px;font-size:13px;cursor:pointer;margin:0 6px 6px 0}
 button.atk{background:#a4331f} button:disabled{opacity:.4;cursor:default}
 .pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;margin-left:8px}
 .pill.on{background:#132e1a;color:#3fb950} .pill.off{background:#2d1618;color:#f85149}
 pre{background:#000;border-radius:8px;padding:10px;overflow:auto;color:#8b949e}
 .log{font-size:12px;background:#000;border-radius:8px;padding:10px;max-height:150px;overflow:auto;color:#8b949e}
 .log b{color:#58a6ff}
 details.brief{background:#101820;border-color:#1f3350}
 details.brief summary{cursor:pointer;color:#cdd;font-size:13px}
 details.brief .body{margin-top:8px}
 details.brief p{margin:6px 0;color:#9db3c8;font-size:13px}
 details.brief b{color:#cdd}
</style></head><body><div class=wrap>
<h1>adam6000-tm4c &mdash; rehosted firmware</h1>
<!-- On-page briefing (playbook §2.5-5a): device-specific, factual text so a
     first-time viewer understands the page without the repo. -->
<details class="card brief" open>
 <summary><b>About this panel</b> &mdash; what it is, what to do, what to expect</summary>
 <div class=body>
  <p><b>Device.</b> An Advantech ADAM-6050 remote I/O module &mdash; a DIN-rail box with
     12 digital inputs and 6 relay outputs, wired to plant equipment and driven over
     Ethernet. This is its own firmware (6000_DIO V6.15B23) running its own bootloader,
     its own lwIP stack and its own Modbus/TCP server on port 502.</p>
  <p><b>Steps.</b> 1) <b>Boot firmware</b> &mdash; about a minute, and it ends when the
     firmware prints <i>IP ready.</i> &rarr; 2) <b>Re-read</b> to pull what the device says
     about itself &rarr; 3) <b>Run attack</b> &rarr; 4) <b>Stop</b>.</p>
  <p><b>What you&rsquo;re seeing.</b> The <b>STATE</b> card is read from the firmware&rsquo;s
     own console, not from host bookkeeping: the address it chose (10.0.0.1, Advantech&rsquo;s
     factory default), its MAC (00:D0:C9, Advantech&rsquo;s real OUI), its model number and
     its I/O-point count. The log shows boot and attack stages.</p>
  <p><b>The attack.</b> <b>Run attack</b> opens a TCP connection to port 502 and sends one
     Modbus request &mdash; no credential, no session, no key. Modbus/TCP has no
     authentication at all, so on the real module the same five bytes that read an input can
     close a relay contact. That is the finding: a device sold to sit on a plant network and
     drive equipment answers anyone who can reach its socket.</p>
  <p><b>Expect.</b> Success is the device <i>answering</i> &mdash; a Modbus exception frame
     with the function byte echoed and its top bit set. Every address is illegal here
     (exception <b>2</b>) because this module keeps its I/O profile in a serial flash the
     vendor image does not contain, so it boots reporting <i>GetDevInfo() Err</i>,
     <i>g_usModel = 255</i> and zero I/O points. An unsupported function code comes back as
     exception <b>1</b> instead &mdash; that difference is the proof the vendor&rsquo;s own
     parser is running and not a stand-in. A device that never came up would show no answer
     at all.</p>
 </div>
</details>
<div class=card>
 <button id=boot onclick="post('/boot')">&#9889; Boot firmware</button>
 <button id=refresh onclick="post('/refresh')" disabled>&#8635; Re-read</button>
 <button id=stop onclick="post('/stop')" disabled>&#9632; Stop</button>
 <span id=state class=pill></span>
</div>
<div class=card><b>STATE</b> (live from the firmware's own engine)<pre id=st>&mdash; boot to populate &mdash;</pre></div>
<div class=card>
 <button id=atk class=atk onclick="post('/attack')" disabled>&#9760; Run attack</button>
 <pre id=atkbox></pre>
</div>
<div class=card><div class=log id=log>ready. click to boot the firmware.</div></div>
</div>
<script>
function render(s){
  document.getElementById('boot').disabled=s.busy||s.ready;
  document.getElementById('refresh').disabled=!s.ready||s.busy;
  document.getElementById('stop').disabled=!s.ready&&!s.busy;
  document.getElementById('atk').disabled=!s.ready||s.busy;
  const sp=document.getElementById('state');
  sp.className='pill '+(s.ready?'on':'off'); sp.textContent=s.ready?'firmware live':(s.busy?'booting':'offline');
  document.getElementById('st').textContent=s.state?JSON.stringify(s.state,null,2):'— boot to populate —';
  document.getElementById('atkbox').textContent=s.attack?JSON.stringify(s.attack,null,2):'';
  const log=document.getElementById('log');
  log.innerHTML=(s.log||[]).map(l=>'<b>'+l.stage+'</b> '+(l.note||'')).join('<br>')||'ready.';
  log.scrollTop=log.scrollHeight;
}
function post(p){fetch(p,{method:'POST'}).then(()=>setTimeout(poll,300));}
function poll(){fetch('/state').then(r=>r.json()).then(render).catch(()=>{});}
poll(); setInterval(poll, 1500);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # noqa: ARG002 - quiet
        pass

    def _send(self, code, ctype, body):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/state":
            with _LOCK:
                body = json.dumps(_STATE)
            self._send(200, "application/json", body)
            return
        if path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE)
            return
        self._send(404, "text/plain", b"not found")

    def do_POST(self):  # noqa: N802
        with _LOCK:
            busy = _STATE["busy"]
            ready = _STATE["ready"]
        if self.path.startswith("/boot"):
            if not busy and not ready:
                threading.Thread(target=_boot, daemon=True).start()
        elif self.path.startswith("/refresh"):
            if ready and not busy:
                threading.Thread(target=_refresh, daemon=True).start()
        elif self.path.startswith("/attack"):
            if ready and not busy:
                threading.Thread(target=_attack, daemon=True).start()
        elif self.path.startswith("/stop"):
            threading.Thread(target=_shutdown_scenario, daemon=True).start()
        else:
            self._send(404, "text/plain", b"not found")
            return
        self._send(200, "application/json", b'{"ok":true}')


def main(argv=None) -> int:
    global ARGS
    p = argparse.ArgumentParser(description="Live web panel for the adam6000-tm4c re-host + attack")
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("ADAM6000_TM4C_HTTP_PORT", "29264")),
                   help="panel HTTP port (default from ADAM6000_TM4C_HTTP_PORT, else 29264)")
    p.add_argument("--bridge-port", type=int, default=spawn.BRIDGE_PORT,
                   dest="port_bridge",
                   help="firmware host-bridge TCP port (default %d)"
                        % spawn.BRIDGE_PORT)
    p.add_argument("--log-dir", default="/tmp", help="where to write the emulator boot log")
    p.add_argument("--no-open", action="store_true", help="don't open a browser")
    args = p.parse_args(argv)
    ARGS = argparse.Namespace(http_port=args.port, port=args.port_bridge,
                              log_dir=args.log_dir, no_open=args.no_open)

    httpd = ThreadingHTTPServer(("127.0.0.1", ARGS.http_port), Handler)
    httpd.daemon_threads = True
    url = "http://127.0.0.1:%d" % ARGS.http_port
    print("[adam6000_panel] polling panel on %s (firmware bridge tcp/%d)" % (url, ARGS.port))
    if not ARGS.no_open:
        threading.Thread(target=lambda: (time.sleep(0.6), webbrowser.open(url)),
                         daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        _shutdown_scenario()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
