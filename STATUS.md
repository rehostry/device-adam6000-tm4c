<!-- rehostry-census: milestone=M5 landed=true verdict=M4-OK verified=2026-09-02 method=live-run note=two-servers-Modbus502-HTTP80-one-EMAC-see-independence-section -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — device-adam6000-tm4c  (**M5**)

**Milestone reached: M5 — two of the device's own servers each complete a
protocol round trip, and each does so with the other switched off.** The
Modbus/TCP result below was already there; what was missing was that the
firmware has been serving its **web configuration server on tcp/80** the whole
time, and nothing ever asked it a question. It answers, it discriminates, and
it does so from a second modelled machine on the segment. See
"The second server" and "The independence test" below.

**Milestone previously recorded: M4 — a sustained Modbus/TCP conversation.** The vendor
image boots its own bootloader, loads and runs the application, reads its
(blank) serial flash, saves configuration to internal flash, brings up lwIP,
transmits and receives Ethernet frames, completes a TCP handshake on port 502,
and **keeps answering Modbus requests from one anonymous peer, down a single
TCP connection, with no credential of any kind** — 40/40 in the graded run
(`attack.py`), and 200/200 in a longer sweep of the same seam.

```
>>> 000100000006 01 01 00000008     read coils 0..7
<<< 000100000003 01 81 02           exception 2, illegal data address

>>> 000100000006 01 41 00000001     function 0x41 -- not a Modbus function
<<< 000100000003 01 c1 01           exception 1, illegal function
```

## The second server, and how it was settled

The fleet-wide capability sweep flagged this device at *medium* confidence and
said plainly that it could not be settled from code: the image carries
`HTTP/1.[01]`, `Server:`, `SNMP` and `MQTT` string sets, but **"the image
contains an httpd string set" is not "the httpd is `init`'d and bound"**. Four
in five such flags in that sweep turned out to be quiet-the-firmware stubs.

It was settled by asking lwIP, which answers this question unambiguously.
`net_peer.connect()` has always taken a port; only its caller was the literal
`502`. Pointed at 80, a listening PCB replies SYN/ACK and an unbound port
replies RST:

```
PEER: TCP 80->40001 [SYN|ACK] seq=0x196e ack=0x1001 len=0 win=2560
```

SYN/ACK. Then, with one `GET`:

```
HTTP/1.1 404 File not found
Server: ADAM-6000/8.1.0019
Content-type: text/html
Connection: close
```

**It is not a stub, and it is not only a 404 machine.** It serves the ADAM-6000
web UI:

```
>>> GET / HTTP/1.0
<<< HTTP/1.1 200 OK
    Server: ADAM-6000/8.1.0019
    Content-type: text/html
    Content-Length: 6463
    <!DOCTYPE html><html lang="en-US"> ... 6463 bytes ...
```

That page is in the firmware image at offset `0x5e65c` and in **no** host-side
file — checked. Nothing host-side parses HTTP: the bridge and the peer move
bytes and nothing else.

### Why this is evidence and not an echo

The same discrimination argument the Modbus arm rests on. This server does not
echo anything of the request, so two 404s are byte-identical — which is exactly
why the Modbus oracle's *"no reply was a repeat of the one before it"* term was
**not** borrowed for it; imported unchanged it would score a perfectly working
httpd at zero. What this server does instead is **choose**, from bytes the
attacker supplies, among three answers its own code holds, and **compute** the
length of one of them:

| request | firmware's answer |
| --- | --- |
| `GET /nosuchfile-<nonce>` | `404 File not found` |
| `ZORK<nonce> /` | `501 Not implemented` |
| `GET /` | `200 OK`, `Content-Length: 6463`, and exactly 6463 body bytes |

The oracle cycles those three shapes so **no two consecutive rounds ever expect
the same status** — that is the attributor here, in place of a transaction id.
A server that had gone deaf and was repeating cannot satisfy it, and neither
can a stale buffer.

**Rule 2: six of six, and every round is its own TCP connection.** The httpd
answers `Connection: close` and sends FIN, so each round re-handshakes from a
fresh source port. A server that answered once and went deaf could not complete
round 2's handshake at all. The count is `passed == rounds`, never `>= 1`.

```
round 0 absent URI  -> 404      HTTP/1.1 404 File not found   [404]
round 1 unknown method -> 501   HTTP/1.1 501 Not implemented  [501]
round 2 root page  -> 200       HTTP/1.1 200 OK   [200, 6463 body bytes as declared]
round 3 absent URI  -> 404      HTTP/1.1 404 File not found   [404]
round 4 unknown method -> 501   HTTP/1.1 501 Not implemented  [501]
round 5 root page  -> 200       HTTP/1.1 200 OK   [200, 6463 body bytes as declared]
```

## The independence test (RULES §1a), run both ways

M5 requires two interfaces that each pass M4 *and* an operational
demonstration that disabling one does not disturb the other. Both arms were
run, and the disabling is real rather than polite: `--interfaces modbus` never
binds the HTTP bridge port and never creates the second peer, and
`--interfaces http` never opens a connection to tcp/502 at all.

```
--interfaces both      Modbus 40/40, HTTP 6/6   MILESTONE: M5   exit 0
--interfaces modbus    Modbus 40/40, HTTP  0/0  MILESTONE: M4   exit 0   (0 contacts on tcp/80)
--interfaces http      Modbus  0/0,  HTTP 6/6   MILESTONE: M4   exit 0   (0 contacts on tcp/502)
```

**The two servers are driven by two separately-modelled machines**, not by one
peer object under two names:

```
Bridge[modbus]: tcp/31684 -- from 10.0.0.2 (02:00:00:5e:10:02) to 10.0.0.1:502
Bridge[http]:   tcp/31685 -- from 10.0.0.3 (02:00:00:5e:10:03) to 10.0.0.1:80
```

Getting that exactly right took a second pass. `DeviceScenario.boot()` used to
open its readiness socket on the Modbus bridge **unconditionally**, so the
HTTP-only arm still made the device complete a TCP handshake on tcp/502 — one
line in the log, no Modbus request ever sent, and the arm still passed. But
"this arm never touches Modbus" was then very slightly untrue, and an
independence claim has to be exactly true, so readiness now comes from the
firmware's own `IP ready.` and that arm opens no Modbus connection at all
(measured: 0).

In the `both` run the device completed handshakes with both peers —
`TCP 502->40001 [SYN|ACK]` and `TCP 80->41001 [SYN|ACK]` — so one server was
answering while the other was quiescent (§1a evidence form 1). `net_peer` now
holds a registry rather than a single global, and an unknown peer name **raises
rather than aliasing the default**, because a second peer that is silently the
first one is not a second peer.

### The honest limit on this claim, stated because it is load-bearing

The two services share **one EMAC0, one lwIP, one driver, and one live
interrupt vector** — IRQ 40 is the only external interrupt this image arms —
and the firmware is bare-metal with no RTOS. So RULES §1a's *second* evidence
form (different drivers, different IRQ vectors, different RTOS tasks) is **not
satisfied here and is not claimed**. What is claimed is §1a's first form (one
answers while the other is quiescent, from separately-modelled peers) plus the
mandatory operational test above. A reader who requires "different **bus**"
rather than "different server, different peer, separable both ways" would score
this M4. That caveat is carried in the machine-readable inventory itself
(`INTERFACE_INVENTORY["shared_substrate"]`), not only in this prose.

## The ladder, and the ceiling that was removed

`milestone` was the string literal `"M4"` — a hard ceiling assigned three lines
below a `landed` that already conjoined everything the run had measured. The
web server could have been graded and the rung still could not have risen,
because nothing read the evidence. The rung is now derived from a `LADDER`
table, `RESULT:` carries it **on the default path** (`--ladder` only adds the
table, so a header cannot disagree with its own run), and a test asserts
exhaustively that no rung outside the table can ever be emitted.

```
M1  console_alive        PASS
M3  peripheral_driven    PASS
M4  round_trip           PASS
M5  multi_interface      PASS
```

The same run is reachable as a subcommand of the installed entry point:
`rehostry-adam6000-tm4c ladder [--interfaces both|modbus|http]`.

### The inventory is not ours to shrink (Rule 1)

Four interfaces are published for the ADAM-6000 series; **two are graded, and
the other two stay in the denominator**:

| interface | status |
| --- | --- |
| Modbus/TCP, tcp/502 | graded, 40/40 |
| HTTP configuration server, tcp/80 | graded, 6/6 |
| SNMP agent, udp/161 | **ungraded, not refuted** — this rehost's peer models no UDP at all. The firmware's own console reports it enabled: `[snmp] enable snmp = 1`, `ucReadCommunity:public ucWriteCommunity:private` |
| MQTT client | **ungraded, not refuted** — outbound to a broker, and no broker is modelled |

Dropping the ungraded two to report 2/2 instead of 2/4 would be exactly the
ratio-widening Rule 1 forbids. M8 on this device is 2 of 4, not met.

**Which keys collapse.** `*_round_trip` keys are not interfaces:

* **one** interface, Modbus/TCP — `modbus_round_trip`, `sustained_round_trips`,
  `answers_with_data`, `answers_that_were_exceptions`, `exception_codes_seen`.
  The five probe shapes are five *function codes* down one connection: commands,
  not interfaces.
* **one** interface, HTTP — `http_round_trip`, `http_rounds_passed`,
  `http_statuses_seen`. 404/501/200 is one parser discriminating, not three
  links.
* **not interfaces at all** — `booted`, `tx_ring_descriptors`, `arp_replies`,
  `frames_in`, `frames_out`. Wire-level facts. ARP is link-layer plumbing
  underneath *both* services, not a third service.

## The controls, and both arms of each

A run that cannot be made to fail proves nothing.

| knob | Modbus | HTTP | rung | exit |
| --- | --- | --- | --- | --- |
| `--control none` (real) | 40/40 | 6/6 | **M5** | 0 |
| `--control withhold` | 0/40 | 0/6 | **M3** | 1 |
| `--http-rounds 0` | — | 0/0 | **M3** | 1 |

`withhold` opens every connection exactly as the real arm does, completes every
handshake, and reads every socket — it only never transmits the request bytes.
**Nothing came back on either seam**, which is what would catch a bridge or an
emulator that had learned to answer on the firmware's behalf.

`--http-rounds 0` is the `all()`-over-an-empty-list guard, and the guard is
load-bearing rather than decorative: with zero rounds `passed == rounds` is
`0 == 0`, vacuously true, so the round count is its own explicit term. Removing
it flips that arm to a pass.

The three MAC-model knobs from the original M4 work still apply unchanged
(`HAL_ADAM_EMAC_RING_LEN=16` -> 1/40, `HAL_ADAM_STATIC_TXBUF=1` -> 2/40,
`HAL_ADAM_EMAC_NO_CURSOR=1` -> 5/40).

## Why the web UI is mostly 404, for the same reason the I/O is empty

The module's HTML, JavaScript and applet all live in the same serial NOR flash
as its device profile, and that flash is not part of the distributed image. The
firmware says so on the way up:

```
[SIFlashRead_s] profile=ffffffff
[SIFlashRead_s] html=ffffffff
[SIFlashRead_s] JS=ffffffff
[SIFlashRead_s] JAR=ffffffff
```

So every URI except the built-in root page is a 404 — the same blank-flash
limit that makes nearly every Modbus address illegal. The root page is served
because it is compiled into the image rather than stored in that flash.


## The count, and why it is the headline

**Graded: 40 out of 40 consecutive round trips on a single guest, exit 0.
Swept: 200 out of 200, with 200 distinct replies.** Every request differed from
every other in its transaction id, its unit id, its function code, its address
and its quantity, and every reply carried its own request's transaction and unit
id back — so no answer in either run could have been a buffered repeat of an
earlier one.

That number used to be **one**. Not one *per connection* — one per boot, after
which the device was deaf to everything, and the oracle never asked.

### What was wrong, and how it was found

This device previously claimed M4 on an oracle that **booted a separate guest
for each of five probes**. `landed = all(checks.values())` read like a strong
conjunction, but each clause was answered by a different freshly-booted device
on its *first* exchange, so the oracle was structurally incapable of noticing
that no guest ever answered a second question. The repository documented the
symptom as a firmware quirk — "One Modbus exchange per boot" — and worked
around it.

It was not a firmware quirk. It was **three defects in the MAC model**, each of
which alone silences the device, and each of which now has a switch that puts
it back:

| Defect | What it did | Where it stops | Knob that restores it |
| --- | --- | --- | --- |
| Fixed 16-descriptor ring scan | Descriptors 16..23 of a 24-entry ring were never serviced; the firmware handed them to a DMA engine that never looked | after exactly **16** transmitted frames | `HAL_ADAM_EMAC_RING_LEN=16` |
| Transmit-complete never raised | The driver's only reclaim path is gated on it, so no pbuf and no descriptor slot was ever freed | after one lap of the ring | `HAL_ADAM_STATIC_TXBUF=1` |
| No DMA cursor on the rings | The model used whichever slot was free rather than the next one in ring order, so it and the driver walked the same ring in different places | after **5** exchanges | `HAL_ADAM_EMAC_NO_CURSOR=1` |

Measured by the graded oracle, one guest, fresh content per request
(`runs-on-9bde2c0/adam6000-tm4c.control.run`):

```
default (all three fixed)                40/40   exit 0   landed
HAL_ADAM_EMAC_RING_LEN=16                 1/40   exit 1   <- the published behaviour, exactly
HAL_ADAM_STATIC_TXBUF=1                   2/40   exit 1
HAL_ADAM_EMAC_NO_CURSOR=1                 5/40   exit 1
```

Restoring the fixed 16-descriptor scan alone reproduces the *one request per
boot* the repository used to describe as a property of the firmware. It was
never the firmware.

**The reclaim.** The old model left transmit-complete unasserted on purpose and
said why: *"transmit buffers are not reclaimed, which for a short session costs
memory and nothing else."* That is false, and the firmware says so.
`tivaif_transmit` refuses to send at all when the descriptor it is about to
write still carries a pbuf:

```
1cc0e:  ldr   r1, [r0]          ; pTxDescList->pDescriptors
1cc10:  ldr   r0, [r0, #0xc]    ; ->ui32Write
1cc12:  mul   r0, r8, r0        ; * 0x24  (36 bytes per descriptor)
1cc1a:  ldr   r0, [sb, #0x20]   ; pDescriptors[write].pBuf
1cc1e:  cmp   r0, #0
1cc22:  beq   0x1cc4c           ; free      -> go on
1cc24:  bl    pbuf_free         ; NOT free  -> drop the frame, return -1
```

and it sizes the run of free descriptors from `ui32Read`, which only the
reclaim advances (`rsb r1, r1, #0x18` at `0x0001CC5E` — 24 is the firmware's
own transmit-ring size, and the same constant appears at `0x0001CCDC`). `pBuf`
is cleared in exactly one place, `tivaif_process_transmit` at `0x0001CD6A`, and
`tivaif_interrupt` reaches it only when bit 0 of the DMA status word is set:

```
1d1b2:  lsls  r0, r5, #0x1f     ; bit 0 == EMAC_INT_TRANSMIT
1d1b4:  bpl   0x1d1c2           ; clear -> skip the reclaim entirely
1d1be:  bl    0x1cd6a           ; tivaif_process_transmit
```

So withholding the bit does not cost memory. It costs the device its
transmitter, one ring-lap after boot.

**The cursor** was the deepest of the three and the last to fall. A Synopsys
DMA holds a current-descriptor pointer per ring: it services that descriptor,
moves to the next, wraps, and **never goes back to pick whichever slot happens
to be free**. The model did exactly that, and it deadlocked against the
driver's own read index:

* the driver reads at `ui32Read` and stops the moment that descriptor is still
  DMA-owned — `cmp r0,#0; bmi <exit>` at `0x0001CE26`;
* the model delivered three frames into descriptors 0, 1, 2; the driver
  consumed all three, re-armed them, and left `ui32Read` at 3;
* the next frame went to descriptor 0, because that was the lowest slot the
  "DMA" owned again. The driver looked at descriptor 3, found it armed and
  empty, and stopped — permanently.

The instrumentation that settled it (`HAL_ADAM_EMAC_DEBUG=1`, still in the
model) prints the descriptors *and* the driver's own indices side by side:

```
DBG ring 0x20020f60 own=000000000000001111111111 pbuf=1111...  list@0x20000264 n=24 rd=3 wr=0
DBG ring 0x20020c00 own=000000000000000000000000 pbuf=0000...  list@0x20000254 n=24 rd=5 wr=5
```

`rd=3`, frozen, while the model kept consuming descriptors 4, 5, 6 …. The
transmit ring beside it (`rd=5 wr=5`, every `pBuf` cleared) is the reclaim fix
working. Reading the owner bits alone would have shown drift and explained
nothing; it is the driver's indices next to them that name the fault.

**Ring length is now measured, not assumed.** Both rings are built in chained
mode, so word 3 of each descriptor is the address of the next and the last
links back to the first. Following that chain gives 24 for both rings, which
agrees with the firmware's own `#0x18`:

```
EMAC: ring at 0x20020f60 is 24 descriptors (followed the firmware's own chain, 36 bytes apart)
EMAC: ring at 0x20020c00 is 24 descriptors (followed the firmware's own chain, 36 bytes apart)
```

## The oracle

`src/rehostry_adam6000_tm4c/attack.py` boots **one** device and puts every
question to it, in order, down one connection. Every request differs from every
other in transaction id, unit id, function code, address and quantity; every
reply must carry its own request's transaction and unit id back and echo its
function byte (plain when the device answers, with the error bit when it
refuses); and a successful answer must be **sized from the quantity field that
request chose** — a check no canned or replayed reply can pass. The count it
sustained is in the `RESULT:` line, `landed` is a conjunction containing the
seam field, and `main()` exits non-zero below M4.

The controls are the point. Each knob restores one defect and nothing else:

```
default                        40/40   landed
HAL_ADAM_STATIC_TXBUF=1         2/40   not landed   (reclaim gone)
HAL_ADAM_EMAC_NO_CURSOR=1       5/40   not landed   (cursor gone)
HAL_ADAM_EMAC_RING_LEN=16       1/40   not landed   (fixed scan back)
```

A run that cannot be made to fail proves nothing; these can.

## Why nearly every answer is an exception, and why that is still evidence

This module keeps its identity — model number, channel count, the whole I/O
profile — in a serial NOR flash beside the microcontroller, and that flash is
not part of the distributed firmware image. The device boots and says so:

```
 Boot_ SFinit() ff,ff,ff,ff,...
[SIFlashRead_s] profile=ffffffff
 Profi_XX: not found in flash
 GetDevInfo() Err: ulLen=-1
---------------g_sModelInfo.ucTotal_StatusPins = 0
g_usModel = 255
```

A module with no I/O points has almost no legal data address, so nearly every
read is exception 2 — 31 of the 40 graded exchanges, with the 8 negative
controls making up the rest and exactly one address answering with data.
Filling that flash with invented vendor data would produce prettier output and
would be a fabrication.

What makes it evidence anyway is the **discrimination**: a supported function
code aimed at an unusable address is refused as *illegal data address* (2),
while an unsupported function code is refused as *illegal function* (1), with
the function byte echoed and the top bit set in both. Nothing that merely
pretends to be a Modbus server tells those apart.

## What the round-trip does and does not show

**Does.** The response bytes are the firmware's, captured at the bus boundary —
read by `tiva_emac._transmit` out of the guest's own transmit descriptor buffer,
not from the peer's reassembly one layer up:

```
EMAC TX #6: 63 bytes
  0200005e1002 00d0c9feffff 0800            dst, src (the device), IPv4
  45...0a000001 0a000002                    from 10.0.0.1
  01f6 9c40 ... 5018 09f4 ....              TCP sport 502, the device's own seq
  000100000003 01 81 02                     <- the Modbus response
```

And the firmware genuinely parses each request rather than emitting a constant.
Both MBAP fields track across values, and the exception code still
discriminates by function:

| sent | received |
| --- | --- |
| txn `0xbeef`, unit 7, fc `0x01` | `beef 0000 0003 07 81 02` |
| txn `0x0042`, unit 19, fc `0x01` | `0042 0000 0003 13 81 02` |
| txn `0x7a3c`, unit 200, fc `0x41` | `7a3c 0000 0003 c8 c1 01` |

The firmware carried both header fields through, recomputed the length, OR'd
the function byte, and chose the exception code from its own dispatch table.
No host code could have synthesised that — and it did it two hundred times in
a row, which no buffered reply could have.

**Does not.** What round-trips is the **protocol** layer — MBAP framing and
function dispatch — not the **application** layer:

- **Almost no Modbus data handler is reached.** Address validation rejects
  first for nearly everything. *Nearly*: sweeping addresses across the graded
  run found one that is legal, and the firmware answered it with data —

  ```
  >>> b203 0000 0006 08  03 00cb 0008      read 8 holding registers at 203
  <<< b203 0000 0013 08  03 10 0000 0000 0000 0000 0000 0000 0000 6000
  ```

  a byte count of 0x10 = 16 = 2 x 8, **sized from the quantity field this run
  chose**, followed by sixteen bytes out of the firmware's own register map.
  That is the data handler, not the dispatcher. It is one address out of forty
  probes and it is not what an ADAM-6050 is *for* — the coil space is still
  entirely rejected — but the earlier flat claim that no data handler is ever
  reached was wrong, and this run disproves it.
- **The attack does not land a physical action.** Modbus/TCP's lack of
  authentication is real and is why this device is worth rehosting, but this
  rehost demonstrates reaching the parser, not driving a relay.
- **This is still a weaker M4 than device-bmxnoe**, whose M4 was FC03 returning
  register data across the map rather than at a single address. The gap is
  entirely the blank serial flash.

Closing that gap needs the serial NOR contents from a real module. Everything
above it already works.

## The boot, and the network coming up

```
QualComm Project Boot Code Start
 BL: Advantech ADAM-6000D A1.03B10!! 0
6000_DIO V6.15B23 start!!
 ip=100000a, sm=ff, gw=0
MACID:0.d0.c9.fe.ff.ff
[lwIPInit] g_ui32IPMode = 0, g_ui32IPAddr=100000a, ...
IP ready.
```

```
EMAC TX #1: 42 bytes ffffffffffff000000000000080600010800060400010000000000000a000001
             |          |                                              +-- 10.0.0.1
             |          +-- ethertype 0x0806 = ARP, opcode 1 = request
             +-- broadcast
EMAC TX #3: ARP reply to the peer          <- the device answers what it receives
EMAC RX #4: 66 bytes into 0x20011fbc       <- a Modbus request, into the ring
```

`ip=100000a` is 10.0.0.1, Advantech's factory default, and `00:D0:C9` is
Advantech's real OUI — neither is written into the guest by the host.

## The bug that cost the most: two vector tables

The image carries **two** vector tables — the bootloader's at `0x00000000` and
the application's at `0x00010000` — and the application relocates to its own by
writing VTOR. The backend keeps its own copy of the vector base and only learns
about it through `set_vtor()`, so a PPB model that merely stored the register
left every interrupt dispatching through the *bootloader's* table.

That failed in the worst possible way: **both** tables have a live entry for
IRQ 40, so interrupts kept working and kept landing in the bootloader's
Ethernet driver, whose `netif` the application never initialises. Its
`netif->state` was still the `.data` image (`0xFFFFFFFF`), and the receive walk
faulted:

```
64c8: ldr r0, [r0, #28]     ; netif->state  -> 0xFFFFFFFF
64cc: ldr r5, [r0, #8]      ; [0xFFFFFFFF+8] wraps to 0x07 -- inside the vector table
64e2: ldr r0, [r5, #0]      ; UC_ERR_READ_UNMAPPED at 0x00F0BD00
```

`0x00F0BD00` is the unaligned word at offset 7 of the table: the top byte of
the reset vector followed by three bytes of the NMI vector. It reads exactly
like a descriptor-layout bug in the Ethernet driver, and it is a driver that
was never running. Four hypotheses were tested and disproved before a memory
watchpoint and a pointer-chain probe found it.

## Known limits

- **No I/O points**, for the serial-flash reason above — so the coil space is
  refused wholesale and only one holding-register address answers with data.
- The web panel renders device state as JSON rather than a coil grid.
- Two walls still block the **provisioned** path (the derived device profile);
  the default path is what is graded here.
- **The graded sweep is 40 requests, not an endurance test.** 200 was measured
  separately over the same seam and held, but nothing here establishes a bound;
  a longer run could still find one. Set `HAL_ADAM_SUSTAINED_N` to raise it.
- **SNMP and MQTT are ungraded, not refuted.** SNMP would need UDP, which this
  rehost's peer does not model at all; MQTT is an outbound client and no broker
  is modelled. Both remain in the interface denominator, so **M8 is 2 of 4 and
  not met**.
- **The web UI is served but not driven.** Only `GET /` returns content; the
  rest of the site is in the blank serial flash. No form POST, no login and no
  configuration change has been exercised, so nothing here shows the web
  server can *alter* device state — that would be the M6 question and it is
  not claimed.
- **The two graded servers share one bus.** One EMAC0, one lwIP, one driver,
  one live IRQ (40), no RTOS. See "The honest limit on this claim" above; a
  strict "different bus" reading of RULES §1a scores this device M4.
- **The Modbus oracle's per-exchange bound is load-sensitive, and a bound is a
  classifier.** `exchange()` allows 30 s per request against a warm reply that
  takes well under a second. On an idle host that is ~300x headroom; on this
  host at load average 22 (several emulators from other work running at once) a
  confirmation run scored **0/40** while the device was demonstrably still
  answering — its reply arrived on the wire *after* the oracle had given up
  (`PEER: TCP 502->40001 [ACK|PSH]` following the timeout). Re-run on a settled
  box it is 40/40 again. The bound was **not** widened to rescue the run: a
  bound moved to make a test pass is how a classifier becomes a fabrication.
  Treat any sub-40 Modbus score without a matching `uptime` as unreadable.
- **The HTTP timeouts are derived from this device, not guessed**: a warm
  exchange measures ~3.3 s and the first one after boot ~30 s (the peer's SYN
  and first segment are retransmitted while the firmware copies its image to
  serial flash), against bounds of 90 s and 150 s. A bound is a classifier;
  these leave ~5x headroom on the worst measured case.

## What is established (and checked by `tools/extract_firmware.py`)

**The SoC was identified from the image alone.** There is no part number in it:

- GPIO ports **A through Q** are addressed (`0x40061000`..`0x40066000` = K/L/M/
  N/P/Q). Only the TM4C129x family has ports past J.
- **EMAC0 at `0x400EC000`** — an on-chip Ethernet MAC, which in the Tiva line
  exists only on the Connected (129x) series.
- Of 112 external interrupt slots, **exactly one is live: IRQ 40**, which is
  TM4C129x's EMAC0. The extractor pins that as the device's fingerprint.
- `SYSCTL` at `0x400FE000`, and the registers the firmware drives are TM4C129x's
  by offset: `RSCLKCFG` (0x0B0), `PLLFREQ0` (0x160, bit 23 = PLLPWR),
  `PLLSTAT` (0x168, bit 0 = LOCK).
- The image contains the literal string `Cortex-M4` and TivaWare's Hungarian
  notation (`g_ui32IPMode`) throughout its debug output.

**The software stack**, from its own strings: bare-metal TivaWare (no RTOS —
there is no FreeRTOS string anywhere) + lwIP + an HTTP server with an embedded
web UI + Modbus/TCP + SNMP + mbedTLS 3.6.0 + an Azure IoT client. The vendor's
own build path survives: `D:\ADAM-6000DIO_V615\Code\Lib\mbedtls-3.6.0\...`.

## Honest scope note

This device needed a synthesised TivaWare ROM layer, a clock tree, an Ethernet
MAC with DMA descriptor rings, and a host-side TCP peer before a Modbus/TCP
round-trip was possible. The round trip is real and is the firmware's own; what
took a second pass was proving it could be repeated, which is the difference
between a device that works and a device that answered once.
