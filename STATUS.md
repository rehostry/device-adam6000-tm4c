<!-- rehostry-census: milestone=M4 landed=true verdict=M4-OK verified=2026-08-28 method=live-run -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — device-adam6000-tm4c  (**M4**)

**Milestone reached: M4 — a sustained Modbus/TCP conversation.** The vendor
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
