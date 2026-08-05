<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# device-adam6000-tm4c

A rehost of the **Advantech ADAM-6000** remote I/O module's firmware
(`6000_DIO V6.15B23`, TI TM4C129x), running under HALucinator on the unicorn
backend.

The vendor image boots its own bootloader, starts the application, brings up
its own lwIP stack, and **answers Modbus/TCP requests on port 502** over a
modelled Ethernet controller. Nothing above the registers is simulated: the
MAC, PHY, serial flash, uDMA and internal flash controller are modelled at the
register level, and the protocol stack, the Modbus server and the boot logic
are the firmware's own.

Milestone **M4** (a Modbus/TCP round-trip). See [STATUS.md](STATUS.md) for the
evidence, the identification work, and the bug that cost the most.

## What the device is

An ADAM-6050 is a DIN-rail box with 12 digital inputs and 6 relay outputs,
wired to plant equipment and driven over Ethernet by a PLC or SCADA host. Its
control interface is Modbus/TCP, which has **no authentication of any kind** —
no credential, no session, no signature. Anyone who can open a TCP connection
to port 502 can read every input and drive every output; on the real module an
output coil is a relay contact, so a five-byte request is a physical action.

That is not a defect in this firmware. It is what Modbus is, and it is why a
faithful rehost of a device that ships it is worth having.

## Install

The firmware image is **not redistributed**. Supply your own copy and generate
the packaged artefacts from it:

```bash
pip install "halucinator[unicorn] @ git+https://github.com/rehostry/halucinator.git@dev"
pip install -e .
python tools/extract_firmware.py --firmware /path/to/adam6000_dio_v615B23.bin
```

`tools/extract_firmware.py` pins the image by SHA-256, verifies its vector
table, seven build landmarks and every byte-pinned recovered symbol, and writes
`adam6000_tm4c.bin`, `rom_stubs.bin` and `adam6000_tm4c_addrs.yaml` into
`src/rehostry_adam6000_tm4c/configs/`. It refuses to run on an image that does
not match — which is what stops this device intercepting the wrong function.

The device runs the installed `halucinator@dev` via `sys.executable` (override
with `HAL_PY=/path/to/venv/bin/python`). No `HALUCINATOR_SRC` / `PYTHONPATH`
source-tree injection.

## Run

```bash
rehostry-adam6000-tm4c run --seconds 15             # boot + stream the console
rehostry-adam6000-tm4c run --bridge --seconds 1800  # also expose the host bridge
rehostry-adam6000-tm4c-panel                        # the polling web panel
python -m rehostry_adam6000_tm4c.attack             # speak Modbus/TCP to it
```

`attack` boots one device per probe, concurrently, and prints a check list with
the raw exchange. All 18 checks pass on a working tree:

```
>>> 000100000006 01 01 00000008     read coils 0..7
<<< 000100000003 01 81 02           exception 2, illegal data address

>>> 000100000006 01 41 00000001     function 0x41 -- not a Modbus function
<<< 000100000003 01 c1 01           exception 1, illegal function
```

## What is modelled, and where the seams are

| Model | What it stands in for |
| --- | --- |
| `tiva_rom` | The TM4C's masked driverlib ROM at `0x01000000`, answered structurally: `APITABLE[i]` → a synthetic sub-table, sub-table entry → a distinct `bx lr` stub. Calls that must return a value are implemented in `bp_handlers/tiva_rom_api.py`; the rest return immediately. |
| `tiva_emac` | The Synopsys DesignWare MAC and its PHY: descriptor rings, interrupt status, source-MAC insertion. Ring pitch is **36** bytes — TivaWare's lwIP port carries a `pbuf *` after the eight-word descriptor. |
| `net_peer` | An Ethernet/ARP/IPv4/TCP peer on the other end of the wire, with retransmission. Its checksums are unit-tested against RFC 1071 and verified to zero over a data-carrying segment. |
| `spi_flash` | The serial NOR on SSI3, driven through the ROM's SSI entries. **Starts erased** — see "Known limits". |
| `tiva_udma` | The uDMA channel pair that carries SSI3 transfers. |
| `tiva_flashctrl` | The internal flash controller the firmware saves its configuration through. |
| `cortexm_ppb` | NVIC, SysTick and STIR — and **VTOR**, which must be forwarded to the backend rather than merely stored. |
| `modbus_bridge` | A host-side TCP listener that carries Modbus/TCP to the device over the modelled Ethernet. |

## Known limits

- **One Modbus exchange per boot.** The device answers the first request after
  boot and does not pick up later ones, on the same connection or a fresh one.
  Reproduced at SysTick rates of 1500/2000/3000/4000 ROM calls per tick and
  with up to 200 retransmissions, so it is neither the clock nor frame loss;
  the cause is not yet isolated. `attack.py` works around it by booting one
  device per probe.
- **The device reports no model and no I/O points**, so every Modbus address is
  illegal and every answer is exception 2. Its identity — model number, channel
  count, the whole I/O profile — lives in a serial NOR flash that the vendor
  image does not contain. The flash is modelled as erased, which is the honest
  state of a part whose contents we do not have; inventing plausible vendor
  data would make the output look better and would be a fabrication. The
  firmware says so itself (`GetDevInfo() Err`, `g_usModel = 255`), and the
  exception-code discrimination shows the real parser is running regardless.
- **What round-trips is the protocol layer, not the application layer.** MBAP
  framing and function dispatch are exercised end to end and proven to be the
  firmware's own; the Modbus data handlers behind address validation are never
  reached, so nothing here demonstrates driving an output. The
  no-authentication property of Modbus/TCP is real, but this rehost shows
  reaching the parser, not actuating a relay.
- **The device profile is derived, and populates the module -- but the boot
  does not finish.** An ADAM-6000 keeps its identity off-chip and the vendor
  image does not carry it, which is why every Modbus address is illegal.
  `peripheral_models/device_profile.py` reconstructs the record from the
  firmware's own parser -- placement, XML vocabulary, structure, the `DI`/`DO`
  block types and the pin-list grammar are all read out of the code. With it
  the firmware accepts the profile and describes itself correctly:

  ```
   Copy OK >> model (0), bDO_OCP=1
  ---------------g_sModelInfo.ucTotal_StatusPins = 6
  @0x20015e40 [ADAM6050]:  HvA1.0
    I[12] 1: 0.0 0.1 0.2 0.3 0.4 0.5 0.6 0.7 1.0 1.1 1.2 1.3
    O[6]  0: 2.0 2.1 2.2 2.3 2.4 2.5
  ```

  Twelve inputs, six outputs, model index 0 of its own 6050/6051/6052/6060/6066
  table. But the boot then stops at `sntp sync : 255` and never reaches
  `IP ready.`, so there is no Modbus at all on this path. It is therefore
  **opt-in** (`HAL_ADAM_PROFILE=1`); the default remains the erased part, which
  boots and answers.
- The web panel renders device state as JSON rather than a coil grid.

## Debugging aids

Off by default. Each was written to answer a question that took several wrong
guesses to ask properly, and each is kept so the next person does not have to
write it again.

| Variable | What it does |
| --- | --- |
| `HAL_ADAM_PROBE=1` | Logs the lwIP receive walk's pointer chain and the `.data` copy that overwrites it. |
| `HAL_ADAM_WATCH=0xADDR:LEN` | A write watchpoint: every store into a range, with the PC that made it. |
| `HAL_ADAM_SAMPLE_STATE=0xADDR` | Samples one word over time — tells "never set" from "not set yet". |
| `HAL_ADAM_SFLASH_FILL=0xNN` | Changes the erased-flash fill, so a suspect value can be shown to come from the flash or not. |
| `HAL_ADAM_TICK_EVERY` | ROM calls per SysTick. A correctness parameter, not a speed knob — see `bp_handlers/tiva_rom_api.py`. |
| `HAL_ADAM_RTO_POLLS`, `HAL_ADAM_RTO_BUDGET` | The peer's retransmission timer and retry budget. |

## Tests

```bash
python -m pytest tests -q        # 29 structural tests, no emulator required
```

## License

AGPL-3.0-or-later — see `LICENSE`. Imports HALucinator (GPLv3) at runtime but
contains none of its code. The firmware is not committed; see
[PROVENANCE.md](PROVENANCE.md).
