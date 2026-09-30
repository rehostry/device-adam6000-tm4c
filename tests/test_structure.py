# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural tests: NO emulator required.

These check the things that silently rot -- config/symbol agreement, the spawn
recipe's invariants, the register and protocol couplings the models depend on,
and the pure functions the attack oracle trusts. Booting the firmware is
covered by STATUS.md, not here (the image is not redistributed with the
package).

Several of these exist because the corresponding mistake was actually made
during bring-up; each such test names it.
"""
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
CONFIGS = os.path.join(SRC, "rehostry_adam6000_tm4c", "configs")
sys.path.insert(0, SRC)


def _config():
    with open(os.path.join(CONFIGS, "adam6000_tm4c_config.yaml")) as fh:
        return yaml.safe_load(fh)


def _addrs():
    with open(os.path.join(CONFIGS, "adam6000_tm4c_addrs.yaml")) as fh:
        return yaml.safe_load(fh)


# --- spawn-recipe invariants (playbook non-negotiables) --------------------

def test_spawn_argv_invokes_the_module_not_a_source_tree():
    """The core is the INSTALLED halucinator, invoked as `python -m
    halucinator.main` -- never a HALUCINATOR_SRC source tree."""
    from rehostry_adam6000_tm4c import spawn
    argv = spawn.spawn_argv(python="python")
    assert argv[:4] == ["python", "-m", "halucinator.main", "-c"], argv
    assert "--emulator" in argv


def test_spawn_env_strips_source_injection():
    """A polluted HALUCINATOR_SRC / PYTHONPATH must never reach the child and
    resurrect an out-of-tree core."""
    from rehostry_adam6000_tm4c import spawn
    os.environ["HALUCINATOR_SRC"] = "/some/hal/src"
    os.environ["PYTHONPATH"] = "/some/hal/src"
    try:
        env = spawn.spawn_env()
    finally:
        os.environ.pop("HALUCINATOR_SRC", None)
        os.environ.pop("PYTHONPATH", None)
    assert "HALUCINATOR_SRC" not in env
    assert "PYTHONPATH" not in env


def test_spawn_argv_can_take_distinct_rx_tx_ports():
    """`run_attack` boots one device per probe, concurrently. Shared rx/tx
    ports make every device after the first fail to bind."""
    from rehostry_adam6000_tm4c import spawn
    argv = spawn.spawn_argv(python="python", rx_port=31000, tx_port=32000)
    assert "31000" in argv and "32000" in argv


def test_config_files_are_shipped_as_package_data():
    """Every config named in paths.CONFIG_FILES must exist in configs/."""
    from rehostry_adam6000_tm4c import paths
    for name in paths.CONFIG_FILES:
        assert os.path.exists(os.path.join(CONFIGS, name)), name


# --- config/symbol agreement ------------------------------------------------

def test_every_intercept_symbol_exists_in_addrs():
    """A typo'd symbol registers no breakpoint and fails silently at run time.

    This is not hypothetical here: `lwip_rx_walk` was added with a byte guard
    written in the wrong order, the extractor dropped it, and the resulting
    probe never fired -- which read as "the code is never reached".
    """
    cfg = _config()
    names = set(_addrs()["symbols"].values())
    for icept in cfg["intercepts"]:
        sym = icept.get("symbol", icept.get("function"))
        assert sym in names, sym


def test_bridge_config_symbols_also_exist():
    with open(os.path.join(CONFIGS, "adam6000_tm4c_bridge.yaml")) as fh:
        cfg = yaml.safe_load(fh)
    names = set(_addrs()["symbols"].values())
    for icept in cfg.get("intercepts", []):
        sym = icept.get("symbol", icept.get("function"))
        assert sym in names, sym


def test_machine_matches_the_recovered_vector_table():
    """The bootloader's table at 0x00000000 is what the CPU starts from."""
    machine = _config()["machine"]
    assert machine["init_sp"] == 0x2001C46C
    assert machine["entry_addr"] == 0x0000F0A9      # reset | Thumb


def test_rom_stub_region_is_mapped_and_matches_the_model():
    """ROM call landing pads live in their own region; if the config and the
    model disagree the firmware branches into unmapped memory."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_rom
    regions = _config()["memories"]
    stubs = regions["rom_stubs"]
    assert stubs["base_addr"] == tiva_rom.STUB_BASE
    assert stubs["size"] >= tiva_rom.STUB_SIZE


def test_rom_stub_addresses_carry_the_thumb_bit():
    """A function pointer without bit 0 set makes `blx` switch to ARM state,
    which an M-profile core does not have: UC_ERR_INSN_INVALID at a valid
    `bx lr`."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_rom
    for table, entry in ((0, 0), (13, 6), (42, 22)):
        assert tiva_rom.stub_for(table, entry) & 1


def test_rom_stub_addresses_are_distinct_per_entry():
    from rehostry_adam6000_tm4c.peripheral_models import tiva_rom
    seen = {tiva_rom.stub_for(t, e) for t in range(8) for e in range(64)}
    assert len(seen) == 8 * 64


# --- the PPB: VTOR is the one that bit ------------------------------------

def test_vtor_write_is_forwarded_to_the_backend():
    """THIS IS THE BUG THAT COST THE MOST. The image carries two vector tables
    -- the bootloader's at 0 and the application's at 0x10000 -- and the
    application relocates to its own. A PPB model that merely remembers the
    value leaves every interrupt dispatching through the bootloader's table.
    Both tables have a live IRQ 40, so interrupts kept working and kept landing
    in the bootloader's Ethernet driver, whose interface struct the application
    never initialises.
    """
    from rehostry_adam6000_tm4c.peripheral_models import cortexm_ppb

    class FakeBackend:
        def __init__(self):
            self.vtor = None

        def set_vtor(self, value):
            self.vtor = value

    ppb = cortexm_ppb.CortexMPpb("ppb", cortexm_ppb.PPB_BASE, 0x100000)
    backend = FakeBackend()
    ppb.set_backend(backend)
    ppb.hw_write(cortexm_ppb.VTOR - cortexm_ppb.PPB_BASE, 4, 0x00010000)
    assert backend.vtor == 0x00010000
    assert ppb.hw_read(cortexm_ppb.VTOR - cortexm_ppb.PPB_BASE, 4) == 0x00010000


def test_vtor_written_before_the_backend_arrives_is_not_lost():
    """The model is handed the backend from breakpoint context, which may be
    after the firmware has already relocated its table."""
    from rehostry_adam6000_tm4c.peripheral_models import cortexm_ppb

    class FakeBackend:
        def __init__(self):
            self.vtor = None

        def set_vtor(self, value):
            self.vtor = value

    ppb = cortexm_ppb.CortexMPpb("ppb", cortexm_ppb.PPB_BASE, 0x100000)
    ppb.hw_write(cortexm_ppb.VTOR - cortexm_ppb.PPB_BASE, 4, 0x00010000)
    backend = FakeBackend()
    ppb.set_backend(backend)
    assert backend.vtor == 0x00010000


def test_stir_write_queues_the_interrupt_the_firmware_asked_for():
    """0xE000EF00 is how this firmware hands work to its Ethernet ISR. A model
    that swallows it removes the device's only interrupt."""
    from rehostry_adam6000_tm4c.peripheral_models import cortexm_ppb

    class FakeBackend:
        _pending_irqs: list = []
        _uc = None

    ppb = cortexm_ppb.CortexMPpb("ppb", cortexm_ppb.PPB_BASE, 0x100000)
    backend = FakeBackend()
    backend._pending_irqs = []
    ppb.set_backend(backend)
    ppb.hw_write(cortexm_ppb.STIR - cortexm_ppb.PPB_BASE, 4, 40)
    assert backend._pending_irqs == [40]


def test_only_one_interrupt_is_outstanding_at_a_time():
    """The backend drains its whole queue back to back with no guest
    instructions in between, so two entries are a nested exception entry rather
    than two interrupts (playbook §2.98)."""
    from rehostry_adam6000_tm4c.peripheral_models import cortexm_ppb

    class FakeBackend:
        _uc = None

    ppb = cortexm_ppb.CortexMPpb("ppb", cortexm_ppb.PPB_BASE, 0x100000)
    backend = FakeBackend()
    backend._pending_irqs = []
    ppb.set_backend(backend)
    off = cortexm_ppb.STIR - cortexm_ppb.PPB_BASE
    ppb.hw_write(off, 4, 40)
    ppb.hw_write(off, 4, 40)
    assert backend._pending_irqs == [40]


def test_nvic_iser_records_the_armed_interrupt():
    from rehostry_adam6000_tm4c.peripheral_models import cortexm_ppb
    ppb = cortexm_ppb.CortexMPpb("ppb", cortexm_ppb.PPB_BASE, 0x100000)
    word, bit = divmod(40, 32)
    ppb.hw_write(cortexm_ppb.NVIC_ISER0 - cortexm_ppb.PPB_BASE + word * 4,
                 4, 1 << bit)
    assert 40 in ppb.armed()


# --- the EMAC ---------------------------------------------------------------

def test_descriptor_stride_is_the_ports_pitch_not_the_hardware_descriptor():
    """TivaWare's lwIP port carries a `pbuf *` after the eight-word descriptor,
    so the ring pitch is 36 bytes, not 32. It was derived from the firmware's
    own link pointer (0x20020F84 - 0x20020F60), and the crash site confirms it:
    `mov.w fp, #36` two instructions before the walk."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_emac
    assert tiva_emac.descriptor_stride() == 36


def test_phy_reports_a_link_that_is_up_and_autonegotiated():
    """The driver waits for both bits before it will bring the interface up."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_emac
    assert tiva_emac.BMSR_VALUE & (1 << 2)          # link status
    assert tiva_emac.BMSR_VALUE & (1 << 5)          # autoneg complete


def test_device_mac_is_advantechs_oui():
    """00:D0:C9 is Advantech's registered OUI; the firmware prints it itself,
    so a model that made one up would contradict the console."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_emac
    assert tiva_emac.DEVICE_MAC[:3] == bytes.fromhex("00d0c9")


def test_ring_length_is_followed_off_the_descriptor_chain():
    """The ring size is NOT a constant in this model. Both rings are chained --
    word 3 of each descriptor is the next one's address and the last links back
    to the first -- and following that gives 24, the firmware's own `#0x18`
    (0x0001CC5E, 0x0001CCDC). The model shipped with a fixed scan of 16 and
    silently stranded descriptors 16..23."""
    from rehostry_adam6000_tm4c.peripheral_models.tiva_emac import TivaEmac

    base, stride, n = 0x20020C00, 36, 24
    ring = bytearray(stride * n)
    for i in range(n):
        nxt = base + ((i + 1) % n) * stride
        ring[i * stride + 12:i * stride + 16] = nxt.to_bytes(4, "little")

    class FakeBackend:
        def read_memory(self, addr, size, count, raw=False):
            off = addr - base
            return bytes(ring[off:off + count])

    emac = TivaEmac("emac", 0x400EC000, 0x1000)
    emac.set_backend(FakeBackend())
    assert emac._ring_len(base) == n


def test_the_walk_has_a_dma_cursor_and_does_not_reuse_the_lowest_slot():
    """A Synopsys DMA services descriptors in ring order from its own current
    pointer. Going back to whichever slot happens to be free deadlocks against
    the driver's `ui32Read`, which is what made this device answer five times
    and stop."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_emac
    import inspect

    src = inspect.getsource(tiva_emac.TivaEmac._walk)
    assert "self._cursors" in src
    # And the old behaviour is still reachable, as a control.
    assert hasattr(tiva_emac.TivaEmac, "_walk_no_cursor")
    assert tiva_emac.NO_CURSOR is False       # off unless asked for


def test_transmit_complete_is_reported_unless_the_control_asks_otherwise():
    """`tivaif_interrupt` (0x0001D1B2) reaches the reclaim only when DMA status
    bit 0 is set, and `tivaif_transmit` (0x0001CC1A) refuses to send into a
    descriptor whose pbuf was never freed. Withholding the bit does not cost
    memory; it costs the device its transmitter."""
    from rehostry_adam6000_tm4c.peripheral_models import tiva_emac
    assert tiva_emac.EMAC_INT_TRANSMIT == 1
    assert tiva_emac.STATIC_TXBUF is False    # the leak is a control, not the default


def test_a_successful_read_must_be_sized_from_its_own_request():
    """The structural check the oracle applies to a data answer: the byte count
    is computed from the quantity field the request chose, so a canned or
    replayed reply cannot satisfy it. The good case is a real capture."""
    import struct
    from rehostry_adam6000_tm4c.attack import _check_success, FN_READ_HOLDING

    pdu = struct.pack(">BHH", FN_READ_HOLDING, 0x00CB, 8)
    good = bytes.fromhex("b2030000001308"           # MBAP: txn, proto, len, unit
                         "0310" + "00" * 14 + "6000")
    assert _check_success(FN_READ_HOLDING, pdu, good) is None
    # Same reply, but the request asked for a different number of registers.
    other = struct.pack(">BHH", FN_READ_HOLDING, 0x00CB, 4)
    assert _check_success(FN_READ_HOLDING, other, good) is not None


def test_the_oracle_asks_one_guest_more_than_a_ring_of_questions():
    """Below 24 exchanges the transmit ring need never have wrapped, so a
    sustained result would prove nothing about reclaim."""
    from rehostry_adam6000_tm4c import attack
    assert attack.SUSTAINED_N > attack.TX_RING_DESCRIPTORS


def test_every_request_in_the_sweep_differs_from_every_other():
    """Fresh content per request is what makes a reply attributable."""
    from rehostry_adam6000_tm4c import attack
    seen = {attack._probe_for(i)[:3] for i in range(attack.SUSTAINED_N)}
    assert len(seen) == attack.SUSTAINED_N


# --- the peer's protocol arithmetic ----------------------------------------

def test_checksum_matches_the_rfc_1071_worked_example():
    from rehostry_adam6000_tm4c.peripheral_models import net_peer
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert net_peer.checksum(data) == 0x220D


def test_ip_and_tcp_checksums_verify_to_zero_over_a_data_segment():
    """A header that only validates for an empty payload passes the handshake
    and then silently drops every request."""
    from rehostry_adam6000_tm4c.peripheral_models import net_peer
    sent = []
    peer = net_peer.NetPeer(send=sent.append)
    peer.device_mac = bytes.fromhex("00d0c9feffff")
    peer.state = "ESTABLISHED"
    peer.snd_nxt, peer.rcv_nxt = 0x1001, 0x196F
    peer.remote_port, peer.local_port = 502, 40000
    peer.send(bytes.fromhex("000100000006010100000008"))
    frame = sent[-1]
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    assert net_peer.checksum(ip[:ihl]) == 0
    tcp = ip[ihl:]
    pseudo = ip[12:20] + b"\x00" + bytes([ip[9]]) + len(tcp).to_bytes(2, "big")
    assert net_peer.checksum(pseudo + tcp) == 0
    assert int.from_bytes(ip[2:4], "big") == len(ip)


def test_an_unacked_segment_is_retransmitted():
    """A peer without retransmission is not a TCP peer: this device drops
    frames while it is busy copying its firmware to serial flash, and the first
    request needed dozens of retries before it was looked at."""
    from rehostry_adam6000_tm4c.peripheral_models import net_peer
    sent = []
    peer = net_peer.NetPeer(send=sent.append)
    peer.device_mac = bytes.fromhex("00d0c9feffff")
    peer.state = "ESTABLISHED"
    peer.snd_nxt, peer.rcv_nxt = 0x1001, 0x196F
    peer.remote_port, peer.local_port = 502, 40000
    peer.rto_polls = 3
    peer.send(b"\x01\x02\x03\x04")
    first = len(sent)
    for _ in range(3):
        peer.on_poll()
    assert len(sent) == first + 1


def test_an_acked_segment_is_not_retransmitted():
    from rehostry_adam6000_tm4c.peripheral_models import net_peer
    sent = []
    peer = net_peer.NetPeer(send=sent.append)
    peer.device_mac = bytes.fromhex("00d0c9feffff")
    peer.state = "ESTABLISHED"
    peer.snd_nxt, peer.rcv_nxt = 0x1001, 0x196F
    peer.remote_port, peer.local_port = 502, 40000
    peer.rto_polls = 3
    peer.send(b"\x01\x02\x03\x04")
    peer.unacked = b""                      # what the ack path does
    before = len(sent)
    for _ in range(10):
        peer.on_poll()
    assert len(sent) == before


def test_the_syn_is_retransmitted_too():
    """A SYN sent once into a device that is still busy is a connection that
    never opens -- and it looks exactly like a device with no server."""
    from rehostry_adam6000_tm4c.peripheral_models import net_peer
    sent = []
    peer = net_peer.NetPeer(send=sent.append)
    peer.device_mac = bytes.fromhex("00d0c9feffff")
    peer.rto_polls = 2
    peer.connect(502)
    first = len(sent)
    for _ in range(2):
        peer.on_poll()
    assert len(sent) == first + 1
    assert peer.state == "SYN_SENT"


# --- the SPI NOR flash ------------------------------------------------------

def test_serial_flash_starts_erased():
    """0xFF is the honest state of a part whose contents are not shipped, and
    it is why the device reports no model and no I/O points."""
    from rehostry_adam6000_tm4c.peripheral_models import spi_flash
    flash = spi_flash.SpiNorFlash(size=4096)
    assert set(flash.data) == {0xFF}


def test_jedec_id_is_readable_and_repeats():
    from rehostry_adam6000_tm4c.peripheral_models import spi_flash
    flash = spi_flash.SpiNorFlash(size=4096)
    flash.select(True)
    flash.xfer(spi_flash.CMD_READ_JEDEC)
    assert [flash.xfer(0) for _ in range(3)] == list(spi_flash.JEDEC_ID)


def test_programming_only_clears_bits():
    """NOR programming cannot set a bit; only an erase can."""
    from rehostry_adam6000_tm4c.peripheral_models import spi_flash
    flash = spi_flash.SpiNorFlash(size=4096)
    flash.select(True)
    flash.xfer(spi_flash.CMD_WRITE_ENABLE)
    flash.select(False)
    flash.select(True)
    flash.xfer(spi_flash.CMD_PAGE_PROGRAM)
    for byte in (0, 0, 0):
        flash.xfer(byte)
    flash.xfer(0x0F)
    assert flash.data[0] == 0x0F
    flash.select(False)
    flash.select(True)
    flash.xfer(spi_flash.CMD_WRITE_ENABLE)
    flash.select(False)
    flash.select(True)
    flash.xfer(spi_flash.CMD_PAGE_PROGRAM)
    for byte in (0, 0, 0):
        flash.xfer(byte)
    flash.xfer(0xF0)
    assert flash.data[0] == 0x00           # cleared further, never restored


# --- the attack's own framing ----------------------------------------------

def test_mbap_header_length_counts_the_unit_id_and_pdu():
    from rehostry_adam6000_tm4c import attack
    frame = attack.mbap(7, bytes.fromhex("0100000008"))
    assert int.from_bytes(frame[0:2], "big") == 7
    assert int.from_bytes(frame[2:4], "big") == 0
    assert int.from_bytes(frame[4:6], "big") == len(frame) - 6


def test_every_probe_expects_the_function_byte_echoed_with_the_error_bit():
    from rehostry_adam6000_tm4c import attack
    for _label, pdu, want_fc, want_code in attack.PROBES:
        assert want_fc == (pdu[0] | 0x80)
        assert want_code in (1, 2)


def test_the_negative_control_is_not_a_modbus_function():
    """The whole discrimination argument rests on 0x41 being unsupported."""
    from rehostry_adam6000_tm4c import attack
    assert attack.FN_BOGUS not in (
        attack.FN_READ_COILS, attack.FN_READ_DISCRETE_INPUTS,
        attack.FN_READ_HOLDING, attack.FN_WRITE_SINGLE_COIL)
    bogus = [p for p in attack.PROBES if p[1][0] == attack.FN_BOGUS]
    assert bogus and bogus[0][3] == 1      # illegal function, not address


# ---------------------------------------------------------------------------
# The ladder. Added 2026-09-02: `milestone` was the string literal "M4" --
# a ceiling no amount of evidence could lift -- assigned three lines below a
# `landed` that already conjoined everything the run had measured. The HTTP
# server the device had been serving all along could not have raised the rung
# even after it was graded, because nothing read the evidence.
# ---------------------------------------------------------------------------
def test_milestone_is_derived_and_never_a_literal():
    from rehostry_adam6000_tm4c import attack

    full = {"booted": True, "modbus_round_trip": True, "http_round_trip": True}
    assert attack.grade(dict(full))[0] == "M5"
    # EITHER server alone is M4 -- which is what makes the independence arms
    # readable: `--interfaces http` must still reach M4.
    assert attack.grade({**full, "http_round_trip": False})[0] == "M4"
    assert attack.grade({**full, "modbus_round_trip": False})[0] == "M4"
    assert attack.grade({"booted": True})[0] == "M3"
    assert attack.grade({"console_alive": True})[0] == "M1"
    assert attack.grade({})[0] == "M0"

    import inspect
    src = inspect.getsource(attack)
    for bad in ('res["milestone"] = "M', 'result["milestone"] = "M'):
        assert bad not in src, "the rung is a literal again: %s" % bad


def test_no_milestone_is_assigned_outside_the_ladder_table():
    """Every rung `grade` can ever emit must come from LADDER (or be M0).

    This is the structural guarantee the whole ladder rests on: the rung is
    read out of the table, so a rung cannot be invented by a code path that
    forgot to consult the evidence.
    """
    from rehostry_adam6000_tm4c import attack
    import itertools

    allowed = {rung for rung, _key in attack.LADDER} | {"M0"}
    keys = [key for _rung, key in attack.LADDER] + [
        "modbus_round_trip", "http_round_trip"]
    # Exhaustive over every combination of the inputs the ladder reads.
    for combo in itertools.product([False, True], repeat=len(keys)):
        res = dict(zip(keys, combo))
        rung, met = attack.grade(res)
        assert rung in allowed, "grade() invented the rung %r from %r" % (
            rung, res)
        assert set(met) == {r for r, _ in attack.LADDER}
    # And the table itself is ordered and well formed.
    order = [int(r[1:]) for r, _ in attack.LADDER]
    assert order == sorted(order) and len(set(order)) == len(order)


def test_the_rung_reaches_RESULT_on_the_default_path():
    """A rung an opt-in flag can see but `RESULT:` cannot is the same ceiling.

    `--ladder` may only ADD the table; it must not be what makes the rung
    visible, or a header could disagree with its own run.
    """
    from rehostry_adam6000_tm4c import attack
    for key in ("milestone", "rungs_met", "multi_interface", "round_trip",
                "http_round_trip", "http_rounds_passed", "http_statuses_seen",
                "modbus_round_trip", "interfaces_exercised"):
        assert key not in attack.RESULT_BULK


def test_interface_inventory_is_DERIVED_not_typed():
    """Rule 1: the denominator must not be a literal anyone can retype.

    What this replaces: a test that asserted ``inv["count"] == 4`` against a
    hard-coded dict.  It passed happily, and it was pinning the defect.
    """
    import hashlib
    import json
    import pathlib
    import sys
    from rehostry_adam6000_tm4c import attack
    root = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "tools"))
    import derive_inventory as di
    import inventory_guard as ig

    # 1. NO LITERAL INVENTORY SURVIVES IN attack.py.
    assert not hasattr(attack, "INTERFACE_INVENTORY")
    # Only CODE lines -- the comment block above the derivation quotes the old
    # literal on purpose, to say what was wrong with it.
    code = [ln for ln in (root / "src" / "rehostry_adam6000_tm4c" /
                          "attack.py").read_text().splitlines()
            if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code
                if '"count": 4' in ln or '"graded": 2' in ln]

    # 2. The derivation is a function of the IMAGE BYTES.
    image = pathlib.Path(di.default_image()).read_bytes()
    d = di.derive(image)
    assert d["image_sha256"] == hashlib.sha256(image).hexdigest()
    assert d["n"] == len(d["entries"]) == len(d["entry_ids"])
    assert d["n_is_a_floor"] is True
    # Every entry names the declaring token(s) it rests on -- auditable.
    for e in d["entries"]:
        assert e["declared_by"], e["id"]

    # 3. NOTHING THE OLD DENOMINATOR COUNTED HAS BEEN REMOVED.
    ids = {e["id"] for e in d["entries"]}
    for kept in ("modbus_tcp_502", "http_config_server_80", "snmp_agent_161",
                 "mqtt_client"):
        assert kept in ids, kept
    assert d["n"] >= 4

    # 4. The pre-registration matches, and the guard COMPARES SETS.
    prereg = json.loads((root / "INVENTORY-PREREG.json").read_text())
    assert prereg["n"] == d["n"]
    assert set(prereg["entry_ids"]) == set(d["entry_ids"])
    assert ig.run()["ok"] is True

    # 5. THE GUARD BITES -- every falsification mode VOIDs, and at least one of
    #    them leaves the entry-id set INTACT, so the raw-byte pin is load-bearing
    #    rather than an id-only guard that a sibling image would satisfy.
    base = ig.run()
    ids_intact_but_void = False
    for mode in ig.FALSIFY_MODES:
        try:
            o = ig.run(falsify=mode)
        except SystemExit:
            continue                      # the deriver refusing IS a void
        assert o["ok"] is False, mode
        if set(o["entry_ids"]) == set(base["entry_ids"]):
            ids_intact_but_void = True
            assert "block_bytes_sha256" in o["terms_fired"] or \
                   "image_sha256" in o["terms_fired"]
    assert ids_intact_but_void

    # 6. The collapse table still says which keys are NOT interfaces.
    assert set(attack.COLLAPSED) == {"modbus_tcp_502", "http_80",
                                     "not_interfaces"}
    assert "modbus_round_trip" in attack.COLLAPSED["modbus_tcp_502"]
    assert "http_round_trip" in attack.COLLAPSED["http_80"]
    for wire in ("arp_replies", "frames_in", "frames_out"):
        assert wire in attack.COLLAPSED["not_interfaces"]
    assert "IRQ (40)" in attack.SHARED_SUBSTRATE


def test_the_parity_numerator_is_not_an_inert_constant():
    """`"graded": 2` used to be a literal. A numerator no arm can move is not a
    measurement, so this drives the term both ways."""
    from rehostry_adam6000_tm4c import attack
    inv = attack.derive_inventory()
    assert inv["guard_ok"] is True

    both = {"modbus_round_trip": True, "http_round_trip": True}
    attack._parity(both, inv)
    assert both["parity_void"] is False
    assert both["interfaces_at_m4"] == ["http_config_server_80",
                                        "modbus_tcp_502"]
    assert "2 of %d" % inv["n"] in both["parity"]

    one = {"modbus_round_trip": True, "http_round_trip": False}
    attack._parity(one, inv)
    assert one["interfaces_at_m4"] == ["modbus_tcp_502"]
    assert "1 of %d" % inv["n"] in one["parity"]

    none_ = {"modbus_round_trip": False, "http_round_trip": False}
    attack._parity(none_, inv)
    assert none_["interfaces_at_m4"] == []
    assert "0 of %d" % inv["n"] in none_["parity"]

    # A guard mismatch publishes NO number at all, in either direction.
    voided = dict(inv, guard_ok=False,
                  void_reasons=["image_sha256: deliberately wrong"])
    r = {"modbus_round_trip": True, "http_round_trip": True}
    attack._parity(r, voided)
    assert r["parity_void"] is True and r["parity"].startswith("VOID:")
    assert "of %d" % inv["n"] not in r["parity"]

    # And a derivation that could not run is UNDETERMINED, not a failure.
    undet = dict(inv, undetermined="KeyError: simulated")
    r2 = {"modbus_round_trip": True, "http_round_trip": True}
    attack._parity(r2, undet)
    assert r2["parity_void"] is True
    assert r2["parity"].startswith("UNDETERMINED:")
    assert "TOOL DEFECT" in r2["parity"]


def test_the_independence_lever_exists_and_refuses_nonsense():
    from rehostry_adam6000_tm4c import attack
    import pytest
    assert attack.INTERFACE_SETS == ("both", "modbus", "http")
    with pytest.raises(ValueError):
        attack.run_attack(interfaces="wireless")
    with pytest.raises(ValueError):
        attack.run_attack(control="not-a-control")


def test_the_two_peers_are_separately_modelled():
    """Two 'interfaces' driven by one peer object would be one machine.

    The independence claim rests on the HTTP client being a DIFFERENT host on
    the segment from the Modbus master, so this checks they cannot silently
    become the same object under two names.
    """
    from rehostry_adam6000_tm4c.peripheral_models import net_peer
    import pytest
    net_peer.reset_peers()
    try:
        a = net_peer.get_peer()
        b = net_peer.get_peer("http")
        assert a is not b
        assert a.mac != b.mac
        assert a.ip != b.ip
        assert a.device_ip == b.device_ip      # same device, different callers
        assert {p.name for p in net_peer.all_peers()} == {"default", "http"}
        # An unknown name must raise rather than alias the default.
        with pytest.raises(KeyError):
            net_peer.get_peer("modbus-but-typoed")
    finally:
        net_peer.reset_peers()


def test_the_http_oracle_is_n_of_n_and_guards_the_empty_list():
    """Rule 2, and `all()` over an empty list is vacuously True.

    With zero rounds every check that quantifies over replies is vacuous, so
    the round count has to be its own explicit term. `rounds=0` opens no
    socket, so this needs no emulator.
    """
    from rehostry_adam6000_tm4c import attack
    out = attack.converse_http(host_port=1, rounds=0)
    assert out["http_round_trip"] is False, \
        "an empty round set passed -- the all()-over-empty guard is missing"
    assert out["http_rounds_passed"] == 0
    # Below the minimum cycle length it must also refuse.
    assert attack.MIN_HTTP_ROUNDS >= 3


def test_http_shapes_cycle_so_consecutive_rounds_differ():
    """The attributor for this seam is the status the request shape demands.

    This server echoes nothing of the request -- two 404s are byte-identical --
    so the Modbus arm's `no reply was a repeat` term would score a working
    httpd at zero if it were borrowed. What replaces it is the cycle: if two
    consecutive rounds ever demanded the same status, a server that had gone
    deaf and was repeating could satisfy it.
    """
    from rehostry_adam6000_tm4c import attack
    wants = [w for _l, _t, w in attack.HTTP_SHAPES]
    assert len(set(wants)) == len(wants) >= 3
    for i in range(len(attack.HTTP_SHAPES) * 3):
        a = attack.HTTP_SHAPES[i % len(attack.HTTP_SHAPES)][2]
        b = attack.HTTP_SHAPES[(i + 1) % len(attack.HTTP_SHAPES)][2]
        assert a != b
    # Every shape must carry the per-round nonce, so no two rounds of the same
    # shape are byte-identical on the wire.
    for _label, template, _want in attack.HTTP_SHAPES:
        assert "%N%" in template
    assert attack._http_nonce(1, 0) != attack._http_nonce(1, 1)
    assert attack._http_nonce(1, 0) != attack._http_nonce(2, 0)


def test_the_http_status_set_is_the_firmwares_own():
    """The three status lines the oracle demands must exist in the image.

    If a status the oracle expects were NOT in the firmware, the oracle would
    be asserting something only the harness could produce.
    """
    from rehostry_adam6000_tm4c import attack, paths
    if not paths.firmware_present():
        return                      # firmware is not redistributed
    blob = open(paths.firmware_bin(), "rb").read()
    for _label, _template, want in attack.HTTP_SHAPES:
        assert b"HTTP/1.1 %d " % want in blob, \
            "status %d is not in the firmware image" % want
    assert b"Server: ADAM-6000/" in blob
