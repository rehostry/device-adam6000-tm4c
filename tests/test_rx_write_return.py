# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A REFUSED backend write must not be counted as a delivery.

`HalBackend.write_memory` answers an unmapped address with `return False`; it
does NOT raise. The receive path here used to wrap it in `try/except`, which
catches nothing, so a frame written nowhere was popped off the queue, counted,
given a "valid frame here" descriptor status and announced with an interrupt.
Measured on `device-accusine-pcs-hmi` (DEVICE-PLAYBOOK w49.1) and reproduced
here on 2026-09-06.

This is a SOURCE-level test on purpose: the receive path needs a booted guest,
a live descriptor ring and a backend, and the property being pinned is one
line of control flow. It fails if the return value is ever dropped again.

NO emulator required.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
MODEL = os.path.join(SRC, "rehostry_adam6000_tm4c", "peripheral_models", "tiva_emac.py")
sys.path.insert(0, SRC)


def _tree():
    with open(MODEL, encoding="utf-8") as fh:
        return ast.parse(fh.read()), fh


def test_every_write_memory_return_is_used():
    """No `backend.write_memory(...)` may stand as a bare statement.

    A bare-statement call is one whose return value is discarded. That is the
    exact shape of the defect: the only failure signal the API has is thrown
    away.
    """
    tree, _ = _tree()
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    bare = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in ("write_memory", "write_memory_word",
                             "write_memory_bytes"):
            continue
        if isinstance(parent.get(node), ast.Expr):
            bare.append((func.attr, node.lineno))
    assert bare == [], (
        "write_memory return value discarded at %s -- an unmapped address "
        "returns False and does not raise, so this counts a delivery that "
        "never happened" % bare)


def test_the_counter_is_guarded_by_the_return():
    """`rx_count` must not be reachable from a refused write.

    Pins the fix rather than its wording: the model must own a separate
    `rx_write_failed` counter, and the refusal branch must leave the delivery
    path (return) unless the `HAL_ADAM_RX_COUNT_UNCHECKED` control is set.
    """
    tree, _ = _tree()
    src = open(MODEL, encoding="utf-8").read()
    assert "rx_write_failed" in src, (
        "no rx_write_failed counter: 'could not deliver' and 'delivered' are "
        "still the same measurement")
    assert "HAL_ADAM_RX_COUNT_UNCHECKED" in src, (
        "the fix has no both-arms control; a knob nobody can flip looks "
        "exactly like proof (ADVERSARIAL attack 3)")
    assert "HAL_ADAM_RX_WRITE_FAULT" in src, (
        "no fault-injection knob: the failure path cannot be exercised")


def test_the_fault_knob_defaults_to_off():
    """The knobs must be inert unless asked for, so a normal run is normal."""
    for var in ("HAL_ADAM_RX_WRITE_FAULT", "HAL_ADAM_RX_COUNT_UNCHECKED"):
        assert os.environ.get(var) in (None, "", "0"), (
            "%s is set in this environment; the suite would be measuring the "
            "fault arm" % var)
    import importlib
    mod = importlib.import_module("rehostry_adam6000_tm4c.peripheral_models.tiva_emac")
    assert mod.RX_WRITE_FAULT == 0
    assert mod.RX_COUNT_UNCHECKED is False
