# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural tests: NO emulator required.

These check the things that silently rot -- config/symbol agreement, the spawn
recipe's invariants, and (TODO) your device's register couplings / encode round
trips. Booting the firmware is covered by STATUS.md, not here (the image is not
redistributed with the package).

TODO: rename `rehostry_adam6000_tm4c` / `adam6000-tm4c_*` below, and ADD device-specific
checks: the recovered vector table (entry_addr/init_sp) matching the config,
peripheral base addresses, and any encode/decode round trip your attack oracle
relies on. See device-zephyr-can/tests/test_structure.py.
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


def test_config_files_are_shipped_as_package_data():
    """Every config named in paths.CONFIG_FILES must exist in configs/."""
    from rehostry_adam6000_tm4c import paths
    for name in paths.CONFIG_FILES:
        # TODO: un-skip once you have real (non-commented) config files.
        assert isinstance(name, str)


# --- config/symbol agreement (TODO: enable once you have real configs) ------

def test_every_intercept_symbol_exists_in_addrs():
    """A typo'd symbol registers no breakpoint and fails silently at run time;
    `function` must equal the symbol (this repo's convention).

    TODO: enable this once adam6000_tm4c_config.yaml has real `intercepts:` and
    adam6000_tm4c_addrs.yaml has a real `symbols:` map. The template config is fully
    commented, so there is nothing to check yet.
    """
    cfg = _config()
    if not cfg or "intercepts" not in cfg:
        return  # template skeleton: no real intercepts yet
    with open(os.path.join(CONFIGS, "adam6000_tm4c_addrs.yaml")) as fh:
        names = set(yaml.safe_load(fh)["symbols"].values())
    for icept in cfg["intercepts"]:
        sym = icept.get("symbol", icept.get("function"))
        assert sym in names, sym


# TODO: add device-specific structural checks, e.g.:
#
# def test_machine_matches_recovered_vector_table():
#     m = _config()["machine"]
#     assert m["entry_addr"] == 0xTODO      # Reset | Thumb
#     assert m["init_sp"] == 0xTODO
