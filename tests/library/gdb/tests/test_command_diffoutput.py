from __future__ import annotations

from typing import Any

import gdb

import pwndbg.commands.diffoutput
import pwndbg.commands.saveoutput

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def test_diffoutput_no_saved_output(capfd: Any):
    pwndbg.commands.diffoutput.saved_outputs.clear()
    pwndbg.commands.diffoutput.last_command = "info registers"

    pwndbg.commands.diffoutput.diffoutput([])

    out, _ = capfd.readouterr()
    assert "No saved output for command: 'info registers'" in out


def test_diffoutput_no_last_command(capfd: Any):
    pwndbg.commands.diffoutput.saved_outputs.clear()
    pwndbg.commands.diffoutput.last_command = None

    pwndbg.commands.diffoutput.diffoutput([])

    out, _ = capfd.readouterr()
    assert "No previous command to diff." in out


def test_diffoutput_no_difference(start_binary: Any, capfd: Any):
    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    cmd_tokens = ["info", "registers"]
    cmd = " ".join(cmd_tokens)
    result = gdb.execute(cmd, to_string=True)

    pwndbg.commands.diffoutput.saved_outputs.clear()
    pwndbg.commands.diffoutput.saved_outputs[cmd] = result
    pwndbg.commands.diffoutput.last_command = cmd

    pwndbg.commands.diffoutput.diffoutput(cmd_tokens)

    out, _ = capfd.readouterr()
    assert "No differences found." in out


def test_diffoutput_detects_difference(start_binary: Any, capfd: Any):
    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    cmd_tokens = ["info", "registers"]
    cmd = " ".join(cmd_tokens)

    pwndbg.commands.diffoutput.saved_outputs.clear()
    pwndbg.commands.diffoutput.saved_outputs[cmd] = "Fake register output\nRegister A: 0x0"
    pwndbg.commands.diffoutput.last_command = cmd

    pwndbg.commands.diffoutput.diffoutput(cmd_tokens)

    out, _ = capfd.readouterr()
    assert "Differences:" in out
    assert "--- saved" in out
    assert "+++ current" in out
