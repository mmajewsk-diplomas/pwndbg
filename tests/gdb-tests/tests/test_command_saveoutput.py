from __future__ import annotations

import re

import gdb
import pytest
import pwndbg.commands.saveoutput
import tests
from pwndbg.commands.saveoutput import saved_outputs


REFERENCE_BINARY = tests.binaries.get("reference-binary.out")

def test_saveoutput_joins_args_correctly(start_binary):
    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    pwndbg.commands.saveoutput.saveoutput("info", "registers")

    assert "info registers" in saved_outputs


def test_saveoutput_saves_command_output(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("break main")
    gdb.execute("run")

    gdb.execute("saveoutput info registers", to_string=True)

    current = gdb.execute("info registers", to_string=True)

    assert "info registers" in saved_outputs
    assert saved_outputs["info registers"] == current


def test_saveoutput_uses_last_command_when_no_args(start_binary):
    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    cmd = "info registers"
    pwndbg.commands.saveoutput.saveoutput(cmd)

    saved_outputs.clear()
    pwndbg.commands.saveoutput.saveoutput()

    assert cmd in saved_outputs


def test_saveoutput_when_no_args_and_no_last_command(capfd):
    pwndbg.commands.saveoutput.last_command = None
    pwndbg.commands.saveoutput.saved_outputs.clear()

    pwndbg.commands.saveoutput.saveoutput()

    out, _ = capfd.readouterr()
    assert "No previous command to save." in out
