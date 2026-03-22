from __future__ import annotations

import gdb

import pwndbg.commands.saveoutput
from pwndbg.commands.saveoutput import saved_outputs

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def test_saveoutput_joins_args_correctly(start_binary):
    pwndbg.commands.saveoutput.saved_outputs.clear()
    pwndbg.commands.saveoutput.last_command = None

    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    pwndbg.commands.saveoutput.saveoutput(["info", "registers"])

    assert "info registers" in saved_outputs


def test_saveoutput_saves_command_output(start_binary):
    pwndbg.commands.saveoutput.saved_outputs.clear()
    pwndbg.commands.saveoutput.last_command = None

    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    gdb.execute("saveoutput info registers", to_string=True)

    current = gdb.execute("info registers", to_string=True)

    assert "info registers" in saved_outputs
    assert saved_outputs["info registers"] == current


def test_saveoutput_uses_last_saved_command_when_no_args(start_binary):
    pwndbg.commands.saveoutput.saved_outputs.clear()
    pwndbg.commands.saveoutput.last_command = None

    start_binary(REFERENCE_BINARY)
    gdb.execute("break main")
    gdb.execute("run")

    cmd = "info registers"
    pwndbg.commands.saveoutput.saveoutput(["info", "registers"])
    pwndbg.commands.saveoutput.saveoutput([])

    assert cmd in saved_outputs


def test_saveoutput_when_no_args_and_no_previous_saved_command(capfd):
    pwndbg.commands.saveoutput.last_command = None
    pwndbg.commands.saveoutput.saved_outputs.clear()

    pwndbg.commands.saveoutput.saveoutput([])

    out, _ = capfd.readouterr()
    assert "No previous command to save." in out
