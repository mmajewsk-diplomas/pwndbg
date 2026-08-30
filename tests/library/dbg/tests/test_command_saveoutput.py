from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_saveoutput_saves_output_for_explicit_command(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    out = await ctrl.execute_and_capture("saveoutput regs")
    assert "Output saved for command: 'regs'" in out


@pwndbg_test
async def test_saveoutput_uses_history_when_no_args(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    first = await ctrl.execute_and_capture("saveoutput regs")
    assert "Output saved for command: 'regs'" in first

    out = await ctrl.execute_and_capture("saveoutput")
    assert "Output saved for command: 'regs'" in out


@pwndbg_test
async def test_saveoutput_no_args_and_no_history_command(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    out = await ctrl.execute_and_capture("saveoutput")

    assert "No previous command to save." in out
