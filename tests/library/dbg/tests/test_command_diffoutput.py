from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_diffoutput_no_previous_command_to_diff(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    out = await ctrl.execute_and_capture("diffoutput")
    assert "No previous command to diff." in out


@pwndbg_test
async def test_diffoutput_no_saved_output_for_explicit_command(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    out = await ctrl.execute_and_capture("diffoutput regs")
    assert "No saved output for command: 'regs'" in out


@pwndbg_test
async def test_diffoutput_no_differences_after_save(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    out_save = await ctrl.execute_and_capture("saveoutput regs")
    assert "Output saved for command: 'regs'" in out_save

    out_diff = await ctrl.execute_and_capture("diffoutput regs")
    assert "No differences found." in out_diff


@pwndbg_test
async def test_diffoutput_detects_difference_after_state_change(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    out_save = await ctrl.execute_and_capture("saveoutput regs")
    assert "Output saved for command: 'info registers'" in out_save

    await ctrl.execute_and_capture("stepi")

    out_diff = await ctrl.execute_and_capture("diffoutput regs")
    assert "Differences:" in out_diff
    assert "--- saved" in out_diff
    assert "+++ current" in out_diff
