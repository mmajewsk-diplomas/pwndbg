from __future__ import annotations

from pathlib import Path

from ....host import Controller
from . import pwndbg_test


@pwndbg_test
async def test_setrlimit_unknown_resource(ctrl: Controller) -> None:
    await ctrl.launch(Path("/bin/true"), args=[])

    result = await ctrl.execute_and_capture("setrlimit unknown 1")

    assert "Unknown resource 'unknown'" in result


@pwndbg_test
async def test_setrlimit_invalid_value(ctrl: Controller) -> None:
    await ctrl.launch(Path("/bin/true"), args=[])

    out1 = await ctrl.execute_and_capture("setrlimit cpu not-a-number")
    assert "Invalid limit 'not-a-number'" in out1

    out2 = await ctrl.execute_and_capture("setrlimit cpu 1 invalid_hard")
    assert "Invalid limit 'invalid_hard'" in out2
