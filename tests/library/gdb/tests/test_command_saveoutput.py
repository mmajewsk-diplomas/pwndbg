from __future__ import annotations

import pwndbg
import pwndbg.commands.saveoutput as so


class DummyRegSet:
    gpr = ("rax", "rbx")
    args = ("rdi",)
    pc = "rip"
    stack = "rsp"


class DummyRegs:
    def __init__(self, values: dict[str, int]):
        self._values = values

    def by_name(self, name: str):
        return self._values[name]


class DummyFrame:
    def __init__(self, regs: DummyRegs):
        self._regs = regs

    def regs(self):
        return self._regs


def test_saveoutput_registers_saves(monkeypatch):
    so.saved_outputs.clear()
    so.last_command = None

    monkeypatch.setattr(pwndbg.aglib.arch, "name", "test-arch", raising=False)
    monkeypatch.setattr(pwndbg.lib.regs, "reg_sets", {"test-arch": DummyRegSet()}, raising=False)

    regs = DummyRegs({"rax": 0x1, "rbx": 0x2, "rdi": 0x3, "rip": 0x401000, "rsp": 0x7FFFFFFF0000})
    monkeypatch.setattr(pwndbg.dbg, "selected_frame", lambda: DummyFrame(regs), raising=False)

    so.saveoutput(["registers"])

    assert "registers" in so.saved_outputs
    assert "rip\t0x401000" in so.saved_outputs_
