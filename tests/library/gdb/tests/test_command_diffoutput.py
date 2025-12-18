from __future__ import annotations

import pwndbg
import pwndbg.commands.diffoutput as do
import pwndbg.commands.saveoutput as so


class DummyRegSet:
    gpr = ("rax",)
    args = ()
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


def test_diffoutput_no_saved_output(capfd):
    so.saved_outputs.clear()
    do.saved_outputs.clear()
    so.last_command = "registers"
    do.last_command = "registers"

    do.diffoutput(["registers"])

    out, _ = capfd.readouterr()
    assert "No saved output for snapshot: 'registers'" in out


def test_diffoutput_no_last_command(capfd):
    so.saved_outputs.clear()
    do.saved_outputs.clear()
    so.last_command = None
    do.last_command = None

    do.diffoutput([])

    out, _ = capfd.readouterr()
    assert "No previous snapshot to diff." in out


def test_diffoutput_no_difference(monkeypatch, capfd):
    so.saved_outputs.clear()
    do.saved_outputs.clear()
    so.last_command = None
    do.last_command = None

    monkeypatch.setattr(pwndbg.aglib.arch, "name", "test-arch", raising=False)
    monkeypatch.setattr(pwndbg.lib.regs, "reg_sets", {"test-arch": DummyRegSet()}, raising=False)

    regs = DummyRegs({"rax": 0x1, "rip": 0x401000, "rsp": 0x1000})
    monkeypatch.setattr(pwndbg.dbg, "selected_frame", lambda: DummyFrame(regs), raising=False)

    so.saveoutput(["registers"])
    do.diffoutput(["registers"])

    out, _ = capfd.readouterr()
    assert "No differences found." in out


def test_diffoutput_detects_difference(monkeypatch, capfd):
    so.saved_outputs.clear()
    do.saved_outputs.clear()
    so.last_command = None
    do.last_command = None

    monkeypatch.setattr(pwndbg.aglib.arch, "name", "test-arch", raising=False)
    monkeypatch.setattr(pwndbg.lib.regs, "reg_sets", {"test-arch": DummyRegSet()}, raising=False)

    regs_a = DummyRegs({"rax": 0x1, "rip": 0x401000, "rsp": 0x1000})
    regs_b = DummyRegs({"rax": 0x2, "rip": 0x401000, "rsp": 0x1000})

    monkeypatch.setattr(pwndbg.dbg, "selected_frame", lambda: DummyFrame(regs_a), raising=False)
    so.saveoutput(["registers"])

    monkeypatch.setattr(pwndbg.dbg, "selected_frame", lambda: DummyFrame(regs_b), raising=False)
    do.diffoutput(["registers"])

    out, _ = capfd.readouterr()
    assert "Differences:" in out
    assert "--- saved" in out
    assert "+++ current" in out


def test_diffoutput_uses_last_command_when_no_args(monkeypatch, capfd):
    so.saved_outputs.clear()
    do.saved_outputs.clear()
    so.last_command = None
    do.last_command = None

    monkeypatch.setattr(pwndbg.aglib.arch, "name", "test-arch", raising=False)
    monkeypatch.setattr(pwndbg.lib.regs, "reg_sets", {"test-arch": DummyRegSet()}, raising=False)

    regs_a = DummyRegs({"rax": 0x1, "rip": 0x401000, "rsp": 0x1000})
    regs_b = DummyRegs({"rax": 0x2, "rip": 0x401000, "rsp": 0x1000})

    monkeypatch.setattr(pwndbg.dbg, "selected_frame", lambda: DummyFrame(regs_a), raising=False)
    so.saveoutput(["registers"])

    monkeypatch.setattr(pwndbg.dbg, "selected_frame", lambda: DummyFrame(regs_b), raising=False)
    do.diffoutput([])

    out, _ = capfd.readouterr()
    assert "Differences:" in out
