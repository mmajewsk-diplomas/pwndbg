from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.arch
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.lib.regs
from pwndbg.commands import CommandCategory

saved_outputs: dict[str, str] = {}
last_command: str | None = None

save_parser = argparse.ArgumentParser(
    description="Save a debugger-agnostic snapshot for later diffing."
)

save_parser.add_argument(
    "args",
    nargs=argparse.REMAINDER,
    type=str,
    help="Snapshot name (registers|vmmap).",
)


def snapshot_registers() -> str:
    regset = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
    reg_names = tuple(regset.gpr) + tuple(regset.args) + (regset.pc, regset.stack)

    regs = pwndbg.dbg.selected_frame().regs()

    out_lines: list[str] = []
    for name in reg_names:
        try:
            v = int(regs.by_name(name))
        except Exception:
            continue
        out_lines.append(f"{name}\t0x{v:x}")

    return "\n".join(out_lines) + ("\n" if out_lines else "")


def snapshot_vmmap() -> str:
    import pwndbg.aglib.vmmap

    pages = pwndbg.aglib.vmmap.get()
    out_lines: list[str] = []

    for p in pages:
        r = "r" if getattr(p, "read", False) else "-"
        w = "w" if getattr(p, "write", False) else "-"
        x = "x" if getattr(p, "execute", False) else "-"
        perms = f"{r}{w}{x}p"
        obj = getattr(p, "objfile", "") or ""
        out_lines.append(f"{p.start:#x}-{p.end:#x} {perms} {obj}".rstrip())

    return "\n".join(out_lines) + ("\n" if out_lines else "")


@pwndbg.commands.Command(save_parser, category=CommandCategory.MISC)
def saveoutput(args: list[str]) -> None:
    global saved_outputs, last_command

    what = args[0] if args else None
    if not what:
        if not last_command:
            print(message.error("No previous snapshot to save."))
            return
        what = last_command

    try:
        if what == "registers":
            result = snapshot_registers()
        elif what == "vmmap":
            result = snapshot_vmmap()
        else:
            print(message.error(f"Unsupported snapshot: '{what}' (use: registers|vmmap)"))
            return
    except Exception as e:
        print(message.error(f"Failed to capture snapshot: {e}"))
        return

    saved_outputs[what] = result
    last_command = what
    print(message.success(f"Output saved for snapshot: '{what}'"))
