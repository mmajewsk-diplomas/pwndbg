from __future__ import annotations

import argparse

import pwnlib.shellcraft

import pwndbg.aglib.asm
import pwndbg.aglib.shellcode
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.commands import CommandCategory

RLIM_INFINITY = -1
LIMITS: dict[str, int] = {
    "core": 4,
    "cpu": 0,
    "fsize": 1,
    "data": 2,
    "stack": 3,
    "nofile": 7,
    "as": 9,
}

parser = argparse.ArgumentParser(
    description="Set a POSIX resource limit in the debugged process.",
)
parser.add_argument(
    "resource",
    type=str.lower,
    choices=sorted(LIMITS.keys()),
    help="Which resource to limit",
)
parser.add_argument(
    "soft",
    type=str,
    help="Soft limit value (integer) or 'infinite'",
)
parser.add_argument(
    "hard",
    type=str,
    nargs="?",
    default=None,
    help="Hard limit value (integer) or 'infinite' (defaults to soft)",
)


def to_int_limit(val: str) -> int:
    lv = val.lower()
    if lv in ("infinite", "unlimited"):
        return RLIM_INFINITY
    try:
        return int(val)
    except ValueError:
        print(message.error(f"Invalid limit '{val}'"))
        raise


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def setrlimit(resource: str, soft: str, hard: str | None = None) -> None:
    """
    Sets a POSIX resource limit in the debugged process via the setrlimit syscall.
    Usage: setrlimit <resource> <soft> [hard]
    """

    res = resource.lower()

    try:
        soft_val = to_int_limit(soft)
        hard_val = to_int_limit(hard) if hard is not None else soft_val
    except ValueError:
        return

    num = LIMITS[res]

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController) -> None:
        soft_str = "inf" if soft_val == RLIM_INFINITY else str(soft_val)
        hard_str = "inf" if hard_val == RLIM_INFINITY else str(hard_val)
        print(
            f"calling setrlimit for resource {res!r} (resource={num}): "
            f"soft={soft_str}, hard={hard_str}"
        )
        asm = f"""
            push {hard_val & 0xFFFFFFFFFFFFFFFF}
            push {soft_val & 0xFFFFFFFFFFFFFFFF}
            mov rsi, rsp
        """
        asm += pwnlib.shellcraft.syscall("SYS_setrlimit", num, "rsi")

        shellcode_bin = pwndbg.aglib.asm.asm(asm)
        async with pwndbg.aglib.shellcode.exec_shellcode(ec, shellcode_bin):
            register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
            ret: int = pwndbg.aglib.regs.read_reg(register_set.retval)

        print(message.success(f"Set {res} limit (return={ret}): soft={soft_str}, hard={hard_str}"))

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
