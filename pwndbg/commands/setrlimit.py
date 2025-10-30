from __future__ import annotations

import argparse

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb

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
    type=str,
    help="Which resource to limit: " + ", ".join(LIMITS.keys()),
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


def _invoke_setrlimit(num: int, soft_val: int, hard_val: int) -> str:
    return gdb.execute(
        f"call (int) setrlimit({num}, (struct rlimit[]){{ {{ {soft_val}, {hard_val} }} }})",
        to_string=True,
    )


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
def setrlimit(resource: str, soft: str, hard: str | None = None) -> None:
    """
    Sets a POSIX resource limit in the debugged process.

    Usage: setrlimit <resource> <soft> [hard]
    """
    res = resource.lower()
    if res not in LIMITS:
        print(message.error(f"Unknown resource '{resource}'. Valid: {', '.join(LIMITS)}"))
        return

    def to_int(val: str) -> int:
        lv = val.lower()
        if lv in ("infinite", "unlimited"):
            return RLIM_INFINITY
        try:
            return int(val)
        except ValueError:
            print(message.error(f"Invalid limit '{val}'"))
            raise

    try:
        soft_val = to_int(soft)
        hard_val = to_int(hard) if hard is not None else soft_val
    except ValueError:
        return

    num = LIMITS[res]
    try:
        out = _invoke_setrlimit(num, soft_val, hard_val)
        if out:
            print(message.notice(out.strip()))
        print(
            message.success(
                f"Set {res} limit: soft={'∞' if soft_val==RLIM_INFINITY else soft_val}, "
                f"hard={'∞' if hard_val==RLIM_INFINITY else hard_val}"
            )
        )
    except Exception as e:
        print(message.error(f"setrlimit failed: {e}"))
