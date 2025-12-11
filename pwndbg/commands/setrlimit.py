from __future__ import annotations

import argparse

import pwndbg
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg
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


def _invoke_setrlimit(num: int, soft_val: int, hard_val: int) -> int:
    inferior = pwndbg.dbg.selected_inferior()
    if inferior is None:
        raise pwndbg.dbg_mod.Error("No selected inferior")

    expr = f"(int)setrlimit({num}, (struct rlimit[]){{ {{ {soft_val}, {hard_val} }} }})"

    value = inferior.evaluate_expression(expr)
    return int(value)


def _to_int_limit(val: str) -> int:
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
    Sets a POSIX resource limit in the debugged process.

    Usage: setrlimit <resource> <soft> [hard]
    """
    res = resource.lower()
    if res not in LIMITS:
        print(message.error(f"Unknown resource '{resource}'. Valid: {', '.join(LIMITS)}"))
        return

    try:
        soft_val = _to_int_limit(soft)
        hard_val = _to_int_limit(hard) if hard is not None else soft_val
    except ValueError:
        return

    num = LIMITS[res]

    try:
        ret = _invoke_setrlimit(num, soft_val, hard_val)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(str(e)))
        return
    except Exception as e:
        print(message.error(f"Failed to call setrlimit in inferior. Details: {e}"))
        return

    print(
        message.success(
            f"Set {res} limit (return={ret}): "
            f"soft={'∞' if soft_val == RLIM_INFINITY else soft_val}, "
            f"hard={'∞' if hard_val == RLIM_INFINITY else hard_val}"
        )
    )
