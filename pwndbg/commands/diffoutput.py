from __future__ import annotations
import argparse
import difflib

import pwndbg.commands
from pwndbg.commands import CommandCategory
import pwndbg.color.message as message
from pwndbg.commands.saveoutput import saved_outputs, last_command

if pwndbg.dbg.is_gdblib_available():
    import gdb

diff_parser = argparse.ArgumentParser(
    description="Compare the current output of a command to its saved version."
)
diff_parser.add_argument(
    "args",
    nargs="*",
    help="Command plus arguments to execute and diff",
)

@pwndbg.commands.ArgparsedCommand(diff_parser, category=CommandCategory.MISC)
def diffoutput(args: list[str]) -> None:
    """
    Usage: diffoutput [cmd args...]
    Compares the saved output to the current one.
    """
    global saved_outputs, last_command

    if args:
        cmd = " ".join(args)
    elif last_command:
        cmd = last_command
    else:
        print(message.error("No previous command to diff."))
        return

    if cmd not in saved_outputs:
        print(message.error(f"No saved output for command: '{cmd}'"))
        return

    try:
        current = gdb.execute(cmd, to_string=True)
    except gdb.error as e:
        print(message.error(f"Failed to execute '{cmd}': {e}"))
        return

    saved = saved_outputs[cmd].splitlines()
    curr  = current.splitlines()

    diff = "\n".join(difflib.unified_diff(
        saved,
        curr,
        fromfile="saved",
        tofile="current",
        lineterm=""
    ))

    if diff:
        print(message.notice("Differences:\n" + diff))
    else:
        print(message.success("No differences found."))
