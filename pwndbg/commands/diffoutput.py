from __future__ import annotations

import argparse
import difflib

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.commands.saveoutput import last_command
from pwndbg.commands.saveoutput import saved_outputs

if pwndbg.dbg.is_gdblib_available():
    import gdb

diff_parser = argparse.ArgumentParser(
    description="Compare the current output of a command to its saved version."
)

diff_parser.add_argument(
    "args",
    nargs=argparse.REMAINDER,
    type=str,
    help="Command plus arguments to execute and diff",
)


@pwndbg.commands.Command(diff_parser, category=CommandCategory.MISC)
def diffoutput(args: list[str]) -> None:
    global saved_outputs, last_command
    if args:
        cmd = " ".join(args)
    else:
        if not last_command:
            print(message.error("No previous command to diff."))
            return
        cmd = last_command
    if cmd not in saved_outputs:
        print(message.error(f"No saved output for command: '{cmd}'"))
        return

    try:
        current = gdb.execute(cmd, to_string=True)
    except gdb.error as e:
        print(message.error(f"Failed to execute command: {e}"))
        return

    saved = saved_outputs[cmd]
    diff = difflib.unified_diff(
        saved.splitlines(), current.splitlines(), fromfile="saved", tofile="current", lineterm=""
    )
    result = "\n".join(diff)
    if result:
        print(message.notice("Differences:\n" + result))
    else:
        print(message.success("No differences found."))
