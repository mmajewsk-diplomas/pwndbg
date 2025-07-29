from __future__ import annotations

import argparse

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb

saved_outputs: dict[str, str] = {}
last_command: str | None = None

save_parser = argparse.ArgumentParser(
    description="Save the output of a debugger command for later diffing."
)

save_parser.add_argument(
    "args",
    nargs=argparse.REMAINDER,
    type=str,
    help="Command plus arguments to execute and save output",
)


@pwndbg.commands.Command(save_parser, category=CommandCategory.MISC)
def saveoutput(args: list[str]) -> None:
    global saved_outputs, last_command
    if args:
        cmd = " ".join(args)
    else:
        if not last_command:
            print(message.error("No previous command to save."))
            return

        cmd = last_command
    try:
        result = gdb.execute(cmd, to_string=True)
        saved_outputs[cmd] = result
        last_command = cmd
        print(message.success(f"Output saved for command: '{cmd}'"))
    except gdb.error as e:
        print(message.error(f"Failed to execute command: {e}"))
