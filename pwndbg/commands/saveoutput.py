from __future__ import annotations
import argparse

import pwndbg.commands
from pwndbg.commands import CommandCategory
import pwndbg.color.message as message

if pwndbg.dbg.is_gdblib_available():
    import gdb

saved_outputs: dict[str, str] = {}
last_command: str | None    = None

save_parser = argparse.ArgumentParser(
    description="Save the output of a debugger command for later diffing."
)
save_parser.add_argument(
    "args",
    nargs="*",
    help="Command plus arguments to execute and save output",
)

@pwndbg.commands.ArgparsedCommand(save_parser, category=CommandCategory.MISC)
def saveoutput(args: list[str]) -> None:
    """
    Usage: saveoutput [cmd args...]
    Saves the output of the given debugger command. If no command is provided,
    reuses the last saved command.
    """
    global saved_outputs, last_command

    if args:
        cmd = " ".join(args)
    elif last_command:
        cmd = last_command
    else:
        print(message.error("No previous command to save."))
        return

    try:
        output = gdb.execute(cmd, to_string=True)
        saved_outputs[cmd] = output
        last_command = cmd
        print(message.success(f"Output saved for command: '{cmd}'"))
    except gdb.error as e:
        print(message.error(f"Failed to execute '{cmd}': {e}"))
