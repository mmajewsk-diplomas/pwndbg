from __future__ import annotations

import argparse
import difflib

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.commands.saveoutput import last_command, saved_outputs, snapshot_registers, snapshot_vmmap

diff_parser = argparse.ArgumentParser(
    description="Compare current snapshot output to its saved version."
)

diff_parser.add_argument(
    "args",
    nargs=argparse.REMAINDER,
    type=str,
    help="Snapshot name (registers|vmmap).",
)


@pwndbg.commands.Command(diff_parser, category=CommandCategory.MISC)
def diffoutput(args: list[str]) -> None:
    global saved_outputs, last_command

    what = args[0] if args else None
    if not what:
        if not last_command:
            print(message.error("No previous snapshot to diff."))
            return
        what = last_command

    if what not in saved_outputs:
        print(message.error(f"No saved output for snapshot: '{what}'"))
        return

    try:
        if what == "registers":
            current = snapshot_registers()
        elif what == "vmmap":
            current = snapshot_vmmap()
        else:
            print(message.error(f"Unsupported snapshot: '{what}' (use: registers|vmmap)"))
            return
    except Exception as e:
        print(message.error(f"Failed to capture snapshot: {e}"))
        return

    saved = saved_outputs[what]
    diff = difflib.unified_diff(
        saved.splitlines(),
        current.splitlines(),
        fromfile="saved",
        tofile="current",
        lineterm="",
    )
    result = "\n".join(diff)

    if result:
        print(message.notice("Differences:\n" + result))
    else:
        print(message.success("No differences found."))
