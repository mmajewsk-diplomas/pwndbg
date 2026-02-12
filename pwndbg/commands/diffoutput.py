from __future__ import annotations

import argparse
import difflib

import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.commands import CommandCategory
from pwndbg.commands.saveoutput import last_command
from pwndbg.commands.saveoutput import run_debugger_command
from pwndbg.commands.saveoutput import saved_outputs

diff_parser = argparse.ArgumentParser(
    description="Diff current output of a debugger command against a saved snapshot."
)

diff_parser.add_argument("args", nargs=argparse.REMAINDER, type=str, help="Command to diff")


@pwndbg.commands.Command(diff_parser, category=CommandCategory.MISC)
def diffoutput(args: list[str]) -> None:
    if args:
        cmd = " ".join(args).strip()
    else:
        if not last_command:
            print(message.error("No previous command to diff."))
            return
        cmd = last_command

    if cmd not in saved_outputs:
        print(message.error(f"No saved output for command: '{cmd}'"))
        return

    try:
        current = run_debugger_command(cmd)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed to run command '{cmd}': {e}"))
        return

    saved = saved_outputs[cmd]

    diff_iter = difflib.unified_diff(
        saved.splitlines(),
        current.splitlines(),
        fromfile="saved",
        tofile="current",
        lineterm="",
    )
    diff_text = "\n".join(diff_iter)

    if diff_text:
        print(message.notice("Differences:\n" + diff_text))
    else:
        print(message.success("No differences found."))
