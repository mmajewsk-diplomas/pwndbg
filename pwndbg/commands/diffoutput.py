from __future__ import annotations

import argparse
import difflib

import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.commands.saveoutput as saveoutput_mod
import pwndbg.dbg_mod
from pwndbg.commands import CommandCategory

saved_outputs = saveoutput_mod.saved_outputs
last_command: str | None = None

diff_parser = argparse.ArgumentParser(
    description="Diff current output of a debugger command against a saved snapshot."
)

diff_parser.add_argument("args", nargs=argparse.REMAINDER, type=str, help="Command to diff")


def _get_last_command() -> str | None:
    return saveoutput_mod.last_command or last_command


@pwndbg.commands.Command(diff_parser, category=CommandCategory.MISC)
def diffoutput(args: list[str]) -> None:
    if args:
        cmd = " ".join(args).strip()
    else:
        cmd = _get_last_command()
        if not cmd:
            print(message.error("No previous command to diff."))
            return

    if cmd not in saved_outputs:
        print(message.error(f"No saved output for command: '{cmd}'"))
        return

    try:
        current = saveoutput_mod.run_debugger_command(cmd)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed to run command '{cmd}': {e}"))
        return

    saved = saveoutput_mod.saved_outputs[cmd]

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
