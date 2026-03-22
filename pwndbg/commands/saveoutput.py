from __future__ import annotations

import argparse

import pwndbg
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.commands import CommandCategory

saved_outputs: dict[str, str] = {}
last_command: str | None = None

save_parser = argparse.ArgumentParser(
    description="Save the output of a debugger command for later diffing."
)

save_parser.add_argument(
    "args",
    nargs=argparse.REMAINDER,
    type=str,
    help="Command to run and save.",
)


def get_last_history_command() -> str | None:
    history = pwndbg.dbg.history(50)
    for _, cmd in reversed(history):
        line = cmd.strip()
        if not line:
            continue
        name = line.split()[0]
        if name in {"saveoutput", "diffoutput"}:
            continue
        return line
    return None


def get_command_to_save(args: list[str]) -> str | None:
    global last_command
    if args:
        cmd = " ".join(args).strip()
        return cmd or None

    cmd = get_last_history_command()
    if cmd:
        return cmd

    if last_command:
        return last_command

    return None


def run_debugger_command(cmd: str) -> str:
    proc = pwndbg.dbg.selected_inferior()
    if proc is None:
        raise pwndbg.dbg_mod.Error("No selected inferior process.")

    return proc.runcmd(cmd)


@pwndbg.commands.Command(save_parser, category=CommandCategory.MISC)
def saveoutput(args: list[str]) -> None:
    global saved_outputs, last_command

    cmd = get_command_to_save(args)
    if not cmd:
        print(message.error("No previous command to save."))
        return

    try:
        output = run_debugger_command(cmd)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed to run command '{cmd}': {e}"))
        return

    saved_outputs[cmd] = output
    last_command = cmd

    if output:
        print(output, end="" if output.endswith("\n") else "\n")

    print(message.success(f"Output saved for command: '{cmd}'"))
