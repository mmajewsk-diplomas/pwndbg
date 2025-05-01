from __future__ import annotations

import pwndbg.commands

@pwndbg.commands.Command
def save(*args):
    cmd = ''.join(args)
    if not cmd:
        print(message.error("No command to save."))
        return