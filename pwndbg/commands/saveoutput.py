from __future__ import annotations

import pwndbg.commands
import pwndbg.color.message as message
if pwndbg.dbg.is_gdblib_available():
    import gdb

saved_outputs = {}
last_command = None

@pwndbg.commands.Command(category='user')
def saveoutput(*args):
    global saved_outputs, last_command
    if args:
        cmd = ' '.join(args)
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