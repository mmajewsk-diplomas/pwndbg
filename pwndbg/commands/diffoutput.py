from __future__ import annotations

import pwndbg.commands
import difflib
import pwndbg.color.message as message
from pwndbg.commands.saveoutput import saved_outputs, last_command 
if pwndbg.dbg.is_gdblib_available():
    import gdb
    
@pwndbg.commands.Command(category='user')
def diffoutput(*args):
    global saved_outputs, last_command
    if args:
        cmd = ' '.join(args)
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
        saved.splitlines(),
        current.splitlines(),
        fromfile='saved',
        tofile='current',
        lineterm=''
    )
    result = '\n'.join(diff)
    if result:
        print(message.notice("Differences:\n" + result))
    else:
        print(message.success("No differences found."))