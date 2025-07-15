from __future__ import annotations

import pwndbg.commands
import pwndbg.color.message as message
import ctypes
if pwndbg.dbg.is_gdblib_available():
    import gdb

RLIM_INFINITY = -1

LIMITS = {
    'core': 4,
    'cpu': 0,
    'fsize': 1,
    'data': 2,
    'stack': 3,
    'nofile': 7,
    'as': 9
}

@pwndbg.commands.Command(category='user')
def setrlimit(resource: str = '', soft: str = '', hard: str = ''):
    """
    Sets a resource limit in the debugged process.
    Usage:
        setrlimit resource soft [hard]
    """
    if not resource or not soft:
        print(message.error("You must provide at least the resource and the soft limit."))
        return

    res_name = resource.lower()
    if res_name not in LIMITS:
        print(message.error(f"Unknown resource: {res_name}"))
        return

    res = LIMITS[res_name]

    def parse_limit(val: str) -> int:
        if val == "inlimited":
            return RLIM_INFINITY
        try:
            return int(val)
        except ValueError:
            print(message.error(f"Invalid limit value: {val}"))
            raise

    soft_limit = parse_limit(soft)
    if hard:
        hard_limit = parse_limit(hard)
    else:
        hard_limit = soft_limit

    class Rlimit(ctypes.Structure):
        _fields_ = [("rlim_cur", ctypes.c_ulonglong), ("rlim_max", ctypes.c_ulonglong)]

    rlim = Rlimit(soft_limit, hard_limit)

    addr = pwndbg.memory.allocate(ctypes.sizeof(rlim))
    pwndbg.memory.write(addr, bytes(rlim))

    try:
        gdb.execute(f"call setrlimit({res}, (struct rlimit*){addr})")
        print(message.success(f"Set {resource}: soft={soft}, hard={hard_limit if hard else soft}"))
    except gdb.error as e:
        print(message.error(f"Failed to set limit: {e}"))