from __future__ import annotations

from unittest.mock import patch

import gdb

import pwndbg.commands.setrlimit as sr


def test_setrlimit_unknown_resource():
    out = gdb.execute("setrlimit unknown 1", to_string=True)
    assert "Unknown resource 'unknown'" in out


def test_setrlimit_invalid_soft_value():
    out = gdb.execute("setrlimit cpu not-a-number", to_string=True)
    assert "Invalid limit 'not-a-number'" in out


def test_setrlimit_invalid_hard_value():
    out = gdb.execute("setrlimit cpu 1 invalid_hard", to_string=True)
    assert "Invalid limit 'invalid_hard'" in out


def test_setrlimit_soft_only_calls_invoke_and_defaults_hard():
    called: dict[str, tuple[int, int, int]] = {}

    def fake_invoke(num: int, soft_val: int, hard_val: int) -> str:
        called["args"] = (num, soft_val, hard_val)
        return "OK"

    with patch.object(sr, "_invoke_setrlimit", side_effect=fake_invoke):
        out = gdb.execute("setrlimit cpu 10", to_string=True)

    assert called["args"] == (sr.LIMITS["cpu"], 10, 10)
    assert "OK" in out
    assert "Set cpu limit: soft=10, hard=10" in out
