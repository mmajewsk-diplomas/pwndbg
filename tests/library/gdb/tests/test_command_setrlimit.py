from __future__ import annotations

from unittest.mock import patch

import pwndbg.commands.setrlimit as sr


def test_setrlimit_unknown_resource(capfd):
    with patch.object(sr, "_invoke_setrlimit") as mock_invoke:
        sr.setrlimit("unknown", "1")
        mock_invoke.assert_not_called()

    out, _ = capfd.readouterr()
    assert "Unknown resource 'unknown'" in out


def test_setrlimit_invalid_soft_value(capfd):
    with patch.object(sr, "_invoke_setrlimit") as mock_invoke:
        sr.setrlimit("cpu", "not-a-number")
        mock_invoke.assert_not_called()

    out, _ = capfd.readouterr()
    assert "Invalid limit 'not-a-number'" in out


def test_setrlimit_invalid_hard_value(capfd):
    with patch.object(sr, "_invoke_setrlimit") as mock_invoke:
        sr.setrlimit("cpu", "1", "invalid_hard")
        mock_invoke.assert_not_called()

    out, _ = capfd.readouterr()
    assert "Invalid limit 'invalid_hard'" in out


def test_setrlimit_soft_only_calls_invoke_and_defaults_hard(capfd):
    called = {}

    def fake_invoke(num, soft_val, hard_val):
        called["args"] = (num, soft_val, hard_val)
        return "OK"

    with patch.object(sr, "_invoke_setrlimit", side_effect=fake_invoke):
        sr.setrlimit("cpu", "10")

    out, _ = capfd.readouterr()
    assert called["args"] == (sr.LIMITS["cpu"], 10, 10)
    assert "OK" in out
    assert "Set cpu limit: soft=10, hard=10" in out
