"""Run actual owner UI handlers in a dependency-free synthetic DOM in Node."""
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.skipif(not shutil.which("node"), reason="Node is unavailable")
@pytest.mark.parametrize("scenario", [
    "arrivals", "unread", "keyboard", "focus", "expired_focus", "last_older_focus",
    "anchor", "older_feedback", "older_error", "timeout_races",
])
def test_owner_ui_handlers(scenario):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([
        shutil.which("node"), str(root / "tests/owner_ui_harness.cjs"),
        str(root / "bridge/static/owner-conversations.js"), scenario,
    ], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
