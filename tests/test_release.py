"""Source-only version and tag validation; no registry or publication access."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_release", ROOT / "scripts" / "release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
TAG = "v" + release.source_version()


def test_release_plan_matches_application_and_chart_source():
    plan = release.release_plan(TAG)
    chart = yaml.safe_load((ROOT / "charts" / "agent-message-bridge" / "Chart.yaml").read_text())
    assert chart["name"] == "agent-message-bridge"
    assert str(chart["version"]) == plan["version"]
    assert str(chart["appVersion"]) == plan["version"]
    assert plan == {"version": release.source_version(), "tag": TAG, "artifact_kind": "source"}
    with pytest.raises(ValueError):
        release.release_plan("v9999.9999.9999")


@pytest.mark.parametrize("tag", [
    "0.1.0", "v01.1.0", "v0.1.0-01", "v0.1.0-rc..1", "v0.1.0+build",
    "v0.1.0\nx", "v0.1.0-", "v0.1.0-" + "x" * 128,
])
def test_invalid_release_tag_is_rejected(tag):
    with pytest.raises(ValueError):
        release.canonical_version(tag)


def test_canonical_prerelease():
    assert release.canonical_version("v2.0.0-rc.1") == "2.0.0-rc.1"


def test_release_cli_emits_a_local_source_plan():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "release.py"), "plan", "--tag", TAG],
                            cwd=ROOT, capture_output=True, text=True, check=True)
    lines = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert lines == {"version": release.source_version(), "tag": TAG, "artifact_kind": "source"}
    assert not result.stderr


def test_workflow_is_tag_only_and_has_no_build_or_publish_job():
    files = list((ROOT / ".github" / "workflows").glob("*"))
    assert len(files) == 1
    workflow = yaml.load(files[0].read_text(), Loader=yaml.BaseLoader)
    assert workflow["on"] == {"push": {"tags": ["v*"]}}
    assert set(workflow["jobs"]) == {"validate"}
    rendered = json.dumps(workflow).lower()
    for forbidden in ("docker/build-push-action", "build-push", "publish", "container-image"):
        assert forbidden not in rendered
    assert "scripts/release.py plan --tag" in files[0].read_text()
