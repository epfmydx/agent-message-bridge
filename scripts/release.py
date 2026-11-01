"""Validate source-only release versions without publishing artifacts."""
import argparse
import ast
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[1]

def canonical_version(tag):
    if not isinstance(tag, str) or len(tag) > 128:
        raise ValueError("Release tag must be vMAJOR.MINOR.PATCH[-prerelease]")
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?", tag)
    if not match or (match[4] and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in match[4].split("."))):
        raise ValueError("Release tag must use canonical vMAJOR.MINOR.PATCH[-prerelease]")
    return tag[1:]

def source_version(root=ROOT):
    tree = ast.parse((Path(root) / "bridge" / "__init__.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets):
            value = ast.literal_eval(node.value)
            if not isinstance(value, str):
                break
            return value
    raise ValueError("Application version is missing")

def release_plan(tag, root=ROOT):
    version = canonical_version(tag)
    chart = yaml.safe_load((Path(root) / "charts" / "agent-message-bridge" / "Chart.yaml").read_text())
    if (not isinstance(chart, dict) or chart.get("name") != "agent-message-bridge"
            or str(chart.get("version")) != version or str(chart.get("appVersion")) != version
            or source_version(root) != version):
        raise ValueError("Release tag, application version and chart versions must match")
    return {"version": version, "tag": tag, "artifact_kind": "source"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        result = release_plan(args.tag)
    except ValueError as exc:
        parser.error(str(exc))
    print("".join(k + "=" + v + "\n" for k, v in result.items()), end="")

if __name__ == "__main__":
    main()
