"""Check active local documentation links and the source-to-guide map."""
import argparse
import glob
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    errors = []
    mapping = json.loads((root/"docs/docs-map.json").read_text())
    if mapping.get("version") != 1 or not isinstance(mapping.get("areas"), dict): return ["Invalid documentation map"]
    for name, area in mapping["areas"].items():
        if not area.get("source") or not area.get("documents"): errors.append("Empty mapping: "+name)
        for pattern in area.get("source", []):
            if not glob.glob(str(root/pattern), recursive=True): errors.append("Unmatched source pattern: "+pattern)
        for document in area.get("documents", []):
            if not (root/document).is_file(): errors.append("Missing mapped guide: "+document)
    paths = [root/"README.md", root/"AGENTS.md", *sorted((root/"docs").rglob("*.md"))]
    for path in paths:
        for value in re.findall(r"\[[^\]]*\]\(([^)]+)\)", path.read_text()):
            value = value.strip("<>")
            target = urlsplit(value)
            if target.scheme or target.netloc or not target.path: continue
            resolved = (path.parent/unquote(target.path)).resolve()
            if not resolved.exists(): errors.append(str(path.relative_to(root))+": broken local link "+target.path)
    return errors


def impact(root=ROOT):
    mapping = json.loads((root/"docs/docs-map.json").read_text())["areas"]
    result = subprocess.run(["git", "ls-files", "--modified", "--others", "--exclude-standard", "-z"], cwd=root, check=True, capture_output=True)
    changed = {p.decode() for p in result.stdout.split(b"\0") if p}
    staged = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"], cwd=root, check=True, capture_output=True)
    changed.update(p.decode() for p in staged.stdout.split(b"\0") if p)
    for name, area in mapping.items():
        sources = {str(Path(p).relative_to(root)) for pattern in area["source"] for p in glob.glob(str(root/pattern), recursive=True)}
        if sources & changed: print(name+": review "+", ".join(area["documents"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--impact", action="store_true")
    args = parser.parse_args()
    try: errors = check()
    except (ValueError, KeyError, OSError) as error: print("Documentation check failed: "+type(error).__name__); return 1
    for error in errors: print(error)
    if errors: return 1
    print("Documentation map and local links passed; heading fragments and external URLs are not checked.")
    if args.impact: impact()
    return 0


if __name__ == "__main__": raise SystemExit(main())
