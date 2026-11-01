"""Check Git candidates for credentials and private runtime artifacts."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
SIGNED = re.compile(r"(?i)X-Amz-(?:Signature|Credential)=[0-9a-f]{64}")
PATTERNS = [re.compile(r"(?m)^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
            re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"), SIGNED]


def check():
    result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT, check=True, capture_output=True)
    problems = []
    for raw in set(result.stdout.split(b"\0")) - {b""}:
        relative = raw.decode()
        path = ROOT / relative
        if path.is_symlink():
            problems.append((relative, "symlinks require explicit publication review"))
            continue
        if not path.is_file():
            continue
        if (path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")
                or (path.name.endswith(".env") or (".env." in path.name and not path.name.endswith(".env.example")))
                or path.name == "config.json"
                or any(part in ("runtime", "secrets", ".venv", "__pycache__") for part in path.relative_to(ROOT).parts)
                or path.suffix in (".db", ".sqlite", ".sqlite3", ".log", ".pem", ".key", ".p12", ".pfx")):
            problems.append((relative, "runtime or credential artifact"))
            continue
        try:
            content = path.read_text()
        except UnicodeError:
            problems.append((relative, "binary file requires explicit publication review"))
            continue
        if any(pattern.search(content) for pattern in PATTERNS):
            problems.append((relative, "possible credential material"))
        if any(match.group(1).lower() != "example.com" and not match.group(1).lower().endswith(".example.com") for match in EMAIL.finditer(content)):
            problems.append((relative, "non-example email address"))
    for relative, reason in sorted(set(problems)):
        print(relative + ": " + reason)
    if not problems:
        print("Git candidate content check passed (synthetic examples and source only).")
    return bool(problems)


if __name__ == "__main__":
    sys.exit(check())
