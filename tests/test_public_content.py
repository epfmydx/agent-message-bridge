"""The content check must report filenames without echoing private values."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace


def checker(tmp_path, monkeypatch, filename, content):
    source = Path(__file__).resolve().parents[1] / "scripts" / "check_public_content.py"
    spec = importlib.util.spec_from_file_location("bridge_public_content_check", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=filename.encode() + b"\0"))
    (tmp_path / filename).write_text(content)
    return module


def test_synthetic_example_address_is_allowed(tmp_path, monkeypatch):
    assert checker(tmp_path, monkeypatch, "sample.txt", "agent@example.com\n").check() is False


def test_credential_candidate_is_detected_without_echoing_value(tmp_path, monkeypatch, capsys):
    marker = "SYNTHETIC_VALUE_MUST_NOT_ECHO"
    module = checker(tmp_path, monkeypatch, "config.txt", "TOKEN=" + marker)
    module.PATTERNS.append(__import__("re").compile(marker))
    assert module.check() is True
    assert marker not in capsys.readouterr().out


def test_private_email_private_key_and_signed_url_are_reported_without_values(tmp_path, monkeypatch, capsys):
    private_email = "agent" + "@" + "private.invalid"
    private_key = "-----BEGIN " + "PRIVATE KEY-----"
    signed_url = "X-Amz-Signature=" + "SYNTHETIC_PRIVATE_SIGNATURE"
    module = checker(tmp_path, monkeypatch, "sample.txt", private_email + "\n" + private_key + "\n" + signed_url + "\n")
    assert module.check() is True
    output = capsys.readouterr().out
    assert private_email not in output and private_key not in output and signed_url not in output
