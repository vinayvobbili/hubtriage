"""What must never be committed, checked on every run rather than remembered."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# State holds account ids and emails; tfvars holds the emails accounts are made with.
FORBIDDEN = re.compile(r"(\.tfstate(\.|$)|(?<!\.example)\.tfvars$|\.tfvars\.json$|\.db$)")


def tracked() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return out.stdout.splitlines()


def test_no_state_or_tfvars_is_tracked():
    assert [p for p in tracked() if FORBIDDEN.search(p)] == []


def test_the_pattern_catches_what_it_should():
    bad = ["terraform/00-org/terraform.tfstate", "x/terraform.tfstate.backup", "a/terraform.tfvars", "c.db"]
    good = ["terraform/00-org/terraform.tfvars.example", "terraform/00-org/.terraform.lock.hcl"]
    assert all(FORBIDDEN.search(p) for p in bad)
    assert not any(FORBIDDEN.search(p) for p in good)


# The shape GitHub's secret scanning (and most others) treat as an AWS access key
# id. Fixtures carry placeholder keys, and a placeholder in this shape - even
# AWS's own documentation example - raises a secret alert on a public repository.
AWS_KEY_ID = re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])")


def test_no_key_shaped_placeholder_is_tracked():
    hits = []
    for path in tracked():
        try:
            text = (ROOT / path).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        hits += [f"{path}: {m.group(0)}" for m in AWS_KEY_ID.finditer(text)]
    assert hits == [], "use a placeholder that is not key-shaped, e.g. ASIA-EXAMPLE-..."


def test_the_key_pattern_catches_what_it_should():
    # Assembled here so this file does not itself carry the shape it forbids.
    shaped = "ASIA" + "IOSFODNN7" + "EXAMPLE"
    assert AWS_KEY_ID.search(f'"AccessKeyId": "{shaped}"')
    assert not AWS_KEY_ID.search('"AccessKeyId": "ASIA-EXAMPLE-ENRICH"')
