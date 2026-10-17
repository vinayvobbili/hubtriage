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
