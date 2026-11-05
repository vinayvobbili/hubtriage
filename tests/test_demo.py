"""The demo video's slides: they build offline, and show only made-up data."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("demo_build", ROOT / "scripts" / "demo" / "build.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)

# AWS's documentation accounts, the only twelve-digit ids a slide may show.
PLACEHOLDER_ACCOUNTS = {"111122223333", "444455556666"}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    return out, demo.build(out)


def test_every_slide_has_a_page_and_narration(built):
    out, reel = built
    assert len(reel["slides"]) >= 8
    for entry in reel["slides"]:
        assert (out / entry["html_file"]).exists() and entry["narration"].strip()
    assert json.loads((out / "reel.json").read_text()) == reel


def test_no_spoken_spelling_starts_with_the_word_a():
    assert [spoken for spoken in demo.PHONETIC.values() if spoken.startswith("A ")] == []


def test_aws_is_spoken_as_three_letters():
    assert demo.PHONETIC[r"\bAWS\b"] == "A.W.S"


def test_without_music_the_reel_has_the_voice_only(built):
    assert "music" not in built[1]


def test_the_terminal_slides_come_from_real_runs_of_the_gate():
    text = demo.decision_text("port-probe-misread-port")
    assert "REFUSE" in text and "record says 22, claim asserts 3389" in text
    assert "available:" not in text


def test_the_records_slide_shows_the_field_the_claim_gets_wrong():
    assert "IpPermissions.0.FromPort" in demo.records_text("port-probe-misread-port")


def test_the_iam_transcript_names_no_account():
    assert not re.search(r"\d{12}", (demo.HERE / "check-iam.txt").read_text(encoding="utf-8"))


def test_slides_show_only_placeholder_accounts(built):
    out, _ = built
    for page in (out / "slides").glob("*.html"):
        visible = re.sub(r"<style>.*?</style>", "", page.read_text(encoding="utf-8"), flags=re.S)
        assert set(re.findall(r"(?<!\d)\d{12}(?!\d)", visible)) <= PLACEHOLDER_ACCOUNTS


def test_the_video_says_no_model_was_measured():
    pages = demo.slides()
    notes = " ".join(body for name, body, _ in pages if name in {"04-refused", "05-downgraded"})
    assert notes.count("Not a measure of any model") == 2
    assert "An accuracy number for any model" in pages[-1][1]
