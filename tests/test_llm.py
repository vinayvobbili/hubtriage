"""The hosted backends, and the rule that keeps live data off the public ones."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hubtriage import cases, cli, llm


def block(kind: str, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(type=kind, text=text)


class FakeAnthropic:
    def __init__(self, *content, stop_reason="end_turn"):
        self.calls = []
        self.reply = SimpleNamespace(content=list(content), stop_reason=stop_reason)
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        return self.reply


def test_claude_returns_the_text_and_leaves_out_the_thinking():
    client = FakeAnthropic(block("thinking"), block("text", '{"verdict": "benign"}'))
    assert llm.claude_api(client=client)("p") == '{"verdict": "benign"}'
    (call,) = client.calls
    assert call["model"] == llm.CLAUDE_MODEL and call["fallbacks"] == "default"
    assert "temperature" not in call


@pytest.mark.parametrize("stop", ["refusal", "max_tokens"])
def test_claude_stopping_short_moves_on_to_the_next_judge(stop):
    judge = llm.failover(
        llm.claude_api(client=FakeAnthropic(block("text", "cut"), stop_reason=stop)),
        lambda prompt: "next",
    )
    assert judge("p") == "next"


def test_a_keychain_failure_names_the_item_and_no_secret(monkeypatch):
    monkeypatch.setattr(
        llm.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 44, stdout="", stderr=""),
    )
    with pytest.raises(llm.NoAnswer, match="made-up-item"):
        llm._keychain_secret("made-up-item")


def agy_run(returncode=0, **reply):
    def run(args, **kw):
        run.args, run.kw = args, kw
        return subprocess.CompletedProcess(args, returncode, stdout=json.dumps(reply), stderr="")

    return run


def test_agy_runs_sandboxed_in_an_empty_directory_and_returns_the_response():
    run = agy_run(status="SUCCESS", response='{"verdict": "benign"}')
    assert llm.agy(run=run)("the prompt") == '{"verdict": "benign"}'
    assert "--sandbox" in run.args and "the prompt" in run.args
    assert "agy-" in run.kw["cwd"]


@pytest.mark.parametrize(
    "run",
    [agy_run(status="ERROR", response="", error="quota reached"), agy_run(returncode=1)],
)
def test_agy_out_of_quota_or_failing_moves_on_to_the_next_judge(run):
    assert llm.failover(llm.agy(run=run), lambda prompt: "next")("p") == "next"


def test_agys_own_error_text_is_what_gets_reported():
    run = agy_run(status="ERROR", response="", error="quota reached")
    with pytest.raises(llm.NoAnswer, match="quota reached"):
        llm.agy(run=run)("p")


# ---------------------------------------------------------------- the eval


def test_a_judge_that_never_answered_is_not_an_accuracy_number(monkeypatch, capsys):
    def down(prompt):
        raise llm.NoAnswer("out of credits")

    monkeypatch.setattr(llm, "from_env", lambda env=None, allow_public=False: down)
    assert cli.main(["eval", "--judge", "env"]) == 1
    out = capsys.readouterr().out
    assert "no accuracy to report" in out and "out of credits" in out
    assert "verdicts correct" not in out


def test_answers_can_be_kept_for_reading_without_touching_the_fixtures(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "from_env", lambda env=None, allow_public=False: lambda prompt: "{}")
    before = {p: p.read_bytes() for p in Path(cli.FIXTURES).rglob("model_output.json")}
    assert cli.main(["eval", "--judge", "env", "--answers", str(tmp_path)]) == 0
    assert {p.name for p in tmp_path.iterdir()} == {f"{p.parent.name}.json" for p in before}
    assert {p: p.read_bytes() for p in before} == before


def test_no_answer_never_scores_as_correct_on_a_needs_human_case(tmp_path):
    def down(prompt):
        raise llm.NoAnswer("out of credits")

    outcomes = [cases.run(case, down) for case in cases.discover(cli.FIXTURES)]
    assert any(o.case.label["verdict"] == "needs_human" for o in outcomes)
    summary = cases.summarize(outcomes)
    assert summary["correct"] == 0 and summary["no_answer"] == summary["cases"]


class FakeBedrock:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def client(self, *a, **kw):
        return self

    def converse(self, **kw):
        self.calls.append(kw)
        return self.reply


def test_bedrock_skips_reasoning_blocks_and_sends_no_temperature():
    session = FakeBedrock({
        "stopReason": "end_turn",
        "output": {"message": {"content": [{"reasoningContent": {}}, {"text": "answer"}]}},
    })
    assert llm.bedrock("a-model", session=session)("p") == "answer"
    assert "temperature" not in session.calls[0]["inferenceConfig"]


def test_bedrock_stopping_short_is_not_an_answer():
    session = FakeBedrock({"stopReason": "refusal", "output": {"message": {"content": []}}})
    with pytest.raises(llm.NoAnswer):
        llm.bedrock("a-model", session=session)("p")


# ------------------------------------------------------------- the privacy rule


@pytest.mark.parametrize("backend", ["claude", "agy", "local,claude"])
def test_public_backends_are_refused_by_default(backend):
    with pytest.raises(llm.PublicBackendRefused):
        llm.from_env({"HUBTRIAGE_LLM": backend})


def test_public_backends_are_built_when_the_data_is_made_up():
    judge = llm.from_env({"HUBTRIAGE_LLM": "claude,agy"}, allow_public=True)
    assert "claude_api" in judge.__name__ and "agy" in judge.__name__


def test_only_cases_under_fixtures_count_as_made_up(monkeypatch, tmp_path):
    monkeypatch.setenv("HUBTRIAGE_LLM", "claude")
    assert cli._judge("env", cli.FIXTURES / "synthetic") is not None
    with pytest.raises(llm.PublicBackendRefused):
        cli._judge("env", tmp_path)
    with pytest.raises(llm.PublicBackendRefused):
        cli._judge("env")
    with pytest.raises(llm.PublicBackendRefused):
        cli._judge("env", cli.FIXTURES / ".." / "recordings")


@pytest.mark.parametrize("command", [["consume", "--queue-url", "q"], ["pull"]])
def test_the_live_commands_refuse_a_public_backend(monkeypatch, command):
    pytest.importorskip("boto3")
    monkeypatch.setenv("HUBTRIAGE_LLM", "claude")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with pytest.raises(llm.PublicBackendRefused):
        cli.main(command)


def test_the_fixtures_directory_holds_only_the_synthetic_set():
    assert [p.name for p in Path(cli.FIXTURES).iterdir() if p.is_dir()] == ["synthetic"]
