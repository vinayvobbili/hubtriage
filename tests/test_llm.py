"""The hosted backends, and the rule that keeps live data off the public ones."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hubtriage import cases, cli, llm, scrub, verdict


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
    asked = [o for o in outcomes if o.case.label["verdict"] != "sample"]
    assert any(o.case.label["verdict"] == "needs_human" for o in asked)
    summary = cases.summarize(asked)
    assert summary["correct"] == 0 and summary["no_answer"] == summary["cases"]
    # A sample never needed the model, so a model outage changes nothing about it.
    assert all(o.correct for o in outcomes if o.case.label["verdict"] == "sample")


def scored(label: dict, said: str) -> cases.Outcome:
    decision = SimpleNamespace(verdict=said, refused=[], outcomes=[])
    return cases.Outcome(cases.Case("c", Path("."), label), SimpleNamespace(answer="{}", decision=decision))


def test_a_contested_case_accepts_its_other_verdict_but_never_a_dismissal():
    label = {"verdict": "true_positive", "also_correct": ["needs_human"]}
    assert scored(label, "true_positive").correct and scored(label, "needs_human").correct
    assert not scored(label, "benign").correct and scored(label, "benign").false_benign


def test_the_eval_counts_dismissals_apart_from_cheap_mix_ups():
    outcomes = [
        scored({"verdict": "true_positive"}, "needs_human"),  # still reaches a person
        scored({"verdict": "needs_human"}, "benign"),  # dismissed
        scored({"verdict": "benign"}, "benign"),
    ]
    s = cases.summarize(outcomes)
    assert (s["correct"], s["false_benign"]) == (1, 1)
    assert s["confusion"]["true_positive"]["needs_human"] == 1
    assert s["confusion"]["needs_human"]["benign"] == 1


def test_the_eval_prints_false_benigns_and_the_table(monkeypatch, capsys):
    monkeypatch.setattr(llm, "from_env", lambda env=None, allow_public=False: lambda prompt: "{}")
    assert cli.main(["eval", "--judge", "env"]) == 0
    out = capsys.readouterr().out
    assert "false benign" in out and "said needs_human" in out and "contested" in out


def test_a_local_server_is_sent_the_answer_schema_with_its_caps(monkeypatch):
    sent = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()

    def urlopen(request, timeout):
        sent.update(json.loads(request.data))
        return Reply()

    monkeypatch.setattr(llm.urllib.request, "urlopen", urlopen)
    assert llm.openai_compatible("http://a/v1", "m")("p") == "{}"
    schema = sent["response_format"]["json_schema"]["schema"]
    assert schema["properties"]["verdict"]["enum"] == list(verdict.VERDICTS)
    assert schema["properties"]["summary"]["maxLength"] and list(schema["properties"])[:2] == ["verdict", "claims"]


def test_the_answer_schema_accepts_what_the_parser_accepts():
    jsonschema = pytest.importorskip("jsonschema")
    for path in Path(cli.FIXTURES).rglob("model_output.json"):
        jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), verdict.JSON_SCHEMA)


LOCAL = {"HUBTRIAGE_LLM": "local", "HUBTRIAGE_LOCAL_URLS": "http://a/v1", "HUBTRIAGE_LOCAL_MODEL": "m"}


def local_saying(monkeypatch, text):
    monkeypatch.setattr(llm, "openai_compatible", lambda url, model, timeout=120.0: lambda prompt: text)


def test_the_local_model_may_answer_but_not_dismiss_unless_named(monkeypatch):
    local_saying(monkeypatch, "{}")
    assert llm.from_env(LOCAL)("p") == "{}" and not llm.may_dismiss(llm.from_env(LOCAL)("p"))
    assert llm.may_dismiss(llm.from_env({**LOCAL, "HUBTRIAGE_MAY_DISMISS": "local"})("p"))
    assert llm.may_dismiss("a recorded answer")


def test_a_benign_from_a_model_that_may_not_dismiss_goes_to_a_person(monkeypatch):
    benign = next(c for c in cases.discover(cli.FIXTURES) if c.name == "web-https-approved")
    local_saying(monkeypatch, (benign.directory / "model_output.json").read_text(encoding="utf-8"))
    held = cases.run(benign, llm.from_env(LOCAL)).result.decision
    trusted = cases.run(benign, llm.from_env({**LOCAL, "HUBTRIAGE_MAY_DISMISS": "local"})).result.decision
    assert (held.verdict, held.model_verdict) == ("needs_human", "benign") and "may not dismiss" in held.reason
    assert trusted.verdict == "benign"


def test_an_escalation_from_a_model_that_may_not_dismiss_still_stands(monkeypatch):
    tp = next(c for c in cases.discover(cli.FIXTURES) if c.name == "ssh-brute-force-open")
    local_saying(monkeypatch, (tp.directory / "model_output.json").read_text(encoding="utf-8"))
    assert cases.run(tp, llm.from_env(LOCAL)).result.decision.verdict == "true_positive"


def test_a_queued_local_server_can_be_given_longer_to_answer(monkeypatch):
    seen = []
    def fake(url, model, timeout=120.0):
        seen.append(timeout)
        return lambda prompt: "{}"

    monkeypatch.setattr(llm, "openai_compatible", fake)
    env = {"HUBTRIAGE_LLM": "local", "HUBTRIAGE_LOCAL_URLS": "http://a/v1", "HUBTRIAGE_LOCAL_MODEL": "m"}
    llm.from_env(env)
    llm.from_env({**env, "HUBTRIAGE_LOCAL_TIMEOUT": "900"})
    assert seen == [120.0, 900.0]


def test_saved_answers_can_be_rescored_without_a_model(monkeypatch, tmp_path, capsys):
    def no_model(env=None, allow_public=False):
        raise AssertionError("re-scoring must not ask a model")

    monkeypatch.setattr(llm, "from_env", no_model)
    for path in Path(cli.FIXTURES).rglob("model_output.json"):
        (tmp_path / f"{path.parent.name}.json").write_bytes(path.read_bytes())
    assert cli.main(["eval", "--judge", f"answers:{tmp_path}"]) == 0
    assert "false benign" in capsys.readouterr().out


def test_the_prompt_tells_the_model_a_value_keeps_its_type():
    # Claude cited a CloudTrail readOnly=true as "true" and the gate refused a correct reading.
    from hubtriage import prompt

    assert "keeps its JSON type" in prompt.INSTRUCTIONS


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


def test_the_fixtures_directory_holds_only_made_up_cases():
    # Public backends may read anything under fixtures/, so a case recorded from a real account goes there
    # only scrubbed, and every file of it still has to pass scrub's own leftover check.
    assert sorted(p.name for p in Path(cli.FIXTURES).iterdir() if p.is_dir()) == ["heldout", "recorded", "synthetic"]
    for case in cases.discover(cli.FIXTURES):
        source = case.label["source"]
        assert source.startswith("synthetic") or source.startswith("scrubbed"), case.name
        if source.startswith("scrubbed"):
            assert case.directory.parent.name == "recorded", case.name
            for path in case.directory.rglob("*.json"):
                assert scrub.leftovers(path.read_text(encoding="utf-8")) == [], path
