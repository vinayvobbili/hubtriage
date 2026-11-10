"""The LangGraph engine: each route, the pause before a dismissal, and agreement with the pipeline."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("langgraph.checkpoint.sqlite", reason="needs hubtriage[graph]")

from witness.store import Store  # noqa: E402

from hubtriage import cases, cli, graph, llm  # noqa: E402
from hubtriage.clients import Cassette  # noqa: E402
from hubtriage.findings import SAMPLE_FIELD, Finding  # noqa: E402
from hubtriage.triage import NoModelAnswered, triage  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SYNTHETIC = FIXTURES / "synthetic"


class FakeHub:
    """Security Hub, as far as write-back goes."""

    def __init__(self):
        self.calls: list[dict] = []

    def batch_update_findings(self, **update):
        self.calls.append(update)
        return {"ProcessedFindings": update["FindingIdentifiers"], "UnprocessedFindings": []}


class FakeModel:
    """A judge with no network: a case's recorded answer, marked as the chosen backend's."""

    def __init__(self, case: Path, *, may_dismiss: bool = True):
        self.answer = (case / "model_output.json").read_text(encoding="utf-8")
        self.may_dismiss = may_dismiss
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        answer = llm.Answer(self.answer)
        answer.may_dismiss = self.may_dismiss
        return answer


class Rig:
    """A graph over one checkpoint file, so a pause can be resumed by a second graph."""

    def __init__(self, tmp_path: Path):
        self.tmp_path = tmp_path
        self.db = tmp_path / "graph.db"
        self.hub = FakeHub()
        self.count = 0

    def run(self, case: str, *, judge=None, finding: Finding | None = None, send: bool = True):
        directory = SYNTHETIC / case if (SYNTHETIC / case).exists() else FIXTURES / "heldout" / case
        judge = judge or FakeModel(directory)
        finding = finding or Finding.load(directory / "finding.json")
        self.count += 1
        with graph.checkpointer(self.db) as saver:
            g = graph.build_graph(Cassette(directory / "cassette"), judge, lambda: self.hub, checkpointer=saver)
            return graph.run(g, finding, f"t{self.count}", self.tmp_path / f"s{self.count}" / "case.db", send=send)

    def resume(self, thread: str, decision: str):
        # A fresh connection and a graph with no client or judge: what `hubtriage resume` has.
        with graph.checkpointer(self.db) as saver:
            g = graph.build_graph(None, None, lambda: self.hub, checkpointer=saver)
            return graph.resume(g, thread, decision)

    def paused(self) -> list[dict]:
        with graph.checkpointer(self.db) as saver:
            return graph.paused(graph.build_graph(None, None, checkpointer=saver))


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


def made_sample(case: str) -> Finding:
    doc = json.loads((SYNTHETIC / case / "finding.json").read_text())
    doc.setdefault("ProductFields", {})[SAMPLE_FIELD] = "true"
    return Finding.from_asff(doc)


def with_severity(case: str, label: str) -> Finding:
    doc = json.loads((SYNTHETIC / case / "finding.json").read_text())
    doc["Severity"] = {"Label": label}
    return Finding.from_asff(doc)


def sent_state(hub: FakeHub) -> list[str]:
    return [call["VerificationState"] for call in hub.calls]


# ------------------------------------------------------------------ routes


def test_a_sample_goes_straight_to_write_back_with_no_lookup_and_no_model(rig):
    class NoClient:
        def __getattr__(self, name):
            raise AssertionError("a sample must not be looked up")

    directory = SYNTHETIC / "ci-user-deploys"
    model = FakeModel(directory)
    finding = made_sample("ci-user-deploys")
    with graph.checkpointer(rig.db) as saver:
        g = graph.build_graph(NoClient(), model, lambda: rig.hub, checkpointer=saver)
        result = graph.run(g, finding, "sample", rig.tmp_path / "sample.db", send=True)
    assert result.route == graph.SAMPLE
    assert result.decision.verdict == "sample" and model.prompts == []
    assert sent_state(rig.hub) == ["FALSE_POSITIVE"]


def test_high_severity_goes_to_a_person_even_for_a_true_positive(rig):
    result = rig.run("crypto-domain-build-runner")
    assert result.gate["verdict"] == "true_positive"  # the gate was satisfied
    assert result.route == graph.HUMAN and result.decision.verdict == "needs_human"
    assert "HIGH severity" in result.decision.reason
    assert sent_state(rig.hub) == ["UNKNOWN"]


def test_critical_benign_is_not_dismissed_and_does_not_pause(rig):
    result = rig.run("ci-user-deploys", finding=with_severity("ci-user-deploys", "CRITICAL"))
    assert result.route == graph.HUMAN and rig.paused() == []
    assert sent_state(rig.hub) == ["UNKNOWN"]


def test_a_verdict_the_gate_rejects_goes_to_a_person(rig):
    # The recorded answer says benign; two of its three claims misread the records.
    result = rig.run("root-login-misread")
    assert result.route == graph.HUMAN
    assert result.gate["refused"] == 2 and "refused" in result.decision.reason
    assert sent_state(rig.hub) == ["UNKNOWN"]


def test_needs_human_from_the_model_goes_to_a_person(rig):
    result = rig.run("brute-force-instance-gone")
    assert result.route == graph.HUMAN
    assert sent_state(rig.hub) == ["UNKNOWN"]


def test_benign_from_a_backend_that_may_not_dismiss_goes_to_a_person(rig):
    result = rig.run("ci-user-deploys", judge=FakeModel(SYNTHETIC / "ci-user-deploys", may_dismiss=False))
    assert result.route == graph.HUMAN and rig.paused() == []
    assert "may not dismiss" in result.decision.reason
    assert sent_state(rig.hub) == ["UNKNOWN"]


def test_a_true_positive_is_written_as_it_is(rig):
    result = rig.run("ci-user-creates-admin")
    assert result.route == graph.ESCALATE
    assert sent_state(rig.hub) == ["TRUE_POSITIVE"]


def test_no_model_answer_stops_the_run_and_writes_nothing(rig):
    def down(prompt):
        raise ConnectionError("no host answered")

    with pytest.raises(NoModelAnswered, match="no host answered"):
        rig.run("ci-user-deploys", judge=down)
    assert rig.hub.calls == []


def test_without_send_the_update_is_built_and_not_written(rig):
    result = rig.run("ci-user-creates-admin", send=False)
    assert not result.sent and result.update["VerificationState"] == "TRUE_POSITIVE"
    assert rig.hub.calls == []


# ------------------------------------------------------------------ the pause


def test_benign_from_an_allowed_backend_pauses_before_any_write(rig):
    with pytest.raises(graph.Paused) as stopped:
        rig.run("ci-user-deploys")
    assert rig.hub.calls == []
    (item,) = rig.paused()
    assert item["thread_id"] == stopped.value.thread_id
    assert item["claims"] and item["severity"] == "MEDIUM"


def test_approve_resumes_from_another_process_and_writes_the_dismissal(rig):
    with pytest.raises(graph.Paused) as stopped:
        rig.run("ci-user-deploys")
    result = rig.resume(stopped.value.thread_id, "approve")
    assert result.route == graph.REVIEW and result.decision.verdict == "benign"
    assert sent_state(rig.hub) == ["BENIGN_POSITIVE"]
    assert rig.hub.calls[0]["Workflow"] == {"Status": "NOTIFIED"}  # never RESOLVED or SUPPRESSED
    assert rig.paused() == []


def test_reject_records_needs_human_and_dismisses_nothing(rig):
    with pytest.raises(graph.Paused) as stopped:
        rig.run("ci-user-deploys")
    result = rig.resume(stopped.value.thread_id, "reject")
    assert result.route == graph.HUMAN and result.decision.verdict == "needs_human"
    assert "rejected" in result.decision.reason
    assert sent_state(rig.hub) == ["UNKNOWN"]
    assert rig.paused() == []


def test_a_finished_or_unknown_thread_cannot_be_resumed(rig):
    with pytest.raises(LookupError):
        rig.resume("no-such-thread", "approve")
    with pytest.raises(graph.Paused) as stopped:
        rig.run("ci-user-deploys")
    rig.resume(stopped.value.thread_id, "approve")
    with pytest.raises(LookupError):
        rig.resume(stopped.value.thread_id, "approve")
    assert len(rig.hub.calls) == 1
    with pytest.raises(ValueError):
        rig.resume(stopped.value.thread_id, "maybe")


# ------------------------------------------------------------------ agreement with the pipeline


def every_case():
    return [c for c in cases.discover(FIXTURES) if c.directory.parent.name in ("synthetic", "heldout")]


@pytest.mark.parametrize("case", every_case(), ids=lambda c: c.name)
def test_the_graph_reaches_the_pipeline_s_verdict(rig, case):
    plain = cases.run(case).result
    try:
        result = rig.run(case.name)
    except graph.Paused as stopped:
        result = rig.resume(stopped.thread_id, "approve")
    assert result.gate["verdict"] == plain.decision.verdict
    if result.finding.severity in graph.PERSON_SEVERITIES:
        assert result.decision.verdict == "needs_human"
    else:
        assert result.decision.verdict == plain.decision.verdict
        assert result.update["VerificationState"] == plain.update["VerificationState"]
        assert len(result.decision.admitted) == len(plain.decision.admitted)


def test_the_pipeline_s_triage_function_is_untouched_by_the_graph(tmp_path):
    case = SYNTHETIC / "ci-user-deploys"
    store = Store(tmp_path / "plain.db")
    try:
        result = triage(store, Cassette(case / "cassette"), llm.recorded(case / "model_output.json"),
                        Finding.load(case / "finding.json"))
    finally:
        store.close()
    assert result.decision.verdict == "benign"


# ------------------------------------------------------------------ the command line


def run_cli(capsys, tmp_path, *argv):
    code = cli.main([*argv, "--graph-db", str(tmp_path / "g.db")])
    return code, capsys.readouterr().out


def test_the_pipeline_is_the_default_engine():
    ap_args = {}

    def capture(args):
        ap_args.update(vars(args))
        return 0

    original = cli.cmd_triage
    cli.cmd_triage = capture
    try:
        cli.main(["triage", str(SYNTHETIC / "ci-user-deploys")])
    finally:
        cli.cmd_triage = original
    assert ap_args["engine"] == "pipeline"


def test_triage_pauses_lists_and_resumes_from_the_command_line(capsys, tmp_path):
    case = str(SYNTHETIC / "ci-user-deploys")
    code, out = run_cli(capsys, tmp_path, "triage", case, "--engine", "graph", "--graph-dir", str(tmp_path / "d"))
    assert code == 0 and "paused" in out and "BENIGN_POSITIVE" not in out
    thread = re.search(r"hubtriage resume (\S+) approve", out).group(1)

    code, out = run_cli(capsys, tmp_path, "paused")
    assert thread in out and "1 waiting" in out

    code, out = run_cli(capsys, tmp_path, "resume", thread, "approve")
    assert code == 0 and "benign" in out and "not written back" in out

    code, out = run_cli(capsys, tmp_path, "paused")
    assert "0 waiting" in out


def test_the_graph_command_line_gives_the_pipeline_s_output_for_a_true_positive(capsys, tmp_path):
    case = str(SYNTHETIC / "ci-user-creates-admin")
    _, out = run_cli(capsys, tmp_path, "triage", case, "--engine", "graph", "--graph-dir", str(tmp_path / "d"))
    assert "verdict   true_positive" in out and '"VerificationState": "TRUE_POSITIVE"' in out


# ------------------------------------------------------------------ the model guard


def test_the_graph_engine_takes_its_judge_from_the_pipeline_s_guard(monkeypatch):
    # `pull --engine graph` builds its judge with llm.from_env() before any finding is read,
    # so a public backend is refused there exactly as for the pipeline.
    monkeypatch.setenv("HUBTRIAGE_LLM", "claude")
    with pytest.raises(llm.PublicBackendRefused):
        llm.from_env()
