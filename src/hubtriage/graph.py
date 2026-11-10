"""The triage flow as a LangGraph graph: an alternative engine beside `triage.triage`.

Same steps, same functions - evidence.collect, prompt.build, verdict.decide, build_update,
hub.write_back - as nodes, with the routing made explicit:

    check_sample -> enrich -> judge -> gate -> decide -> human ----------> write_back
         |                                        |  \\-> approve_dismissal -/
         \\--------------------------------------------------------------> write_back

- A sample goes straight to write-back as SAMPLE, with no lookup and no model.
- needs_human (a refused claim, an unparseable answer, a backend that may not dismiss) and any
  HIGH or CRITICAL finding go to `human`: recorded as needs_human, never dismissed.
- A benign verdict that survived the gate pauses at `approve_dismissal` with `interrupt()`.
  Approve writes it as the pipeline would (BENIGN_POSITIVE, still NOTIFIED); reject records
  needs_human. The pause is kept in a SQLite checkpoint, so `hubtriage resume` can finish it
  from another process, days later.
- A true positive is written as it is.

The model is a hubtriage judge (llm.py), not a separate chat-model wrapper, so the rules that keep
live findings off public APIs and decide who may dismiss (`Answer.may_dismiss`) are the ones
the pipeline uses. The graph never builds a judge: the caller passes one, from `llm.from_env`.

Needs the `graph` extra: pip install 'hubtriage[graph]'.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from witness.store import Store

from . import evidence as ev
from . import hub, prompt, verdict
from .clients import Client
from .findings import Finding
from .llm import Judge, may_dismiss
from .triage import NoModelAnswered, Result
from .writeback import build_update

# These always go to a person, whatever the model said.
PERSON_SEVERITIES = {"HIGH", "CRITICAL"}

# Where a triage ended up: the value of the state's `route`.
SAMPLE, HUMAN, REVIEW, ESCALATE = "sample", "human", "review", "escalate"

APPROVE, REJECT = "approve", "reject"

DEFAULT_DB = "runs/graph.db"  # runs/ is gitignored


class TriageState(TypedDict, total=False):
    finding: Finding
    store_path: str  # the witness store holding this finding's records; reopened by each node
    send: bool  # write the update to Security Hub, or only build it
    mode: str  # "replay" or "live", as for evidence.collect
    evidence: ev.Evidence
    prompt: str
    answer: str
    may_dismiss: bool  # whether the backend that answered may close a finding
    judge_error: str
    decision: verdict.Decision
    gate: dict  # what the gate did: claims, admitted, refused, and the verdict it reached
    route: str
    reviewed: str  # approve or reject, from the person who resumed a paused dismissal
    update: dict
    written: dict


class Paused(RuntimeError):
    """The triage stopped before a dismissal and waits for `resume`."""

    def __init__(self, thread_id: str, request: dict):
        super().__init__(f"paused before dismissing {request.get('title')!r}; thread {thread_id}")
        self.thread_id = thread_id
        self.request = request


@contextmanager
def _store(state: TriageState) -> Iterator[Store]:
    store = Store(state["store_path"])
    try:
        yield store
    finally:
        store.close()


def _needs_human(decision: verdict.Decision, reason: str) -> verdict.Decision:
    """The same claims and outcomes, recorded as a request for a person."""
    return verdict.Decision(
        verdict.NEEDS_HUMAN, decision.model_verdict, decision.summary, decision.outcomes, reason=reason
    )


def build_graph(
    client: Client | None,
    judge: Judge | None,
    securityhub: Callable[[], Any] | None = None,
    *,
    checkpointer: Any = None,
):
    """`securityhub` is a factory, called only when a triage is sent: resuming a paused
    one needs no AWS client unless it writes back. `client` and `judge` are None for a
    graph that only resumes."""

    def check_sample(state: TriageState) -> dict:
        finding = state["finding"]
        if not finding.is_sample:
            return {}
        # Decided by GuardDuty's own mark: no lookup, no model, no one emailed.
        with _store(state) as store:
            evidence = ev.Evidence(finding_record_id=ev.ingest_finding(store, finding))
        decision = verdict.Decision(
            verdict.SAMPLE, None, "", reason="a GuardDuty sample finding; nothing to triage"
        )
        return {"evidence": evidence, "prompt": "", "answer": "", "decision": decision, "route": SAMPLE}

    def enrich(state: TriageState) -> dict:
        with _store(state) as store:
            return {"evidence": ev.collect(store, client, state["finding"], mode=state["mode"])}

    def judge_node(state: TriageState) -> dict:
        with _store(state) as store:
            text = prompt.build(store, state["finding"], state["evidence"])
        try:
            answer = judge(text)
        except Exception as e:  # noqa: BLE001 - kept as the reason; decide stops the run
            return {"prompt": text, "answer": "", "judge_error": f"no model answered: {e}"}
        # The answer's own mark is read here: a checkpoint stores it as a plain string.
        return {"prompt": text, "answer": str(answer), "may_dismiss": may_dismiss(answer)}

    def gate(state: TriageState) -> dict:
        finding = state["finding"]
        if state.get("judge_error"):
            decision = verdict.Decision(verdict.NEEDS_HUMAN, None, "", reason=state["judge_error"])
        else:
            with _store(state) as store:
                decision = verdict.decide(
                    store, state["answer"], host=finding.account_id,
                    shown=state["evidence"].kinds(), may_dismiss=state["may_dismiss"],
                )
        summary = {
            "claims": len(decision.outcomes),
            "admitted": len(decision.admitted),
            "refused": len(decision.refused),
            "verdict": decision.verdict,
        }
        return {"decision": decision, "gate": summary}

    def decide(state: TriageState) -> dict:
        # Same as triage.require_answer: no answer concludes nothing, and writing back
        # would take a live finding out of NEW for good.
        if state.get("judge_error"):
            raise NoModelAnswered(state["judge_error"])
        decision = state["decision"]
        if decision.verdict == verdict.NEEDS_HUMAN or state["finding"].severity in PERSON_SEVERITIES:
            return {"route": HUMAN}
        if decision.verdict == verdict.BENIGN:
            return {"route": REVIEW}
        return {"route": ESCALATE}

    def human(state: TriageState) -> dict:
        decision, finding = state["decision"], state["finding"]
        if decision.verdict == verdict.NEEDS_HUMAN:
            return {}
        reason = (
            f"{finding.severity} severity; a person decides, whatever the model said"
            f" ({decision.model_verdict})"
        )
        return {"decision": _needs_human(decision, reason)}

    def approve_dismissal(state: TriageState) -> dict:
        finding, decision = state["finding"], state["decision"]
        # Before anything with an effect: on resume the node runs again from the top.
        reply = interrupt({
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "account_id": finding.account_id,
            "claims": [o.claim.text for o in decision.admitted],
            "summary": decision.summary,
        })
        if reply is True or str(reply).lower() in (APPROVE, "approved"):
            return {"reviewed": APPROVE}
        return {
            "reviewed": REJECT,
            "route": HUMAN,
            "decision": _needs_human(decision, "a reviewer rejected the dismissal; a person decides"),
        }

    def write_back(state: TriageState) -> dict:
        finding, decision = state["finding"], state["decision"]
        with _store(state) as store:
            update = build_update(finding, decision, store.head())
        if state.get("mode") == "live" and state.get("answer"):
            # Beside the store, where a recorded case keeps it (see cases.record).
            Path(state["store_path"]).with_name("model_output.json").write_text(
                state["answer"], encoding="utf-8"
            )
        if state.get("send") and securityhub is not None:
            hub.write_back(securityhub(), update)
            return {"update": update, "written": {"sent": True}}
        return {"update": update, "written": {"sent": False}}

    g = StateGraph(TriageState)
    g.add_node("check_sample", check_sample)
    g.add_node("enrich", enrich)
    g.add_node("judge", judge_node)
    g.add_node("gate", gate)
    g.add_node("decide", decide)
    g.add_node("human", human)
    g.add_node("approve_dismissal", approve_dismissal)
    g.add_node("write_back", write_back)
    g.add_edge(START, "check_sample")
    g.add_conditional_edges(
        "check_sample", lambda s: "write_back" if s.get("route") == SAMPLE else "enrich",
        ["write_back", "enrich"],
    )
    g.add_edge("enrich", "judge")
    g.add_edge("judge", "gate")
    g.add_edge("gate", "decide")
    g.add_conditional_edges(
        "decide", lambda s: {HUMAN: "human", REVIEW: "approve_dismissal", ESCALATE: "write_back"}[s["route"]],
        ["human", "approve_dismissal", "write_back"],
    )
    g.add_edge("human", "write_back")
    g.add_conditional_edges(
        "approve_dismissal", lambda s: "human" if s["route"] == HUMAN else "write_back",
        ["human", "write_back"],
    )
    g.add_edge("write_back", END)
    return g.compile(checkpointer=checkpointer)


@contextmanager
def checkpointer(path: str | Path = DEFAULT_DB) -> Iterator[SqliteSaver]:
    """The SQLite file that keeps paused triages between processes."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    try:
        yield SqliteSaver(conn)
    finally:
        conn.close()


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


@dataclass
class GraphResult(Result):
    """What the pipeline's Result holds, plus where the graph sent it."""

    route: str = ""
    gate: dict = field(default_factory=dict)
    sent: bool = False


def result_of(state: dict) -> GraphResult:
    return GraphResult(
        state["finding"], state["evidence"], state["prompt"], state["answer"],
        state["decision"], state["update"], route=state["route"], gate=state.get("gate", {}),
        sent=state["written"]["sent"],
    )


def _outcome(graph, thread_id: str, out: dict) -> GraphResult:
    """The finished triage, or Paused if it stopped at a dismissal."""
    if "__interrupt__" in out:
        raise Paused(thread_id, out["__interrupt__"][0].value)
    return result_of(out)


def run(
    graph, finding: Finding, thread_id: str, store_path: str | Path, *, send: bool = False,
    mode: str = "replay",
) -> GraphResult:
    """Triage one finding. The thread id is how a pause is found again."""
    Path(store_path).parent.mkdir(parents=True, exist_ok=True)
    start = {"finding": finding, "store_path": str(store_path), "send": send, "mode": mode}
    return _outcome(graph, thread_id, graph.invoke(start, _config(thread_id)))


def resume(graph, thread_id: str, decision: str) -> GraphResult:
    """Finish a paused triage: `approve` writes the dismissal, `reject` records needs_human."""
    if decision not in (APPROVE, REJECT):
        raise ValueError(f"decision must be {APPROVE} or {REJECT}, not {decision!r}")
    if thread_id not in {p["thread_id"] for p in paused(graph)}:
        raise LookupError(f"no paused triage {thread_id!r}")
    return _outcome(graph, thread_id, graph.invoke(Command(resume=decision), _config(thread_id)))


def paused(graph) -> list[dict]:
    """Every triage waiting at a dismissal, newest first, with what the person is asked."""
    # Read the whole listing first: the saver holds its lock while a listing is open,
    # and get_state needs it.
    threads = list(dict.fromkeys(i.config["configurable"]["thread_id"] for i in graph.checkpointer.list(None)))
    waiting = []
    for thread_id in threads:
        snapshot = graph.get_state(_config(thread_id))
        requests = [i.value for task in snapshot.tasks for i in task.interrupts]
        if requests:
            waiting.append({"thread_id": thread_id, **requests[0]})
    return waiting
