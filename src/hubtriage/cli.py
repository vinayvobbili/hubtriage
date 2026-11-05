"""hubtriage command line.

    hubtriage demo                      the labeled set, offline, each case checked
    hubtriage eval [--judge env]        accuracy and refusals over the labeled set
    hubtriage plan FINDING.json         the AWS questions a finding raises
    hubtriage records CASE_DIR          the records a case's model sees, with ids
    hubtriage triage CASE_DIR           one case, verdict and write-back request
    hubtriage pull --out DIR            live: new findings, recorded as cases
    hubtriage consume --queue-url URL   live: findings from the SQS queue, recorded as cases
    hubtriage check-iam --finding-id ID live: prove the agent's IAM limits on a sample finding
    hubtriage status                    live: read-only health of the security account
    hubtriage sample [--wait SECONDS]   live: generate GuardDuty samples, wait for the queue
    hubtriage test-alert                live: send one test email through the alarm
    hubtriage answers DIR               what each saved model answer said (eval --answers)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from witness.store import Store

from . import cases, consumer, evidence, guardrails, hub, live, llm, verdict
from .clients import Cassette
from .findings import Finding
from .triage import require_answer

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _judge(spec: str, fixtures: str | Path | None = None) -> llm.Judge | None:
    """None means each case's own recorded answer. Public backends need made-up cases."""
    if spec == "recorded":
        return None
    if spec == "env":
        made_up = fixtures is not None and Path(fixtures).resolve().is_relative_to(FIXTURES)
        return llm.from_env(allow_public=made_up)
    raise SystemExit(f"unknown judge {spec!r}; use recorded or env")


def _print_decision(result) -> None:
    d = result.decision
    print(f"  verdict   {d.verdict}  (model said {d.model_verdict or 'nothing parseable'})")
    if d.reason:
        print(f"  why       {d.reason}")
    for o in d.outcomes:
        mark = "ADMIT " if o.admitted else "REFUSE"
        print(f"  {mark}    {o.claim.text}")
        if not o.admitted:
            # The gate lists every field a record has, which can run to pages.
            print(f"            {o.reason.split('; available:')[0]}")


def cmd_demo(args) -> int:
    found = cases.discover(args.fixtures)
    failures = 0
    for case in found:
        outcome = cases.run(case)
        ok = outcome.correct and outcome.refused_as_expected
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {case.name}  expected {case.label['verdict']}")
        _print_decision(outcome.result)
        if args.verbose:
            print(json.dumps(outcome.result.update, indent=2))
        print()
    print(f"{len(found) - failures}/{len(found)} cases came out as labeled")
    return 1 if failures or not found else 0


def cmd_eval(args) -> int:
    found = cases.discover(args.fixtures)
    judge = _judge(args.judge, args.fixtures)
    outcomes = []
    for case in found:
        outcome = cases.run(case, judge)
        outcomes.append(outcome)
        if args.save_answers and judge is not None:
            (case.directory / "model_output.json").write_text(
                outcome.result.answer, encoding="utf-8"
            )
        if args.answers:
            Path(args.answers).mkdir(parents=True, exist_ok=True)
            (Path(args.answers) / f"{case.name}.json").write_text(
                outcome.result.answer, encoding="utf-8"
            )
        print(
            f"{case.name:40} {outcome.result.decision.verdict:14}"
            f" expected {case.label['verdict']:14}"
            f" refused {len(outcome.result.decision.refused)}/{len(outcome.result.decision.outcomes)}"
        )
        if not outcome.answered:
            print(f"  {outcome.result.decision.reason[:300]}")
    s = cases.summarize(outcomes)
    if args.json:
        Path(args.json).write_text(json.dumps(s, indent=2) + "\n", encoding="utf-8")
    if s["no_answer"]:
        print(f"\nno accuracy to report: {s['no_answer']} of {s['cases']} cases got no answer")
        return 1
    print(
        f"\n{s['correct']}/{s['cases']} verdicts correct;"
        f" the gate refused {s['refused']} of {s['claims']} claims"
    )
    return 0


def cmd_plan(args) -> int:
    finding = Finding.load(args.finding)
    for lookup in evidence.plan(finding):
        print(json.dumps({"service": lookup.service, "operation": lookup.operation,
                          "params": lookup.params}))
    return 0


def cmd_records(args) -> int:
    case = cases.Case(Path(args.case).name, Path(args.case), {})
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "case.db")
        found = evidence.collect(store, Cassette(case.directory / "cassette"), case.finding)
        for c in found.collected:
            if c.error:
                print(f"# {c.lookup.label}: {c.error}")
        for record in store.query_records(kind=args.kind):
            print(f"[{record['record_id']}] kind={record['kind']}")
            for name, value in record["fields"].items():
                print(f"  {name} = {json.dumps(value)}")
        store.close()
    return 0


def cmd_triage(args) -> int:
    case = cases.Case(Path(args.case).name, Path(args.case), {})
    outcome = cases.run(case, _judge(args.judge))
    _print_decision(outcome.result)
    print(json.dumps(outcome.result.update, indent=2))
    return 0


def cmd_pull(args) -> int:
    import boto3

    from .clients import AwsClient

    session = boto3.Session()
    securityhub = session.client("securityhub", region_name=args.region)
    judge = llm.from_env()
    live = AwsClient(enrich_role=args.enrich_role, session=session)
    for count, raw in enumerate(hub.new_findings(securityhub, args.product), start=1):
        if count > args.limit:
            break
        result = require_answer(cases.record(raw, args.out, live, judge))
        print(result.finding.title)
        _print_decision(result)
        if args.write_back:
            hub.write_back(securityhub, result.update)
            print("  written back to Security Hub")
        print()
    return 0


def cmd_consume(args) -> int:
    if not args.queue_url:
        raise SystemExit("no queue: pass --queue-url or set HUBTRIAGE_QUEUE_URL"
                         " (terraform output findings_queue_url in terraform/10-security)")
    import boto3

    from .clients import AwsClient

    session = boto3.Session()
    securityhub = session.client("securityhub", region_name=args.region)
    judge = llm.from_env()
    live = AwsClient(enrich_role=args.enrich_role, session=session)
    answered: set[str] = set()

    def handle(raw: dict) -> None:
        result = consumer.triage_new(
            securityhub,
            raw,
            lambda current: cases.record(current, args.out, live, judge),
            write_back=args.write_back,
            product=args.product,
            answered=answered,
        )
        if result is not None:
            print(result.finding.title)
            _print_decision(result)
            print()

    sqs = session.client("sqs", region_name=args.region)
    tally = consumer.drain(sqs, args.queue_url, handle, delete=args.write_back, follow=args.follow)
    print(f"{tally.messages} message(s), {tally.failed} left on the queue")
    return 1 if tally.failed else 0


def cmd_check_iam(args) -> int:
    import boto3

    securityhub = boto3.Session().client("securityhub", region_name=args.region)
    raw = hub.read(securityhub, args.finding_id)
    probes = guardrails.check(securityhub, raw)
    for probe in probes:
        print(f"{'ok  ' if probe.ok else 'FAIL'} {probe.name:28} expected {probe.expected}, got {probe.got}")
    failed = sum(not probe.ok for probe in probes)
    print(f"{len(probes) - failed}/{len(probes)} as expected")
    return 1 if failed else 0


def cmd_status(args) -> int:
    import boto3

    lines = live.status(boto3.Session(), args.region)
    for line in lines:
        print(f"{'ok  ' if line.ok else 'FAIL'} {line.name:22} {line.value}")
    return 0 if all(line.ok for line in lines) else 1


def cmd_sample(args) -> int:
    import boto3

    session = boto3.Session()
    live.generate_samples(session.client("guardduty", region_name=args.region), args.type)
    print("sample findings generated")
    if not args.wait:
        return 0
    arrived = live.wait_for_queue(session.client("sqs", region_name=args.region), args.wait)
    print(f"{arrived} message(s) on the queue" if arrived else "nothing arrived in time")
    return 0 if arrived else 1


def cmd_test_alert(args) -> int:
    import boto3

    live.test_alert(boto3.Session().client("cloudwatch", region_name=args.region))
    print("alarm forced; one email should arrive shortly")
    return 0


def cmd_answers(args) -> int:
    for path in sorted(Path(args.directory).glob("*.json")):
        print(path.stem)
        try:
            model = verdict.parse(path.read_text(encoding="utf-8"))
        except verdict.VerdictError as e:
            print(f"  {e}\n")
            continue
        print(f"  {model.verdict}, {len(model.claims)} claim(s)\n  {model.summary}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hubtriage", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("demo", help="run the labeled set offline and check each case")
    p.add_argument("--fixtures", default=FIXTURES)
    p.add_argument("-v", "--verbose", action="store_true", help="print each write-back request")
    p.set_defaults(fn=cmd_demo)

    p = sub.add_parser("eval", help="verdict accuracy and gate refusals over the labeled set")
    p.add_argument("--fixtures", default=FIXTURES)
    p.add_argument("--judge", default="recorded", help="recorded (default) or env")
    p.add_argument("--save-answers", action="store_true", help="keep live answers as recordings")
    p.add_argument("--answers", help="also write each model answer to this directory, to read")
    p.add_argument("--json", help="also write the summary here")
    p.set_defaults(fn=cmd_eval)

    p = sub.add_parser("plan", help="the lookups a finding raises")
    p.add_argument("finding")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("records", help="the records a case's model sees")
    p.add_argument("case")
    p.add_argument("--kind")
    p.set_defaults(fn=cmd_records)

    p = sub.add_parser("triage", help="triage one case directory")
    p.add_argument("case")
    p.add_argument("--judge", default="recorded")
    p.set_defaults(fn=cmd_triage)

    p = sub.add_parser("pull", help="live: triage new findings and record each as a case")
    p.add_argument("--out", default="recordings")
    p.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.add_argument("--product", default="GuardDuty")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--enrich-role", default="hubtriage-enrich")
    p.add_argument("--write-back", action="store_true", help="send each verdict to Security Hub")
    p.set_defaults(fn=cmd_pull)

    p = sub.add_parser("consume", help="live: triage findings from the SQS queue")
    p.add_argument("--queue-url", default=os.environ.get("HUBTRIAGE_QUEUE_URL"))
    p.add_argument("--out", default="recordings")
    p.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.add_argument("--product", default="GuardDuty")
    p.add_argument("--enrich-role", default="hubtriage-enrich")
    p.add_argument("--follow", action="store_true", help="keep waiting when the queue is empty")
    p.add_argument(
        "--write-back",
        action="store_true",
        help="send each verdict and delete its message; without it, messages stay on the queue"
        " and each run counts toward the dead-letter limit of three receives",
    )
    p.set_defaults(fn=cmd_consume)

    p = sub.add_parser("check-iam", help="live: try every write the agent must be refused")
    p.add_argument("--finding-id", required=True, help="a GuardDuty sample; anything else is refused")
    p.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.set_defaults(fn=cmd_check_iam)

    region = os.environ.get("AWS_REGION", "us-east-1")
    p = sub.add_parser("status", help="live: read-only health of the security account")
    p.add_argument("--region", default=region)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("sample", help="live: generate GuardDuty sample findings")
    p.add_argument("--type", action="append", help="a finding type; repeatable")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for them on the queue")
    p.add_argument("--region", default=region)
    p.set_defaults(fn=cmd_sample)

    p = sub.add_parser("test-alert", help="live: send one test email through the alarm")
    p.add_argument("--region", default=region)
    p.set_defaults(fn=cmd_test_alert)

    p = sub.add_parser("answers", help="what each saved model answer said")
    p.add_argument("directory")
    p.set_defaults(fn=cmd_answers)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
