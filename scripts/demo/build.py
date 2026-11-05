"""The README's demo video: its slides and narration. Writes slides/*.html and reel.json into a folder;
then slidecast (https://pypi.org/project/slidecast/) renders the video. See scripts/demo/README.md.

    python scripts/demo/build.py scripts/demo/out [--music DIR]
    slidecast render scripts/demo/out/reel.json -o scripts/demo/out/hubtriage-demo.mp4 --poster

The terminal slides come from running the code on fixtures/synthetic, so they follow the code, and their ids
are the placeholders AWS and the RFCs reserve for examples. check-iam.txt is one real run of `hubtriage
check-iam` against AWS, on a GuardDuty sample; its output names fields and no account.
"""

from __future__ import annotations

import argparse
import contextlib
import html
import io
import json
from pathlib import Path

from hubtriage import cases, cli

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
SYNTHETIC = cli.FIXTURES / "synthetic"
REPO = "github.com/vinayvobbili/hubtriage"

CSS = """
html { zoom: 1.5; }  /* designed at 1280x720, rendered at 1920x1080 */
* { box-sizing: border-box; margin: 0; padding: 0; }
body { width: 1280px; height: 720px; overflow: hidden; color: #eefbf8;
  font-family: -apple-system, "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
  background: radial-gradient(1100px 680px at 88% -12%, #0f766e 0%, transparent 60%),
              radial-gradient(900px 620px at -12% 112%, #b45309 0%, transparent 55%), #06141a; }
.brand { position: absolute; top: 26px; right: 40px; display: flex; align-items: center; gap: 10px;
  font-weight: 700; font-size: 20px; letter-spacing: -.01em; opacity: .92; }
.logo { width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, #2dd4bf, #f59e0b);
  display: grid; place-items: center; }
.logo::after { content: ""; width: 9px; height: 14px; border: solid #fff; border-width: 0 3px 3px 0;
  transform: rotate(40deg) translate(-1px, -1px); }
.brand b { color: #5eead4; }
header { position: absolute; top: 24px; left: 40px; right: 220px; }
.step { display: inline-flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 700;
  letter-spacing: .08em; text-transform: uppercase; color: #5eead4; }
.step i { font-style: normal; width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center;
  background: linear-gradient(135deg, #14b8a6, #f59e0b); color: #fff; letter-spacing: 0; font-size: 14px; }
h1 { font-size: 38px; line-height: 1.1; letter-spacing: -.02em; margin-top: 8px; }
.sub { font-size: 19px; color: #c5dcd8; margin-top: 8px; }
.frame { position: absolute; left: 40px; right: 40px; top: 160px; bottom: 28px; border-radius: 14px;
  overflow: hidden; box-shadow: 0 24px 60px rgba(0,0,0,.5), 0 0 0 1px rgba(94,234,212,.2); }
.bar { height: 30px; background: #18262c; display: flex; align-items: center; gap: 7px; padding: 0 12px; }
.bar span { width: 11px; height: 11px; border-radius: 50%; background: #ff5f57; }
.bar span:nth-child(2) { background: #febc2e; } .bar span:nth-child(3) { background: #28c840; }
.bar em { margin-left: 14px; font-style: normal; font-size: 12px; color: #8fa8a4; }
.term { position: absolute; top: 30px; left: 0; right: 0; bottom: 0; background: #0a171c; color: #dcefeb;
  font: 16px/1.55 "SF Mono", Menlo, monospace; padding: 18px 26px; white-space: pre-wrap; }
.p { color: #5eead4; } .h { color: #fff; font-weight: 700; } .c { color: #7f9a95; }
.ok { color: #4ade80; font-weight: 700; } .no { color: #fb7185; font-weight: 700; } .f { color: #fbbf24; }
.note { position: absolute; bottom: 36px; right: 56px; font-size: 12px; color: #7f9a95; }
.center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center;
  justify-content: center; text-align: center; padding: 0 110px; }
.center h1 { font-size: 66px; }
.center .sub { font-size: 25px; margin-top: 18px; max-width: 960px; line-height: 1.4; }
.chips { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; margin-top: 32px; }
.chips span { border: 1px solid rgba(94,234,212,.45); color: #ccfbf1; border-radius: 999px; padding: 7px 16px;
  font-size: 16px; background: rgba(20,184,166,.13); }
.big { width: 96px; height: 96px; border-radius: 26px; margin-bottom: 26px; }
.big::after { width: 28px; height: 46px; border-width: 0 9px 9px 0; }
.cmd { margin-top: 30px; font: 22px "SF Mono", Menlo, monospace; background: rgba(0,0,0,.35);
  border: 1px solid rgba(255,255,255,.15); border-radius: 12px; padding: 14px 26px; color: #5eead4; }
.flow { position: absolute; left: 40px; right: 40px; top: 170px; bottom: 44px; display: grid; gap: 18px 16px;
  grid-template-columns: repeat(4, 1fr); grid-auto-rows: 1fr; }
.box { position: relative; border-radius: 16px; padding: 24px 22px 20px;
  background: linear-gradient(160deg, rgba(20,184,166,.22), rgba(6,20,26,.72));
  border: 1px solid rgba(94,234,212,.3); box-shadow: 0 14px 34px rgba(0,0,0,.32); }
.box.warm { background: linear-gradient(160deg, rgba(245,158,11,.26), rgba(6,20,26,.72));
  border-color: rgba(251,191,36,.42); }
.box b { display: block; font-size: 25px; letter-spacing: -.01em; margin-bottom: 10px; }
.box span { font-size: 18.5px; line-height: 1.42; color: #c5dcd8; }
.box em { font-style: normal; font-size: 12px; font-weight: 700; letter-spacing: .08em; color: #5eead4;
  display: block; margin-bottom: 8px; text-transform: uppercase; }
.box.warm em { color: #fbbf24; }
.wide { grid-column: span 2; } .all { grid-column: 1 / -1; }
.cols3 { grid-template-columns: repeat(3, 1fr); top: 190px; bottom: 70px; }
.cols3 .box { display: flex; flex-direction: column; justify-content: center; padding: 28px 28px; }
.cols3 .box b { font-size: 31px; margin-bottom: 14px; }
.cols3 .box span { font-size: 21px; line-height: 1.48; }
.cols3 .box em { font-size: 13.5px; margin-bottom: 12px; }
.state { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 30px; width: 980px; text-align: left; }
.state div { border-radius: 16px; padding: 16px 20px; font-size: 17px; line-height: 1.55;
  background: rgba(20,184,166,.13); border: 1px solid rgba(94,234,212,.3); }
.state div.todo { background: rgba(245,158,11,.14); border-color: rgba(251,191,36,.42); }
.state b { display: block; font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: #5eead4;
  margin-bottom: 6px; }
.state .todo b { color: #fbbf24; }
"""

BRAND = '<div class="brand"><div class="logo"></div><span>hub<b>triage</b></span></div>'

# Kokoro reads these better spelled out. AWS needs its dots: bare it's one word, like "oz", "A W S" comes out
# as the word "a" and then "WS", "ay" as "I", and a last dot ends the sentence there.
PHONETIC = {
    r"\bhubtriage\b": "hub triage",
    r"\bAWS\b": "A.W.S",
    r"\bIAM\b": "I am",
    r"\bLLM\b": "ellellem",
    r"\bMFA\b": "M.F.A",
    r"\bRDP\b": "R D P",
    r"\bSCPs\b": "S C Ps",
}


def page(body: str) -> str:
    return f'<!doctype html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body>{body}</body></html>'


def head(n: int, label: str, title: str, sub: str) -> str:
    return (f'<header><div class="step"><i>{n}</i>{label}</div><h1>{title}</h1>'
            f'<div class="sub">{sub}</div></header>{BRAND}')


def term_slide(n: int, label: str, title: str, sub: str, text: str, note: str = "", size: float = 16) -> str:
    frame = ('<div class="frame"><div class="bar"><span></span><span></span><span></span><em>Terminal</em></div>'
             f'<div class="term" style="font-size:{size}px">{text}</div></div>')
    return page(head(n, label, title, sub) + frame + (f'<div class="note">{note}</div>' if note else ""))


def boxes(items: list[tuple[str, str, str, str]]) -> str:
    """(kicker, title, text, extra classes) for each box."""
    return "".join(
        f'<div class="box {extra}"><em>{kicker}</em><b>{title}</b><span>{text}</span></div>'
        for kicker, title, text, extra in items
    )


def records_text(case: str) -> str:
    """The security group's record, as `hubtriage records` prints it."""
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        cli.main(["records", str(SYNTHETIC / case)])
    blocks = captured.getvalue().split("\n[")
    block = next(b for b in blocks if "IpPermissions.0.FromPort" in b).rstrip()
    lines = block.lstrip("[").splitlines()
    wanted = ("GroupId", "GroupName", "IpPermissions.0.")
    fields = [line for line in lines[1:] if line.strip().startswith(wanted)][:9]
    out = [f'<span class="p">$</span> hubtriage records fixtures/synthetic/{case}', "",
           f'<span class="h">[{html.escape(lines[0])}</span>']
    for line in fields:
        name, _, value = line.strip().partition(" = ")
        out.append(f'  <span class="c">{html.escape(name)}</span> = <span class="f">{html.escape(value)}</span>')
    return "\n".join(out)


def decision_text(case: str) -> str:
    """One case as `hubtriage demo` prints it, from a real run of the gate."""
    found = next(c for c in cases.discover(SYNTHETIC) if c.name == case)
    decision = cases.run(found).result.decision
    out = [f'<span class="p">$</span> hubtriage demo   <span class="c"># {case}</span>', "",
           f'  <span class="h">verdict  {decision.verdict}</span>'
           f'   <span class="c">(model said {decision.model_verdict})</span>']
    if decision.reason:
        out.append(f'  <span class="f">why</span>      {html.escape(decision.reason)}')
    out.append("")
    for outcome in decision.outcomes:
        if outcome.admitted:
            out.append(f'  <span class="ok">ADMIT </span>   {html.escape(outcome.claim.text)}')
        else:
            out.append(f'  <span class="no">REFUSE</span>   {html.escape(outcome.claim.text)}')
            reason = outcome.reason.split("; available:")[0].split(".", 1)[-1]
            out.append(f'           <span class="c">{html.escape(reason)}</span>')
    return "\n".join(out)


def check_iam_text() -> str:
    out = ['<span class="p">$</span> hubtriage check-iam --finding-id &lt;a GuardDuty sample&gt;', ""]
    for line in (HERE / "check-iam.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("ok"):
            mark, rest = line[:4], line[4:]
            out.append(f'<span class="ok">{mark}</span>{html.escape(rest)}')
        else:
            out.append(f'<span class="h">{html.escape(line)}</span>')
    return "\n".join(out)


def slides() -> list[tuple[str, str, str]]:
    return [
        ("01-title", page(
            f'{BRAND}<div class="center"><div class="logo big"></div><h1>hub<span class="p">triage</span></h1>'
            '<div class="sub">Triage AWS Security Hub findings with an LLM that can only say what the AWS APIs '
            'said.</div><div class="chips"><span>GuardDuty</span><span>Security Hub</span><span>EventBridge</span>'
            '<span>SQS</span><span>IAM</span><span>Terraform</span><span>witness</span></div></div>'),
         "A security alert arrives. An LLM can read it in seconds, and misread it just as fast. "
         "hubtriage lets a model triage AWS findings, but it can only say what the AWS APIs said."),
        ("02-flow", page(
            head(1, "The path", "From a finding to a checked verdict", "Each step is a real AWS service or a "
                 "check in the agent.")
            + '<div class="flow">' + boxes([
                ("Detect", "GuardDuty", "Raises a finding in any account.", ""),
                ("Collect", "Security Hub", "Gathers findings in the security account.", ""),
                ("Buffer", "EventBridge to SQS", "A queue, so nothing is lost while the agent is away.", ""),
                ("Ask", "Fixed questions", "The instance, the principal, the CloudTrail events around it.", ""),
                ("Judge", "The model", "A verdict, and claims that cite the records.", "warm"),
                ("Check", "The gate", "Re-reads each cited field and compares it with the claim.", "warm"),
                ("Answer", "Back to Security Hub", "Only what passed the gate goes in the note.", "wide"),
            ]) + "</div>"),
         "GuardDuty raises a finding, and Security Hub collects it. EventBridge puts it on a queue, so nothing "
         "is lost while the agent is away. The agent then asks AWS a fixed set of questions, and each answer "
         "becomes a record."),
        ("03-records", term_slide(
            2, "The evidence", "What the model gets to see", "Every API answer is a record with an id.",
            records_text("port-probe-misread-port"), size=20,
            note="Made-up case: ids and addresses are reserved examples."),
         "This is what the model sees. To claim anything, it has to cite a record, a field, and a value, "
         "copied exactly."),
        ("04-refused", term_slide(
            3, "The gate", "A misread port never reaches the finding", "The gate re-reads the field from the "
            "recorded response.",
            decision_text("port-probe-misread-port"), size=20,
            note="Hand-written answer, written to test the gate. Not a measure of any model."),
         "These test cases are written by hand. In this one, the answer says RDP is open to the world. The "
         "record says port twenty two, so the claim is refused, and it never reaches the finding."),
        ("05-downgraded", term_slide(
            4, "The verdict", "A dismissal built on a misread goes to a person", "Benign has to rest entirely "
            "on evidence.",
            decision_text("root-login-misread"), size=15,
            note="Hand-written answer, written to test the gate. Not a measure of any model."),
         "Here, a root login gets called benign, from a known address, with MFA. Both details are wrong. "
         "The answer wanted to dismiss the alert, and hubtriage sends it to a person instead."),
        ("06-iam", term_slide(
            5, "The limits", "The agent cannot close a finding", "The rule lives in IAM, not only in the code.",
            check_iam_text(), size=19,
            note="One real run against AWS, as the agent's role, on a GuardDuty sample."),
         "The agent can never close a finding, and that rule lives in IAM. This command tried all nine "
         "forbidden writes against real AWS, as the agent. All nine were refused, and the one write it's "
         "allowed went through."),
        ("07-failure", page(
            head(6, "When things go wrong", "Failing out loud", "\"Needs a human\" only helps if a human hears "
                 "about it.")
            + '<div class="flow cols3">' + boxes([
                ("No model answers", "The finding stays open", "Nothing is written or deleted, and the run "
                 "stops, so the other messages keep their retries.", ""),
                ("A message keeps failing", "Parked, then an alarm", "After three tries it moves to a "
                 "dead-letter queue, and an alarm emails you.", "warm"),
                ("A person is needed", "An email", "A true positive or an unsettled finding emails the verdict "
                 "and the title, not the evidence.", "warm"),
            ]) + "</div>"),
         "Failure has to be loud. If no model answers, the finding stays open and the run stops. A message "
         "that keeps failing is parked, and an alarm emails you. So does any finding that needs a person."),
        ("08-org", page(
            head(7, "The organization", "Built in Terraform, in three stages", "A real multi-account AWS "
                 "organization, hub before spokes.")
            + '<div class="flow cols3">' + boxes([
                ("00-org", "Management", "Accounts, budget, delegated admins, centralized root access, and "
                 "SCPs.", ""),
                ("10-security", "Security", "GuardDuty, Security Hub, the organization trail, the queue, "
                 "alerts, and the agent's role.", "warm"),
                ("20-workload", "Workload", "A read-only enrichment role, and nothing else.", ""),
            ]) + "</div>"),
         "All of this runs in a real AWS organization, built in Terraform. SCPs stop member accounts from "
         "switching off security services, and the agent reads other accounts through a read-only role."),
        ("09-end", page(
            f'{BRAND}<div class="center"><div class="logo big"></div><h1>hub<span class="p">triage</span></h1>'
            '<div class="state"><div><b>Proved so far</b>The path, end to end, on GuardDuty samples<br>'
            'The gate, on hand-written cases<br>The IAM limits, against real AWS</div>'
            '<div class="todo"><b>Not yet</b>Real findings<br>The verdict email, on a fresh finding<br>'
            'An accuracy number for any model</div></div>'
            f'<div class="cmd">{REPO}</div></div>'),
         "So far it has run end to end on GuardDuty samples. Real findings, and an accuracy number, come "
         "next. The code is on GitHub."),
    ]


AUDIO = {
    "music": ("music_bed.wav", {"volume": 0.3, "fade_in": 1.0, "fade_out": 3.0, "duck": True, "duck_db": 16}),
    "intro": ("intro_sting.wav", {"volume": 0.75}),
    "outro": ("outro_sting.wav", {"volume": 0.7}),
}


def build(out: Path, music: Path | None = None) -> dict:
    """Write slides/*.html and reel.json into `out`. Without the music files, the reel has the voice only."""
    out = out.expanduser().resolve()
    (out / "slides").mkdir(parents=True, exist_ok=True)
    entries = []
    for name, body, narration in slides():
        (out / "slides" / f"{name}.html").write_text(body, encoding="utf-8")
        entries.append({"html_file": f"slides/{name}.html", "narration": narration, "tail_pad": 1.2})
    entries[0]["tail_pad"] = 1.0
    entries[-1]["tail_pad"] = 1.6
    spec = {"width": 1920, "height": 1080, "fps": 25,
            "tts": {"provider": "mlx", "voice": "af_heart", "phonetic": PHONETIC}}
    where = (music or out).expanduser().resolve()
    missing = [name for name, _ in AUDIO.values() if not (where / name).is_file()]
    if music and missing:
        raise SystemExit(f"{where} has no {', '.join(missing)}: `slidecast compose -o {where}` makes them")
    if not missing:
        for key, (name, options) in AUDIO.items():
            spec[key] = {"file": str(where / name), **options}
    spec.update({"lead_in": 1.8, "loudness": -16, "slides": entries})
    (out / "reel.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    return spec


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", nargs="?", type=Path, default=OUT, help=f"output folder (default: {OUT})")
    ap.add_argument("--music", type=Path, metavar="DIR", help="folder with the music bed and the stings")
    args = ap.parse_args()
    spec = build(args.out, args.music)
    print(f"Wrote {len(spec['slides'])} slides and {args.out / 'reel.json'}"
          + ("" if "music" in spec else " (no music: voice only)"))


if __name__ == "__main__":
    main()
