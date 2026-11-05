# hubtriage

**Triage AWS Security Hub findings with an LLM that can only say what the AWS APIs said.**

[![CI](https://github.com/vinayvobbili/hubtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/vinayvobbili/hubtriage/actions/workflows/ci.yml)

A GuardDuty finding arrives in Security Hub. hubtriage asks AWS a fixed set of questions
about it — the instance and its security groups, the IAM principal and its policies, the
CloudTrail events around it — and shows the answers to a model as records. The model
returns a verdict and the claims it rests on, each claim citing a record and a field.

Every claim then goes through [witness](https://github.com/vinayvobbili/witness)'s gate,
which re-reads the cited field from the recorded API response and compares it with what the
claim says. A claim that does not match is refused. The verdict that reaches Security Hub
is decided by what survived:

| Model says | Gate result | Written back |
|---|---|---|
| true positive | at least one claim admitted | `TRUE_POSITIVE`, admitted claims in the note |
| benign | every claim admitted | `BENIGN_POSITIVE` |
| benign | any claim refused | `UNKNOWN`: needs a human |
| anything | no claim admitted, or unparseable | `UNKNOWN`: needs a human |

The asymmetry is deliberate. A benign verdict closes the loop on an alert, so it has to rest
entirely on evidence; an escalation that also misread one detail is still an escalation.

The agent never closes a finding. It sets workflow to `NOTIFIED` and records its verdict in
the verification state and the note. The IAM policy on its role denies `RESOLVED` and
`SUPPRESSED`, and denies writing any field the product owns, so this rule lives in IAM and
not only in the code.

## Run it

```bash
git clone https://github.com/vinayvobbili/hubtriage && cd hubtriage
pip install -e .
hubtriage demo
```

No AWS account, no credentials, no model. The demo replays recorded API responses and
recorded answers through the real pipeline. Each case declares the verdict it should come
to, and the run exits non-zero if any case lands differently:

```
ok   root-login-misread  expected needs_human
  verdict   needs_human  (model said benign)
  why       benign, but 2 of 3 claim(s) were refused; a dismissal built on a misread record goes to a human
  ADMIT     Root called GetAccountSummary.
  REFUSE    The call came from the known admin address 203.0.113.10.
            f408c90c75fb#0000.CloudTrailEvent.sourceIPAddress: record says '198.51.100.7', claim asserts '203.0.113.10'
  REFUSE    The root session was MFA-authenticated.
            f408c90c75fb#0000.CloudTrailEvent.userIdentity.sessionContext.attributes.mfaAuthenticated: record says 'false', claim asserts 'true'
```

`hubtriage demo -v` also prints each `BatchUpdateFindings` request.

**The cases shipped today are synthetic.** They were written by hand to drive the gate down
each path, and their "model answers" are not a model's (see
[fixtures/synthetic/README.md](fixtures/synthetic/README.md)). They show that the pipeline
works; they say nothing about how accurate any model is. Cases recorded from a real
organization, and accuracy measured against live models, come next.

## Decisions and what failed

- **The model does not choose its lookups.** The questions asked about a finding are a fixed
  plan, because a model that picks its own lookups can also skip the one that would contradict it
  (`src/hubtriage/evidence.py`).
- **A benign verdict needs every claim admitted.** Closing an alert is the expensive direction to
  be wrong in, so one refused claim sends it to a human. A true positive only needs one admitted
  claim.
- **The model's summary is not written back.** The first time this ran, the summary of a refused
  benign verdict repeated both refused claims into the finding's note. The note now carries only
  admitted claims (`src/hubtriage/writeback.py`).
- **The no-close rule is in IAM, not only in code.** The agent's role denies `RESOLVED` and
  `SUPPRESSED` and denies writing fields the product owns, so a bug in the code cannot close a
  finding.
- **Key-shaped placeholders failed.** GitHub secret scanning flagged the AWS documentation
  placeholder in the fixtures as an access key id. They are now `ASIA-EXAMPLE-*`, and a test
  refuses any tracked file with that shape.
- **A network failure is not evidence.** A lookup AWS refused stays in the evidence as a gap the
  model is told about. A lookup that got no answer (no DNS, an expired login, throttling) stops the
  triage and leaves the message on the queue, so it cannot change a verdict or an accuracy number.
- **`terraform validate` passed; the first real apply did not.** Delegated-admin registrations
  conflict when they run in parallel. Delegating to an account whose hub is off switches it on with
  the default standards, so the hub now comes first, without them. Security Hub's `auto_enable`
  skips accounts that already exist, so those are enrolled as members. A delegated administrator
  cannot read back the organization trail it created, because the ARN names the management account,
  so the trail is managed from there.
- **The event can arrive before the finding can be read.** On the first live run a finding was
  still missing from `GetFindings` 54 seconds after its import event, and the re-read treated that
  as an error, which costs one of the message's three receives. It now waits and reads again.
- **The IAM limits are tested against AWS, not assumed.** `hubtriage check-iam` tries every write
  the agent must be refused, as the agent, and then a note it may write. It refuses to run on
  anything but a GuardDuty sample, since a rule that failed would change the finding. All ten
  attempts came out as expected.
- **Not running on real findings yet.** The organization and security account are applied, but the
  agent has not triaged a real finding and the shipped cases are hand-written, so nothing here
  measures how accurate any model is.

## How it fits together

```
GuardDuty -> Security Hub (delegated admin, security account)
                 |  EventBridge: "Security Hub Findings - Imported"
                 v
               SQS (+ dead-letter queue)
                 |
              hubtriage-agent role  -- sts:AssumeRole -->  hubtriage-enrich (read-only, each account)
                 |                                              |
                 |   finding + ec2/iam/cloudtrail answers  <----+   recorded to a cassette
                 v
          witness store (records, hash-chained) -> prompt -> model -> claims -> gate
                 |
          BatchUpdateFindings: note, verification state, NOTIFIED
```

- `src/hubtriage/evidence.py`: the fixed questions each finding raises, and how the answers
  become records. CloudTrail's event bodies arrive as JSON strings, so they are decoded into
  a derived record whose tool call carries the raw response's hash.
- `src/hubtriage/verdict.py`: the schema, the gate call, and the verdict policy.
- `src/hubtriage/writeback.py`: the `BatchUpdateFindings` request. The note carries only
  admitted claims; the model's free-text summary is never written back.
- `src/hubtriage/llm.py`: local OpenAI-compatible hosts with failover between them, and
  Amazon Bedrock as another link in the same chain.
- `terraform/`: the organization, built in stages. See [terraform/README.md](terraform/README.md).

## Models

```bash
export HUBTRIAGE_LLM=local,bedrock                  # order of the failover chain
export HUBTRIAGE_LOCAL_URLS=http://host-a:8000/v1,http://host-b:8000/v1
export HUBTRIAGE_LOCAL_MODEL=<served model name>
export HUBTRIAGE_BEDROCK_MODEL=<model or inference profile id>
hubtriage eval --judge env
```

## Status

- [x] Offline pipeline: evidence → records → verdict → gate → write-back request, with tests
- [x] Terraform stages 00 (organization), 10 (security account) and 20 (workload) applied to a real organization
- [ ] Record GuardDuty sample findings as cases
- [x] SQS consumer (`hubtriage consume`), tested against fakes; not yet run against a real queue
- [ ] Accuracy against live models on recorded cases
- [ ] OCSF reader for the newer Security Hub

## License

MIT
