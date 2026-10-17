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
            bbe695cb273e#0000.CloudTrailEvent.sourceIPAddress: record says '198.51.100.7', claim asserts '203.0.113.10'
  REFUSE    The root session was MFA-authenticated.
            bbe695cb273e#0000.CloudTrailEvent.userIdentity.sessionContext.attributes.mfaAuthenticated: record says 'false', claim asserts 'true'
```

`hubtriage demo -v` also prints each `BatchUpdateFindings` request.

**The cases shipped today are synthetic.** They were written by hand to drive the gate down
each path, and their "model answers" are not a model's (see
[fixtures/synthetic/README.md](fixtures/synthetic/README.md)). They show that the pipeline
works; they say nothing about how accurate any model is. Cases recorded from a real
organization, and accuracy measured against live models, come next.

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
- [x] Terraform stages 00 (organization), 10 (security account), 20 (workload): validated, not yet applied
- [ ] Apply against a real organization; record GuardDuty sample findings as cases
- [ ] SQS consumer
- [ ] Accuracy against live models on recorded cases
- [ ] OCSF reader for the newer Security Hub

## License

MIT
