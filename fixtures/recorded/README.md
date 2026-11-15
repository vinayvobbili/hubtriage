# Recorded cases

Cases recorded from the project's own test account with `hubtriage pull --record-only`, then run
through `hubtriage scrub`: accounts, organization and detector ids, keys, principal ids, emails,
routable addresses and given names are replaced with placeholders, consistently across a case's
files, and scrub refuses its own output if anything that looks real is left. Each case was then read
by hand before it was committed. A test runs the same leftover check on every file here.

Scrubbed, they are made up in the sense that matters: public backends may read them like the
synthetic cases.

- `sample-iamuser-anomalousbehavior`: a GuardDuty sample. It carries ASFF's `Sample` but not
  GuardDuty's own sample field, so it checks that either mark decides it before any lookup or model.
  It has no cassette and no model answer, because nothing is asked.

The six `ec2-` cases are real GuardDuty findings, not samples. Each was scrubbed with `hubtriage scrub`
and read by hand before it was committed, and each keeps the AWS answers recorded for it in `cassette/`.
They have no model answer: a judge reads the cassette and decides.

- `ec2-bitcoin-dns-query-1`, `-2`, `-3`: an instance queried a Bitcoin-related domain name
  (`CryptoCurrency:EC2-BitcoinTool.B!DNS`). Labeled `true_positive`.
- `ec2-instance-group-compromise`: GuardDuty's `AttackSequence:EC2/CompromisedInstanceGroup`.
  Labeled `true_positive`.
- `ec2-ssh-brute-force-1`, `-2`: `UnauthorizedAccess:EC2-SSHBruteForce`. Labeled `needs_human`.
