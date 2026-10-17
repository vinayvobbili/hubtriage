# Synthetic cases

Every case in this directory was written by hand to exercise the gate. The account
ids, instance ids, keys and addresses are the documentation placeholders AWS and the
RFCs reserve for examples (111122223333, 444455556666, ASIA-EXAMPLE-..., 203.0.113.0/24,
198.51.100.0/24). The `model_output.json` files are not a model's answers: they are
written to make the gate admit, refuse or downgrade in a known way.

So nothing measured on these cases is a statement about any model's accuracy. They
prove the pipeline: evidence lands as records, claims bind or are refused, the verdict
policy downgrades what it should, and the write-back request has the right shape.

Cases recorded from a real account live beside this directory and say so in their
`label.json`.
