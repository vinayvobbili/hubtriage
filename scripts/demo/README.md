# Rebuild the demo video

The README's video is made from the hand-written cases in `fixtures/synthetic`. Building it never reaches AWS and
never calls a model. The one exception to "made up" is `check-iam.txt`: the output of one real `hubtriage check-iam`
run against AWS on a GuardDuty sample, which names fields and no account.

```
pip install -e '.[dev]'
pip install 'slidecast[mlx,playwright]'   # renders the video; mlx is Kokoro on Apple Silicon
python -m playwright install chromium
scripts/demo/make-video                   # writes scripts/demo/out/hubtriage-demo.mp4 and demo.gif
```

When hubtriage and slidecast are different installs, point at each:
`PYTHON=.venv/bin/python SLIDECAST=/path/to/venv/bin/slidecast scripts/demo/make-video`, with slidecast's environment
in `VIRTUAL_ENV` for the voice.

- **The story** (slide order, titles, narration) lives in `slides()` in `build.py`.
- **Everything lands in `out/`**, which git ignores. To update the README, copy the video and the GIF to `docs/`.
- **Keep it honest.** The model answers on these slides are hand-written to test the gate, so the video doesn't quote
  them as anything a model did, and it says what isn't proved yet. Update the last slide as that changes.
