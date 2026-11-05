"""Where the verdict comes from. A judge is any `prompt -> text` callable.

Four live backends and one recorded one:

- `openai_compatible` - any server speaking /v1/chat/completions (vLLM, mlx,
  Ollama's shim). This is how the local hosts are reached.
- `bedrock` - Amazon Bedrock's Converse API, through boto3. Credentials come
  from the same chain as every other AWS call, so the agent's role needs
  bedrock:InvokeModel on the one model it uses and nothing broader.
- `claude_api` - Anthropic's API, billed per use. Public: made-up cases only.
- `agy` - the Antigravity CLI on a subscription login. Public: made-up cases only.
- `recorded` - a saved answer, which is what the demo and CI run on.

`failover` tries judges in order and returns the first answer, so "local hosts,
then Bedrock" is `failover(host_a, host_b, bedrock)`. It does not retry a judge
that answered badly - a malformed answer is the gate's problem, not a transport
failure - only one that did not answer.

A live finding carries real account ids, and its lookups can carry a person's
name and address from CloudTrail, so it never goes to a public backend. `from_env`
refuses those unless the caller says the data is made up.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Callable

Judge = Callable[[str], str]

MAX_TOKENS = 2048
# The hosted models think before they answer, and that counts against the limit.
THINKING_MAX_TOKENS = 16000

CLAUDE_MODEL = "claude-opus-5-5"
AGY_MODEL = "claude-sonnet-5-5-medium"  # `agy models` lists the ids
# A security finding can trip a safety classifier. This re-runs a declined request
# on Anthropic's recommended fallback model instead of losing the answer.
FALLBACK_BETA = "server-side-fallback-2026-07-01"

PUBLIC_BACKENDS = {"claude", "agy"}


class NoJudgeAnswered(RuntimeError):
    pass


class NoAnswer(RuntimeError):
    """The model stopped without a usable answer, so the next judge should be asked."""


class PublicBackendRefused(ValueError):
    pass


def openai_compatible(base_url: str, model: str, *, timeout: float = 120.0, api_key: str = "") -> Judge:
    url = base_url.rstrip("/") + "/chat/completions"

    def judge(prompt: str) -> str:
        body = json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "max_tokens": MAX_TOKENS,
                "response_format": {"type": "json_object"},
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            doc = json.load(response)
        return doc["choices"][0]["message"]["content"]

    judge.__name__ = f"openai_compatible({base_url})"
    return judge


def bedrock(model_id: str, *, region: str | None = None, session: Any = None) -> Judge:
    def judge(prompt: str) -> str:
        if session is None:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=region)
        else:
            client = session.client("bedrock-runtime", region_name=region)
        # No temperature: current Claude models refuse any sampling setting.
        response = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": THINKING_MAX_TOKENS},
        )
        if response.get("stopReason") in ("max_tokens", "refusal", "guardrail_intervened"):
            raise NoAnswer(f"stopped with {response['stopReason']}")
        # Reasoning comes back as its own block ahead of the text.
        blocks = response["output"]["message"]["content"]
        return "".join(block["text"] for block in blocks if "text" in block)

    judge.__name__ = f"bedrock({model_id})"
    return judge


def _keychain_secret(item: str) -> str:
    """One secret from the macOS Keychain. The value never reaches an error message."""
    found = subprocess.run(
        ["security", "find-generic-password", "-s", item, "-w"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if found.returncode != 0:
        raise NoAnswer(f"no keychain item {item!r}")
    return found.stdout.strip()


def claude_api(model: str = CLAUDE_MODEL, *, keychain: str = "", client: Any = None) -> Judge:
    """Without a keychain item, the SDK finds its credentials the usual way."""

    def judge(prompt: str) -> str:
        api = client
        if api is None:
            import anthropic

            api = anthropic.Anthropic(api_key=_keychain_secret(keychain) if keychain else None)
        response = api.beta.messages.create(
            model=model,
            max_tokens=THINKING_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
        if response.stop_reason in ("max_tokens", "refusal"):
            raise NoAnswer(f"stopped with {response.stop_reason}")
        return "".join(block.text for block in response.content if block.type == "text")

    judge.__name__ = f"claude_api({model})"
    return judge


def agy(model: str = AGY_MODEL, *, timeout: float = 180.0, run: Callable = subprocess.run) -> Judge:
    """In an empty directory and sandboxed, so the CLI's own tools find nothing to read."""

    def judge(prompt: str) -> str:
        executable = shutil.which("agy") or "agy"
        args = [
            executable, "-p", prompt, "--output-format", "json", "--model", model, "--sandbox",
            "--disable-slash-commands", "--print-timeout", f"{max(int(timeout) - 10, 10)}s",
        ]
        with tempfile.TemporaryDirectory(prefix="agy-") as empty:
            done = run(
                args, cwd=empty, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=timeout,
            )
        if done.returncode != 0:
            raise NoAnswer(f"agy exited {done.returncode}: {(done.stderr or done.stdout)[:300]}")
        reply = json.loads(done.stdout)
        if reply.get("status") != "SUCCESS":
            raise NoAnswer(f"agy status {reply.get('status')}: {str(reply.get('error'))[:300]}")
        return str(reply["response"])

    judge.__name__ = f"agy({model})"
    return judge


def recorded(path: str | Path) -> Judge:
    text = Path(path).read_text(encoding="utf-8")

    def judge(prompt: str) -> str:
        return text

    judge.__name__ = f"recorded({Path(path).name})"
    return judge


def failover(*judges: Judge) -> Judge:
    if not judges:
        raise ValueError("failover needs at least one judge")

    def judge(prompt: str) -> str:
        errors = []
        for candidate in judges:
            try:
                return candidate(prompt)
            # Connection refused, timeouts, HTTP errors, botocore errors: any of
            # them means this judge did not answer, so the next one is asked.
            except Exception as e:  # noqa: BLE001
                errors.append(f"{candidate.__name__}: {type(e).__name__}: {e}")
        raise NoJudgeAnswered("; ".join(errors))

    judge.__name__ = "failover(" + ", ".join(j.__name__ for j in judges) + ")"
    return judge


def from_env(env: dict | None = None, *, allow_public: bool = False) -> Judge:
    """Build the judge chain from HUBTRIAGE_* variables.

    HUBTRIAGE_LLM        order of backends, e.g. "local,bedrock" (the default) or "bedrock"
    HUBTRIAGE_LOCAL_URLS comma-separated OpenAI-compatible base URLs, tried in order
    HUBTRIAGE_LOCAL_MODEL model name the local servers serve
    HUBTRIAGE_BEDROCK_MODEL Bedrock model or inference-profile id
    HUBTRIAGE_CLAUDE_MODEL  for the claude backend; made-up cases only
    HUBTRIAGE_CLAUDE_KEYCHAIN macOS Keychain item holding its API key
    HUBTRIAGE_AGY_MODEL     for the agy backend; made-up cases only
    """
    env = os.environ if env is None else env
    chain: list[Judge] = []
    for backend in [b.strip() for b in env.get("HUBTRIAGE_LLM", "local,bedrock").split(",") if b.strip()]:
        if backend in PUBLIC_BACKENDS and not allow_public:
            raise PublicBackendRefused(
                f"{backend} is a public API, so it only runs on the made-up cases in fixtures/;"
                " use local or bedrock here"
            )
        if backend == "claude":
            chain.append(
                claude_api(
                    env.get("HUBTRIAGE_CLAUDE_MODEL", CLAUDE_MODEL),
                    keychain=env.get("HUBTRIAGE_CLAUDE_KEYCHAIN", ""),
                )
            )
        elif backend == "agy":
            chain.append(agy(env.get("HUBTRIAGE_AGY_MODEL", AGY_MODEL)))
        elif backend == "local":
            model = env.get("HUBTRIAGE_LOCAL_MODEL", "")
            for url in [u.strip() for u in env.get("HUBTRIAGE_LOCAL_URLS", "").split(",") if u.strip()]:
                chain.append(openai_compatible(url, model))
        elif backend == "bedrock":
            if env.get("HUBTRIAGE_BEDROCK_MODEL"):
                chain.append(bedrock(env["HUBTRIAGE_BEDROCK_MODEL"], region=env.get("AWS_REGION")))
        else:
            raise ValueError(f"unknown backend {backend!r}; known: local, bedrock, claude, agy")
    if not chain:
        raise ValueError(
            "no judge configured: set HUBTRIAGE_LOCAL_URLS and HUBTRIAGE_LOCAL_MODEL,"
            " or HUBTRIAGE_BEDROCK_MODEL"
        )
    return failover(*chain)
