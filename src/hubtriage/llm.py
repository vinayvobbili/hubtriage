"""Where the verdict comes from. A judge is any `prompt -> text` callable.

Two live backends and one recorded one:

- `openai_compatible` - any server speaking /v1/chat/completions (vLLM, mlx,
  Ollama's shim). This is how the local hosts are reached.
- `bedrock` - Amazon Bedrock's Converse API, through boto3. Credentials come
  from the same chain as every other AWS call, so the agent's role needs
  bedrock:InvokeModel on the one model it uses and nothing broader.
- `recorded` - a saved answer, which is what the demo and CI run on.

`failover` tries judges in order and returns the first answer, so "local hosts,
then Bedrock" is `failover(host_a, host_b, bedrock)`. It does not retry a judge
that answered badly - a malformed answer is the gate's problem, not a transport
failure - only one that did not answer.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Callable

Judge = Callable[[str], str]

MAX_TOKENS = 2048


class NoJudgeAnswered(RuntimeError):
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
        response = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"temperature": 0, "maxTokens": MAX_TOKENS},
        )
        return response["output"]["message"]["content"][0]["text"]

    judge.__name__ = f"bedrock({model_id})"
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


def from_env(env: dict | None = None) -> Judge:
    """Build the judge chain from HUBTRIAGE_* variables.

    HUBTRIAGE_LLM        order of backends, e.g. "local,bedrock" (the default) or "bedrock"
    HUBTRIAGE_LOCAL_URLS comma-separated OpenAI-compatible base URLs, tried in order
    HUBTRIAGE_LOCAL_MODEL model name the local servers serve
    HUBTRIAGE_BEDROCK_MODEL Bedrock model or inference-profile id
    """
    env = os.environ if env is None else env
    chain: list[Judge] = []
    for backend in [b.strip() for b in env.get("HUBTRIAGE_LLM", "local,bedrock").split(",") if b.strip()]:
        if backend == "local":
            model = env.get("HUBTRIAGE_LOCAL_MODEL", "")
            for url in [u.strip() for u in env.get("HUBTRIAGE_LOCAL_URLS", "").split(",") if u.strip()]:
                chain.append(openai_compatible(url, model))
        elif backend == "bedrock":
            if env.get("HUBTRIAGE_BEDROCK_MODEL"):
                chain.append(bedrock(env["HUBTRIAGE_BEDROCK_MODEL"], region=env.get("AWS_REGION")))
        else:
            raise ValueError(f"unknown backend {backend!r}; known: local, bedrock")
    if not chain:
        raise ValueError(
            "no judge configured: set HUBTRIAGE_LOCAL_URLS and HUBTRIAGE_LOCAL_MODEL,"
            " or HUBTRIAGE_BEDROCK_MODEL"
        )
    return failover(*chain)
