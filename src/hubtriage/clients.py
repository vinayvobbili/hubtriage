"""How the agent asks AWS a question, live or from a recording.

Every enrichment lookup goes through one method, `call(service, operation,
params, account_id, region)`, and gets back the response as plain JSON. Three
things implement it:

- `AwsClient` asks AWS. Each lookup is made from inside the account it is
  about, through a read-only role the agent assumes there - the finding lives
  in the security account, but the instance, the user and the CloudTrail event
  history live where they happened.
- `Recorder` wraps a live client and writes each response to a cassette.
- `Cassette` answers from a cassette and never touches the network, which is
  what the demo, the evals and CI run on.

A cassette is a directory: `index.json` lists each call (service, operation,
params, account, region) and the file holding its response. The response is
what botocore parsed, with `ResponseMetadata` dropped - it carries request ids
and retry counts that differ on every run and say nothing about the account -
and timestamps written as ISO 8601.

A call AWS refused (AccessDenied, NoSuchEntity) is recorded too, as an `error`
in place of a file, and replays as the same refusal. A refusal is an answer the
model is told about, so a replay without it would not be the run it recorded.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

INDEX = "index.json"


class Client(Protocol):
    def call(
        self, service: str, operation: str, params: dict, *, account_id: str, region: str
    ) -> dict: ...


class CassetteMiss(LookupError):
    pass


class RecordedError(RuntimeError):
    """A refusal AWS gave when the cassette was recorded, raised again on replay."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def describe_error(error: Exception) -> dict:
    response = getattr(error, "response", None)
    code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
    return {"code": code or getattr(error, "code", None) or type(error).__name__, "message": str(error)}


# AWS answered, but about the caller's session or load, not about what was asked.
_NOT_AN_ANSWER = {
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "RequestExpired",
    "RequestLimitExceeded",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "UnrecognizedClientException",
}


def is_unavailable(error: Exception) -> bool:
    """True when a failed call says nothing about the account: no network, no session, throttled.

    AccessDenied or NoSuchEntity is AWS answering, and a claim can rest on that
    gap. A DNS failure or an expired login is not an answer. Kept as evidence, it
    would look like a question AWS could not answer, and could change the verdict
    or the accuracy measured from a recorded case.
    """
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return False
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code") in _NOT_AN_ANSWER
    return isinstance(error, BotoCoreError)


def needs_login(error: BaseException) -> bool:
    """True when the AWS session is missing or its SSO login has expired: sign in and run again."""
    try:
        from botocore import exceptions
    except ImportError:
        return False
    login = (exceptions.NoCredentialsError, exceptions.SSOError, exceptions.SSOTokenLoadError,
             exceptions.TokenRetrievalError, exceptions.UnauthorizedSSOTokenError)
    return isinstance(error, login)


def _iso(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"{type(value).__name__} is not JSON serialisable")


def to_json(response: dict) -> str:
    clean = {k: v for k, v in response.items() if k != "ResponseMetadata"}
    return json.dumps(clean, indent=2, sort_keys=True, default=_iso) + "\n"


def _key(service: str, operation: str, params: dict, account_id: str, region: str) -> str:
    return json.dumps([service, operation, params, account_id, region], sort_keys=True)


class Cassette:
    """Replay recorded responses. A call that was not recorded is an error, not a guess."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        index_path = self.directory / INDEX
        entries = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
        self._entries = {
            _key(e["service"], e["operation"], e["params"], e["account_id"], e["region"]): e
            for e in entries
        }

    def call(
        self, service: str, operation: str, params: dict, *, account_id: str, region: str
    ) -> dict:
        entry = self._entries.get(_key(service, operation, params, account_id, region))
        if entry is None:
            raise CassetteMiss(
                f"{service}:{operation} {json.dumps(params, sort_keys=True)} in {account_id}/{region}"
                f" was not recorded in {self.directory}"
            )
        if "error" in entry:
            raise RecordedError(entry["error"]["code"], entry["error"]["message"])
        return json.loads((self.directory / entry["file"]).read_text(encoding="utf-8"))


class Recorder:
    """Pass calls through to a live client and keep what came back."""

    def __init__(self, client: Client, directory: str | Path):
        self.client = client
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        index_path = self.directory / INDEX
        self._entries = (
            json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
        )

    def call(
        self, service: str, operation: str, params: dict, *, account_id: str, region: str
    ) -> dict:
        entry = {
            "service": service,
            "operation": operation,
            "params": params,
            "account_id": account_id,
            "region": region,
        }
        try:
            response = self.client.call(
                service, operation, params, account_id=account_id, region=region
            )
        except Exception as e:
            # No answer at all is not kept: replaying it would invent a refusal.
            if not is_unavailable(e):
                self._add({**entry, "error": describe_error(e)})
            raise
        text = to_json(response)
        name = f"{len(self._entries):02d}-{service}.{operation}.json"
        (self.directory / name).write_text(text, encoding="utf-8")
        self._add({**entry, "file": name})
        return json.loads(text)

    def _add(self, entry: dict) -> None:
        self._entries.append(entry)
        (self.directory / INDEX).write_text(
            json.dumps(self._entries, indent=2) + "\n", encoding="utf-8"
        )


class AwsClient:
    """Ask AWS, assuming the read-only enrichment role in whichever account a lookup is about.

    The agent's own credentials come from the default chain - on a laptop that is
    an IAM Identity Center session, never an access key - and they cannot read a
    single resource. Every lookup, in the agent's own account too, goes through
    sts:AssumeRole into `arn:aws:iam::<account>:role/<enrich_role>`, which trusts
    exactly one principal and can do nothing but read. One role definition is then
    the whole of what enrichment can touch, in every account.
    """

    def __init__(self, enrich_role: str = "hubtriage-enrich", session: Any = None):
        try:
            import boto3
            from botocore import xform_name
        except ImportError as e:  # pragma: no cover
            raise ImportError("live AWS calls need boto3: pip install 'hubtriage[aws]'") from e
        self._xform = xform_name
        self.session = session or boto3.Session()
        self.enrich_role = enrich_role
        self._sessions: dict[str, Any] = {}

    def _session_for(self, account_id: str) -> Any:
        cached = self._sessions.get(account_id)
        # Role sessions last fifteen minutes; a queue consumer outlives that.
        if cached is None or cached[1] - datetime.now(timezone.utc) < timedelta(minutes=2):
            import boto3

            creds = self.session.client("sts").assume_role(
                RoleArn=f"arn:aws:iam::{account_id}:role/{self.enrich_role}",
                RoleSessionName="hubtriage",
                DurationSeconds=900,
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            self._sessions[account_id] = (session, creds["Expiration"])
        return self._sessions[account_id][0]

    def call(
        self, service: str, operation: str, params: dict, *, account_id: str, region: str
    ) -> dict:
        client = self._session_for(account_id).client(service, region_name=region)
        return getattr(client, self._xform(operation))(**params)
