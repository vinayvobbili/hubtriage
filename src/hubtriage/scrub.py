"""Turn a case recorded from a real account into one that is safe to publish and to send anywhere.

A GuardDuty sample finding is made up, but it lands in a real account, and the questions hubtriage
asks about it are answered by that account: its id is in every ARN, and the root sample reads the
real root user's CloudTrail history, with the address and browser it signed in from. So a recorded
case is a fake finding with real answers.

Scrubbing replaces every identifier that points back at the organization with a placeholder, the
same one in every file of the case, so the cassette's index still matches the calls the plan makes
and every claim still binds: account and organization ids, GuardDuty detector and finding ids,
access key and principal ids, IAM Identity Center role suffixes, IP addresses outside the
documentation ranges, and email addresses. What is left is AWS's real answer structure.

`check` then refuses the output if anything of those shapes is still there. Names are the one
thing no pattern finds (a user name, a session name); run the repository's privacy audit on the
output as well, and read it, before it goes anywhere.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

# The accounts AWS's own documentation uses; anything else with twelve digits is real.
ACCOUNTS = ["111122223333", "444455556666", "777788889999", "123456789012", "210987654321"]

ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
ORG = re.compile(r"\bo-[a-z0-9]{10,32}\b")
HEX32 = re.compile(r"(?<![0-9a-zA-Z])[0-9a-f]{32}(?![0-9a-zA-Z])")
KEY = re.compile(r"\b(AKIA|ASIA|AIDA|AROA|AGPA|ANPA|AIPA|ANVA|ABIA|ACCA)[A-Z0-9]{12,20}\b")
SSO = re.compile(r"\b(AWSReservedSSO_[A-Za-z0-9+=,.@-]+?)_[0-9a-f]{16}\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
V4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
V6 = re.compile(r"(?<![\w:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){3,7}(?![\w:])")


class ScrubLeft(ValueError):
    """Something that looks like a real identifier survived the scrub."""


def _routable(text: str) -> bool:
    """An address someone could be found at. Private VPC ranges, 0.0.0.0 and the documentation
    ranges are not, and replacing a security group's 10.0.0.0/16 would change what the group means."""
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False  # 300.1.2.3, a version string


@dataclass
class Scrubber:
    """One mapping per kind of identifier, shared by every file of a case.

    `names` are the ones no pattern can find - a sign-in name, a person's name in a session -
    given by whoever runs the scrub, never stored. Each is replaced wherever it appears, in
    any case, longest first so a full name goes before a part of it.
    """

    names: list[str] = field(default_factory=list)
    seen: dict[str, dict[str, str]] = field(default_factory=dict)

    def _swap(self, kind: str, real: str, make) -> str:
        mapping = self.seen.setdefault(kind, {})
        if real not in mapping:
            mapping[real] = make(len(mapping))
        return mapping[real]

    def text(self, text: str) -> str:
        def account(m):
            if m.group() in ACCOUNTS:
                return m.group()
            return self._swap("account", m.group(),
                              lambda n: ACCOUNTS[n] if n < len(ACCOUNTS) else f"99998888{n:04d}")

        def v4(m):
            if not _routable(m.group()):
                return m.group()
            return self._swap("ipv4", m.group(), lambda n: f"203.0.113.{n % 254 + 1}")

        def v6(m):
            if not _routable(m.group()):
                return m.group()
            return self._swap("ipv6", m.group(), lambda n: f"2001:db8::{n + 1:x}")

        def email(m):
            if m.group().split("@")[1].split(".")[0] == "example":
                return m.group()
            return self._swap("email", m.group(), lambda n: f"person{n + 1}@example.com")

        for name in sorted({n for n in self.names if n}, key=len, reverse=True):
            text = re.sub(re.escape(name), lambda m, name=name: self._swap(
                "name", name.lower(), lambda n: f"person{n + 1}"), text, flags=re.IGNORECASE)
        text = SSO.sub(lambda m: self._swap("sso", m.group(), lambda n: f"{m.group(1)}_{n:016x}"), text)
        text = KEY.sub(lambda m: self._swap("key", m.group(), lambda n: f"{m.group(1)}-EXAMPLE-{n + 1}"), text)
        text = ORG.sub(lambda m: self._swap("org", m.group(), lambda n: f"o-exampleorg{n + 1:02d}"), text)
        text = HEX32.sub(lambda m: self._swap("hex32", m.group(), lambda n: f"example{n:025d}"), text)
        text = EMAIL.sub(email, text)
        text = V6.sub(v6, text)
        text = V4.sub(v4, text)
        return ACCOUNT.sub(account, text)


def leftovers(text: str, names: list[str] | None = None) -> list[str]:
    """What still looks real. Empty for a clean case."""
    found = [m.group() for n in names or [] if n for m in re.finditer(re.escape(n), text, re.IGNORECASE)]
    found += [m.group() for m in ACCOUNT.finditer(text) if m.group() not in ACCOUNTS]
    found += [m.group() for m in KEY.finditer(text)]
    found += [m.group() for m in ORG.finditer(text) if not m.group().startswith("o-exampleorg")]
    found += [m.group() for m in HEX32.finditer(text)]
    # Placeholders count up from zero; a real suffix is random and never starts with ten zeros.
    found += [m.group() for m in SSO.finditer(text) if not m.group()[-16:].startswith("0" * 10)]
    found += [m.group() for m in EMAIL.finditer(text) if m.group().split("@")[1].split(".")[0] != "example"]
    found += [m.group() for m in V4.finditer(text) if _routable(m.group())]
    found += [m.group() for m in V6.finditer(text) if _routable(m.group())]
    return found


def scrub_case(source: str | Path, out: str | Path, names: list[str] | None = None) -> dict[str, int]:
    """Copy a recorded case to `out` with every identifier replaced. Returns how many of each kind.

    Raises ScrubLeft, and leaves nothing at `out`, if the result still has anything of those shapes.
    """
    source, out = Path(source), Path(out)
    scrubber = Scrubber(names=list(names or []))
    files = sorted(p for p in source.rglob("*.json") if p.is_file())
    scrubbed = {p.relative_to(source): scrubber.text(p.read_text(encoding="utf-8")) for p in files}
    left = sorted({hit for text in scrubbed.values() for hit in leftovers(text, names)})
    if left:
        raise ScrubLeft(f"still in the scrubbed case: {', '.join(left[:10])}")
    shutil.rmtree(out, ignore_errors=True)
    for relative, text in scrubbed.items():
        if relative.name == "model_output.json":
            continue  # an answer about the real records; the scrubbed case gets its own
        (out / relative).parent.mkdir(parents=True, exist_ok=True)
        (out / relative).write_text(text, encoding="utf-8")
    return {kind: len(mapping) for kind, mapping in scrubber.seen.items()}
