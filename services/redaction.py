"""
Pseudonymization for model calls.

Bedrock's data handling is strong: no logging, no training, in-region,
PrivateLink available. This layer exists for the people who need more than
a vendor policy. With --redact, every account ID, principal ARN, IP address,
bucket name, and role name is replaced with a stable token before the
package is serialized for the model. The model reasons about PRINCIPAL-3
and ACCOUNT-1. The mapping stays in process memory and is applied in
reverse to whatever comes back.

Consistency matters more than secrecy here: the same real value always
maps to the same token within a run, so the model can still correlate
"PRINCIPAL-3 logged in, then PRINCIPAL-3 created a key." What it can't do
is know who PRINCIPAL-3 is.

What is NOT redacted, on purpose: event names, timestamps, regions, ATT&CK
IDs, error codes, and user agents. Those carry the investigative signal
and don't identify a customer.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any, Dict, Tuple

# Order matters: longer/more specific patterns first so an ARN is tokenized
# as a whole before its embedded account ID is.
ARN_RE = re.compile(r"arn:aws(?:-us-gov|-cn)?:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"',]+")
ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# access key IDs: AKIA (long-term) / ASIA (temp), 16 chars after prefix
AKID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
# S3 bucket names in the common shapes we produce
BUCKET_RE = re.compile(r"(bucket[\"' :=]{1,3})([a-z0-9][a-z0-9.-]{2,62})", re.IGNORECASE)


class Pseudonymizer:
    """Stable, reversible token substitution for identifying values."""

    def __init__(self):
        self._fwd: Dict[str, str] = {}
        self._rev: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}
        # bare name -> token, harvested from ARNs during the first pass
        self._bare_names: Dict[str, str] = {}

    # ------------------------------------------------------------------

    def redact(self, obj: Any) -> Any:
        """Return a deep copy with identifiers replaced by tokens.

        Two passes. The first tokenizes ARNs, account IDs, IPs, keys, and
        buckets. While doing that it harvests the bare names embedded in
        ARNs (the "svc-deploy" in arn:...:user/svc-deploy). The second
        pass tokenizes those names wherever they appear on their own,
        since CloudTrail puts userName in its own field and GuardDuty
        findings mention principals by short name in free text.
        """
        self._harvest_names(obj)
        first = self._walk(copy.deepcopy(obj), self._redact_str)
        if self._bare_names:
            return self._walk(first, self._redact_bare_names)
        return first

    # field names that hold a bare principal name in CloudTrail/GuardDuty output
    NAME_FIELDS = ("userName", "UserName", "roleName", "RoleName", "principalName",
                   "sessionName", "user_name", "role_name",
                   "trailName", "TrailName", "name", "Name", "functionName", "FunctionName")

    def _harvest_names(self, obj: Any) -> None:
        """Walk the structure and register bare names from known fields.

        GuardDuty findings say "IAM user svc-deploy-prod" in free text and
        never include the ARN. Without this pre-pass there is nothing to
        map the bare name against and it leaks.
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in self.NAME_FIELDS and isinstance(v, str) and len(v) >= 3:
                    if v not in self._bare_names:
                        kl = k.lower()
                        kind = ("ROLE" if "role" in kl else "TRAIL" if "trail" in kl
                                else "FUNCTION" if "function" in kl
                                else "RESOURCE" if kl == "name" else "PRINCIPAL")
                        tok = self._token(kind, v)
                        self._bare_names[v] = tok
                self._harvest_names(v)
        elif isinstance(obj, list):
            for v in obj:
                self._harvest_names(v)

    def restore(self, obj: Any) -> Any:
        """Reverse the mapping on a model response."""
        return self._walk(copy.deepcopy(obj), self._restore_str)

    @property
    def mapping_size(self) -> int:
        return len(self._fwd)

    def mapping_summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for tok in self._fwd.values():
            kind = tok.rsplit("-", 1)[0]
            out[kind] = out.get(kind, 0) + 1
        return out

    # ------------------------------------------------------------------

    def _token(self, kind: str, real: str) -> str:
        if real in self._fwd:
            return self._fwd[real]
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        tok = f"{kind}-{n}"
        self._fwd[real] = tok
        self._rev[tok] = real
        # harvest the trailing name from principal/role ARNs so the bare
        # form gets the same token elsewhere
        if kind in ("PRINCIPAL", "ROLE") and "/" in real:
            name = real.rsplit("/", 1)[-1]
            if ":assumed-role/" in real:
                name = real.split(":assumed-role/")[-1].split("/")[0]
            if len(name) >= 3:
                if name in self._bare_names:
                    # name was harvested first; make the ARN share its token
                    existing = self._bare_names[name]
                    self._fwd[real] = existing
                    self._rev[existing] = real  # ARN is the better restore target
                    self._counters[kind] -= 1
                    del self._rev[tok]
                    return existing
                self._bare_names[name] = tok
        return tok

    def _redact_bare_names(self, s: str) -> str:
        if not s or not isinstance(s, str):
            return s
        # longest names first so "svc-deploy-prod" beats "svc-deploy"
        for name in sorted(self._bare_names, key=len, reverse=True):
            if name in s:
                # boundary excludes only alphanumerics: "svc-deploy" inside
                # "svc-deploy-session" is still the same principal and must match
                s = re.sub(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])",
                           self._bare_names[name], s)
        return s

    def _redact_str(self, s: str) -> str:
        if not s or not isinstance(s, str):
            return s
        # ARNs first (they contain account IDs and names)
        s = ARN_RE.sub(lambda m: self._token(_arn_kind(m.group(0)), m.group(0)), s)
        s = AKID_RE.sub(lambda m: self._token("KEY", m.group(0)), s)
        s = ACCOUNT_RE.sub(lambda m: self._token("ACCOUNT", m.group(0)), s)
        s = IPV4_RE.sub(self._ip_sub, s)
        s = BUCKET_RE.sub(lambda m: m.group(1) + self._token("BUCKET", m.group(2)), s)
        return s

    def _ip_sub(self, m) -> str:
        raw = m.group(0)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        # keep the private/public distinction visible to the model since it
        # affects how an IP should be interpreted, without revealing the IP
        kind = "IP-PRIVATE" if ip.is_private else "IP"
        return self._token(kind, raw)

    def _restore_str(self, s: str) -> str:
        if not s or not isinstance(s, str) or not self._rev:
            return s
        # replace longest tokens first so IP-PRIVATE-1 isn't clobbered by IP-1
        for tok in sorted(self._rev, key=len, reverse=True):
            if tok in s:
                s = s.replace(tok, self._rev[tok])
        return s

    def _walk(self, obj: Any, fn) -> Any:
        if isinstance(obj, str):
            return fn(obj)
        if isinstance(obj, dict):
            return {fn(k) if isinstance(k, str) else k: self._walk(v, fn) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(v, fn) for v in obj]
        return obj


def _arn_kind(arn: str) -> str:
    if ":user/" in arn:
        return "PRINCIPAL"
    if ":role/" in arn or ":assumed-role/" in arn:
        return "ROLE"
    if ":s3:::" in arn:
        return "BUCKET"
    if ":function:" in arn:
        return "FUNCTION"
    return "RESOURCE"
