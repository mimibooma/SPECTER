"""
Multi-account session broker.

SPECTER runs from a central security tooling account and reaches member
accounts by assuming a consistently-named role in each. This module owns
that access pattern and nothing else.

Design assumptions (documented in docs/PHASE02.md):

  1. SPECTER executes in a delegated security/audit account, not in the
     accounts under investigation. This follows the AWS security tooling
     account pattern.
  2. Every in-scope member account carries a read-only IR role with the
     same name (default: SPECTERForensicsReadOnly). A consistent name is
     what makes fan-out tractable; per-account role names are supported
     via explicit overrides but are the exception.
  3. Credentials are short-lived and refreshed on expiry. Nothing is
     written to disk.

Thread safety: botocore clients are not safe to share across threads.
This broker hands out one Session per (account, region) and callers are
expected to build their own clients from it inside their own thread.
The credential cache itself is lock-protected.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover - allows import in test environments
    boto3 = None
    BotoConfig = None

    class ClientError(Exception):
        """Fallback so type references resolve without botocore installed."""


log = logging.getLogger(__name__)

DEFAULT_ROLE_NAME = "SPECTERForensicsReadOnly"
DEFAULT_SESSION_NAME = "specter-ir"
CREDENTIAL_REFRESH_MARGIN = timedelta(minutes=5)

# Retry/backoff tuned for wide fan-out. Adaptive mode makes botocore
# back off on its own when the account starts throttling us, which is the
# realistic failure mode when hitting 50+ accounts at once.
DEFAULT_BOTO_CONFIG = dict(
    retries={"max_attempts": 8, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    max_pool_connections=32,
)


@dataclass
class AccountTarget:
    """One account SPECTER has been asked to look at."""

    account_id: str
    name: str = ""
    role_name: str = DEFAULT_ROLE_NAME
    regions: List[str] = field(default_factory=list)
    external_id: Optional[str] = None

    @property
    def role_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"

    def gov_role_arn(self) -> str:
        return f"arn:aws-us-gov:iam::{self.account_id}:role/{self.role_name}"


@dataclass
class AccessResult:
    """Outcome of trying to reach one account. Failures are data, not exceptions."""

    account_id: str
    reachable: bool
    error: Optional[str] = None
    error_kind: Optional[str] = None  # access_denied | not_found | throttled | other


class AccountBroker:
    """Issues assumed-role sessions for member accounts."""

    def __init__(
        self,
        partition: str = "aws",
        session_name: str = DEFAULT_SESSION_NAME,
        duration_seconds: int = 3600,
        base_session=None,
    ):
        self.partition = partition
        self.session_name = session_name
        self.duration_seconds = duration_seconds
        self._base_session = base_session or (boto3.Session() if boto3 else None)
        self._cache: Dict[str, dict] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Account discovery
    # ------------------------------------------------------------------

    def discover_accounts(
        self,
        role_name: str = DEFAULT_ROLE_NAME,
        include_suspended: bool = False,
    ) -> List[AccountTarget]:
        """Enumerate accounts via AWS Organizations.

        Requires organizations:ListAccounts in the calling account. If the
        caller is not in an Organization, or lacks permission, this returns
        an empty list and the caller is expected to fall back to an explicit
        account list. That fallback is deliberate: many IR engagements run
        against accounts the responder does not own.
        """
        if not self._base_session:
            return []

        targets: List[AccountTarget] = []
        try:
            org = self._base_session.client("organizations", config=self._boto_config())
            paginator = org.get_paginator("list_accounts")
            for page in paginator.paginate():
                for acct in page.get("Accounts", []):
                    status = acct.get("Status", "ACTIVE")
                    if status != "ACTIVE" and not include_suspended:
                        continue
                    targets.append(
                        AccountTarget(
                            account_id=acct["Id"],
                            name=acct.get("Name", ""),
                            role_name=role_name,
                        )
                    )
        except ClientError as exc:
            log.warning(
                "Organizations discovery unavailable (%s). "
                "Supply accounts explicitly instead.",
                _error_code(exc),
            )
            return []

        log.info("Discovered %d active accounts via Organizations", len(targets))
        return targets

    # ------------------------------------------------------------------
    # Session issuance
    # ------------------------------------------------------------------

    def session_for(self, target: AccountTarget, region: Optional[str] = None):
        """Return a boto3 Session with assumed-role credentials for a target.

        Raises ClientError on failure. Callers doing fan-out should prefer
        probe() which converts failures into data.
        """
        creds = self._credentials_for(target)
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )

    def probe(self, target: AccountTarget) -> AccessResult:
        """Check reachability without raising.

        Used by the landscape mapper to build an candid picture of which
        accounts are actually in scope before any collection begins. An
        account SPECTER cannot reach is a finding, not a crash.
        """
        try:
            self._credentials_for(target)
            return AccessResult(account_id=target.account_id, reachable=True)
        except Exception as exc:  # noqa: BLE001 - broad on purpose, we want every failure as data
            code = _error_code(exc)
            kind = {
                "AccessDenied": "access_denied",
                "AccessDeniedException": "access_denied",
                "NoSuchEntity": "not_found",
                "Throttling": "throttled",
                "ThrottlingException": "throttled",
            }.get(code, "other")
            return AccessResult(
                account_id=target.account_id,
                reachable=False,
                error=str(exc),
                error_kind=kind,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _credentials_for(self, target: AccountTarget) -> dict:
        key = f"{target.account_id}:{target.role_name}"
        now = datetime.now(timezone.utc)

        with self._lock:
            cached = self._cache.get(key)
            if cached and cached["Expiration"] - CREDENTIAL_REFRESH_MARGIN > now:
                return cached

        arn = (
            target.gov_role_arn()
            if self.partition == "aws-us-gov"
            else target.role_arn
        )
        sts = self._base_session.client("sts", config=self._boto_config())

        kwargs = dict(
            RoleArn=arn,
            RoleSessionName=self.session_name,
            DurationSeconds=self.duration_seconds,
        )
        if target.external_id:
            kwargs["ExternalId"] = target.external_id

        resp = sts.assume_role(**kwargs)
        creds = resp["Credentials"]

        with self._lock:
            self._cache[key] = creds
        return creds

    def _boto_config(self):
        if BotoConfig is None:
            return None
        return BotoConfig(**DEFAULT_BOTO_CONFIG)


def _error_code(exc: Exception) -> str:
    """Best-effort extraction of an AWS error code from an exception."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code", "Unknown")
    return type(exc).__name__
