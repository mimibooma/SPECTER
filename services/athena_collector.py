"""
Athena collection backend for estate-scale evidence gathering.

LookupEvents is fine for a targeted window in a handful of accounts. It
falls apart across a large estate: one attribute filter per call, hard
rate limits, and no way to push event-name filtering server-side. When
the trail already lands in S3 (it always does), the right tool is SQL.

This backend runs the Tier 1-3 reduction (time window, event allowlist,
actor scoping) inside Athena so only the already-filtered rows ever cross
the wire. For a hundred-million-event estate that is the difference
between minutes and never.

Two source shapes are supported:
  - A native Athena table over the CloudTrail S3 bucket (classic).
  - Amazon Security Lake's OCSF tables (the current path since CloudTrail
    Lake closed to new customers on 2026-05-31).

The backend returns the same slimmed event dicts the API collector
produces, so nothing downstream knows or cares which path was used.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

log = logging.getLogger(__name__)

# Poll cadence for async query completion. Athena is not fast; these are
# tuned to avoid hammering the API while keeping interactive latency sane.
POLL_INTERVAL_SECONDS = 1.5
MAX_POLL_SECONDS = 300


@dataclass
class AthenaConfig:
    """Where results live and which table to read."""

    database: str
    table: str
    output_location: str  # s3://bucket/prefix/ for query results
    workgroup: str = "primary"
    source_type: str = "cloudtrail"  # cloudtrail | security_lake
    catalog: str = "AwsDataCatalog"
    # How the CloudTrail table is partitioned. "ymd" expects integer year/month/day
    # columns (the common hand-built table). "timestamp" expects a single string
    # partition like 2026/09/05 (partition projection setups). "none" skips the
    # partition predicate entirely; slow but works on any table.
    partition_scheme: str = "ymd"


class AthenaCollector:
    """Runs reduction as SQL against CloudTrail-in-S3 or Security Lake."""

    def __init__(self, session, config: AthenaConfig):
        self.session = session
        self.config = config
        self._client_cache = None

    @property
    def _client(self):
        """Lazily create the Athena client so query construction can be
        exercised without a live session."""
        if self._client_cache is None:
            if self.session is None:
                raise RuntimeError("AthenaCollector has no session; cannot execute queries")
            self._client_cache = self.session.client("athena")
        return self._client_cache

    def collect(
        self,
        account_ids: List[str],
        regions: List[str],
        start: datetime,
        end: datetime,
        allowed_events: Set[str],
        actors_of_interest: Optional[Set[str]] = None,
        row_cap: int = 20_000,
    ) -> List[dict]:
        """Execute the filtered query and return slimmed event dicts."""
        sql = self._build_query(
            account_ids, regions, start, end,
            allowed_events, actors_of_interest, row_cap,
        )
        log.info("Executing Athena query against %s.%s (source=%s)",
                 self.config.database, self.config.table, self.config.source_type)
        query_id = self._start(sql)
        self._await_completion(query_id)
        return self._fetch_rows(query_id)

    # ------------------------------------------------------------------

    def _build_query(
        self,
        account_ids: List[str],
        regions: List[str],
        start: datetime,
        end: datetime,
        allowed_events: Set[str],
        actors: Optional[Set[str]],
        row_cap: int,
    ) -> str:
        if self.config.source_type == "security_lake":
            return self._security_lake_query(
                account_ids, regions, start, end, allowed_events, actors, row_cap
            )
        return self._cloudtrail_query(
            account_ids, regions, start, end, allowed_events, actors, row_cap
        )

    def _cloudtrail_query(
        self, account_ids, regions, start, end, allowed_events, actors, row_cap
    ) -> str:
        """Query a native Athena table over the CloudTrail S3 bucket.

        Partition pruning on the standard year/month/day columns is what
        keeps this cheap. Without it Athena scans the whole bucket, so the
        date predicates below are essential, not cosmetic.
        """
        events = _sql_in_list(sorted(allowed_events))
        accounts = _sql_in_list(account_ids)
        regions_pred = (
            f"AND awsregion IN ({_sql_in_list(regions)})" if regions else ""
        )
        actor_pred = self._actor_predicate(actors, "useridentity.arn")

        part_pred = _partition_predicate(start, end, self.config.partition_scheme)

        return f"""
SELECT eventtime, eventname, eventsource, awsregion,
       sourceipaddress, useragent, recipientaccountid,
       useridentity.type          AS actor_type,
       useridentity.arn           AS actor_arn,
       useridentity.username      AS actor_username,
       useridentity.sessioncontext.attributes.mfaauthenticated AS mfa,
       errorcode,
       requestparameters
FROM {self.config.database}.{self.config.table}
WHERE {part_pred}
  AND from_iso8601_timestamp(eventtime)
        BETWEEN from_iso8601_timestamp('{_iso(start)}')
        AND from_iso8601_timestamp('{_iso(end)}')
  AND eventname IN ({events})
  AND recipientaccountid IN ({accounts})
  {regions_pred}
  {actor_pred}
ORDER BY eventtime
LIMIT {row_cap}
""".strip()

    def _security_lake_query(
        self, account_ids, regions, start, end, allowed_events, actors, row_cap
    ) -> str:
        """Query Security Lake's OCSF-normalized CloudTrail table.

        OCSF renames nearly everything: eventName becomes api.operation,
        the account moves to cloud.account.uid, the actor to
        actor.user.uid. This mapping is the reason the source_type switch
        exists rather than assuming one schema.
        """
        events = _sql_in_list(sorted(allowed_events))
        accounts = _sql_in_list(account_ids)
        regions_pred = (
            f"AND region IN ({_sql_in_list(regions)})" if regions else ""
        )
        actor_pred = self._actor_predicate(actors, "actor.user.uid")

        return f"""
SELECT time_dt                     AS eventtime,
       api.operation               AS eventname,
       api.service.name            AS eventsource,
       region                      AS awsregion,
       src_endpoint.ip             AS sourceipaddress,
       http_request.user_agent     AS useragent,
       cloud.account.uid           AS recipientaccountid,
       actor.user.type             AS actor_type,
       actor.user.uid              AS actor_arn,
       actor.user.name             AS actor_username,
       mfa                         AS mfa,
       status_code                 AS errorcode
FROM {self.config.database}.{self.config.table}
WHERE eventday BETWEEN '{start.strftime('%Y%m%d')}' AND '{end.strftime('%Y%m%d')}'
  AND time_dt BETWEEN from_iso8601_timestamp('{_iso(start)}')
        AND from_iso8601_timestamp('{_iso(end)}')
  AND api.operation IN ({events})
  AND cloud.account.uid IN ({accounts})
  {regions_pred}
  {actor_pred}
ORDER BY time_dt
LIMIT {row_cap}
""".strip()

    @staticmethod
    def _actor_predicate(actors: Optional[Set[str]], column: str) -> str:
        if not actors:
            return ""
        clauses = " OR ".join(
            f"{column} LIKE '%{_escape(a)}%'" for a in sorted(actors)
        )
        return f"AND ({clauses})"

    # ------------------------------------------------------------------

    def _start(self, sql: str) -> str:
        resp = self._client.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={
                "Database": self.config.database,
                "Catalog": self.config.catalog,
            },
            ResultConfiguration={"OutputLocation": self.config.output_location},
            WorkGroup=self.config.workgroup,
        )
        return resp["QueryExecutionId"]

    def _await_completion(self, query_id: str) -> None:
        waited = 0.0
        while waited < MAX_POLL_SECONDS:
            state = self._client.get_query_execution(
                QueryExecutionId=query_id
            )["QueryExecution"]["Status"]
            status = state["State"]
            if status == "SUCCEEDED":
                return
            if status in ("FAILED", "CANCELLED"):
                reason = state.get("StateChangeReason", "unknown")
                raise RuntimeError(f"Athena query {status}: {reason}")
            time.sleep(POLL_INTERVAL_SECONDS)
            waited += POLL_INTERVAL_SECONDS
        raise RuntimeError(f"Athena query timed out after {MAX_POLL_SECONDS}s")

    def _fetch_rows(self, query_id: str) -> List[dict]:
        """Page results and shape them like slimmed API events."""
        events: List[dict] = []
        paginator = self._client.get_paginator("get_query_results")
        header: Optional[List[str]] = None

        for page in paginator.paginate(QueryExecutionId=query_id):
            rows = page["ResultSet"]["Rows"]
            for i, row in enumerate(rows):
                values = [c.get("VarCharValue", "") for c in row["Data"]]
                if header is None:
                    header = values
                    continue
                record = dict(zip(header, values))
                events.append(self._shape(record))
        return events

    @staticmethod
    def _shape(record: Dict[str, str]) -> dict:
        """Convert a flat Athena row into the collector's event dict shape."""
        out = {
            "eventTime": record.get("eventtime"),
            "eventName": record.get("eventname"),
            "eventSource": record.get("eventsource"),
            "awsRegion": record.get("awsregion"),
            "sourceIPAddress": record.get("sourceipaddress"),
            "userAgent": record.get("useragent"),
            "account": record.get("recipientaccountid"),
            "actor": {
                "type": record.get("actor_type"),
                "arn": record.get("actor_arn"),
                "userName": record.get("actor_username"),
            },
        }
        if record.get("errorcode"):
            out["errorCode"] = record["errorcode"]
        if record.get("mfa"):
            out["mfaAuthenticated"] = record["mfa"]
        if record.get("requestparameters"):
            out["requestParameters"] = record["requestparameters"]
        return {k: v for k, v in out.items() if v not in (None, "")}


# ----------------------------------------------------------------------


def _sql_in_list(values) -> str:
    return ", ".join(f"'{_escape(str(v))}'" for v in values)


def _escape(value: str) -> str:
    """Minimal SQL-literal escaping. Inputs are account IDs, regions, and
    event names from a controlled allowlist, not free user text, but
    escaping quotes is cheap insurance."""
    return value.replace("'", "''")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _partition_predicate(start: datetime, end: datetime, scheme: str = "ymd") -> str:
    """Bound the scan to the incident window using partition columns.

    Without this Athena scans the whole bucket, so it's essential for cost,
    but the column layout varies by how the table was created. Pick the
    scheme that matches yours; "none" is the safe fallback.
    """
    s, e = start.strftime("%Y%m%d"), end.strftime("%Y%m%d")
    if scheme == "ymd":
        return (f"(CAST(year AS varchar) || lpad(CAST(month AS varchar), 2, '0') "
                f"|| lpad(CAST(day AS varchar), 2, '0')) BETWEEN '{s}' AND '{e}'")
    if scheme == "timestamp":
        return (f"replace(timestamp, '/', '') BETWEEN '{s}' AND '{e}'")
    return "1=1"
