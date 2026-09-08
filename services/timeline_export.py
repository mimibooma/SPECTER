"""
Timeline export.

Analysts don't live in JSON. They live in Timesketch, in Excel, in whatever
their team standardized on years ago. This writes the correlated timeline
in formats they'll actually open.

Timesketch format follows the documented CSV import spec: message,
datetime, timestamp_desc are required; other columns become searchable.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List

TIMESKETCH_COLUMNS = [
    "message", "datetime", "timestamp_desc", "event_name", "event_source",
    "actor", "actor_type", "account", "region", "source_ip", "user_agent",
    "mfa", "error_code", "repeat_count", "specter_tag",
]


class TimelineExporter:

    def export(self, events: List[dict], correlation: dict, out_path: str,
               fmt: str = "timesketch") -> str:
        rows = self._rows(events, correlation)
        p = Path(out_path)
        if fmt == "jsonl":
            with p.open("w") as fh:
                for r in rows:
                    fh.write(json.dumps(r) + "\n")
        else:
            with p.open("w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=TIMESKETCH_COLUMNS, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
        return str(p)

    def _rows(self, events: List[dict], correlation: dict) -> List[dict]:
        # tag events that show up in correlation findings so they stand out
        tagged = {}
        for c in correlation.get("escalation_chains", []):
            tagged[(c.get("actor"), c.get("access_time"))] = "escalation_chain_start"
            for e in c.get("escalation_events", []):
                tagged[(c.get("actor"), e.get("time"))] = "escalation"
        for g in correlation.get("logging_gaps", []):
            tagged[(g.get("disabled_by"), g.get("start"))] = "logging_disabled"
            if g.get("end"):
                tagged[(g.get("disabled_by"), g.get("end"))] = "logging_restored"
        for pv in correlation.get("cross_account_pivots", []):
            tagged[(pv.get("actor"), pv.get("time"))] = "cross_account_pivot"
        for s in correlation.get("session_chains", []):
            tagged[(s.get("assumed_by"), s.get("assumed_at"))] = "session_start"

        rows = []
        for ev in sorted(events, key=lambda e: e.get("eventTime", "")):
            actor = ev.get("actor") or {}
            arn = actor.get("arn") or actor.get("userName") or ""
            t = ev.get("eventTime", "")
            short = arn.split("/")[-1] if "/" in arn else arn
            rows.append({
                "message": f"{ev.get('eventName')} by {short} from {ev.get('sourceIPAddress', '?')}",
                "datetime": t,
                "timestamp_desc": "CloudTrail Event Time",
                "event_name": ev.get("eventName"),
                "event_source": ev.get("eventSource"),
                "actor": arn,
                "actor_type": actor.get("type"),
                "account": ev.get("account"),
                "region": ev.get("awsRegion"),
                "source_ip": ev.get("sourceIPAddress"),
                "user_agent": ev.get("userAgent"),
                "mfa": ev.get("mfaAuthenticated"),
                "error_code": ev.get("errorCode"),
                "repeat_count": ev.get("repeatCount"),
                "specter_tag": tagged.get((arn, t), ""),
            })
        return rows
