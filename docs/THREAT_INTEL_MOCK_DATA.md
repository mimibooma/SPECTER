# Threat Feed Format

SPECTER's mock feeds let the enrichment path run without external API
credentials. The same `ThreatFeed` interface accepts a real provider later
without changing any caller.

## File format

One indicator per line, pipe-delimited (commas are also accepted, but
descriptions often contain commas so pipe is preferred):

```
<indicator>|<category>|<confidence>|<severity>|<first_seen>|<last_seen>|<description>
```

- `indicator` — the IP, domain, or hash
- `category` — e.g. `tor_exit_node`, `c2_server`, `phishing`
- `confidence` — 0-100
- `description` — free text; threat-group aliases here are auto-extracted

Lines beginning with `#` are comments.

## Attribution

Threat-group attribution is recovered from the category and description text
by matching against the ATT&CK group alias table in
`services/scoring_engine.py`. Writing "APT29" or "Cozy Bear" anywhere in the
description resolves the indicator to ATT&CK group G0016 automatically.

## Swapping in a real feed

Implement `ThreatFeed` (see `services/threat_intel.py`):

```python
class MyProviderFeed(ThreatFeed):
    name = "my_provider"
    def lookup(self, ioc): ...
    @property
    def available(self): ...
```

Then add it to `ThreatIntelService.feeds`. Enrichment degrades gracefully:
if no feed is available, indicators are still extracted, and output is flagged
`enrichment_degraded: true` so no attribution is silently assumed.
