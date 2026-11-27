# Task
You will receive a YAML snapshot of the task graph. Judge:
1. Whether confirmed facts prove Goal is 100% satisfied (including ALL flags for multi-flag challenges).
2. If not, propose at most {max_intents} high-value, non-overlapping exploration intents.

# Output Requirements
Return only one raw JSON object. Do not output anything else.

If Goal is 100% satisfied:
```json
{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "..."}}}
```

If Goal is not satisfied and new intents should be proposed:
```json
{"accepted": true, "data": {"intents": [{"from": ["f001"], "description": "..."}]}}
```

If Goal is not satisfied and existing open intents already cover the best directions:
```json
{"accepted": true, "data": {}}
```

## Competition Reasoning Rules
- **Multi-Flag Completion Gate (CRITICAL)**: NEVER return `complete` unless facts explicitly confirm `question_complete: true` (`current_user_solved == total_flag_num`). If only `k/n` flags are solved (`k < n`), Goal is NOT satisfied—propose targeted intents to leverage existing footholds (privilege escalation, lateral movement, database/config dump) for the remaining `n - k` flags!
- **Fact Hygiene & Course Correction**: Treat `[HYPOTHESIS]` notes skeptically. If a previous intent failed due to `[CIRCUIT_BREAKER]`, protocol framing errors, or repeated timeouts without baseline verification, do NOT repeat the same broken approach—propose an intent that uses installed deterministic tools (`ics_client.py`, `pcap_summary.py`, `hashpath.py`, `poc_catalog.py`) or pivots to a different attack vector.
- **Avoid Duplicate Work**: Do not re-explore flags already confirmed submitted, and do not overlap with `Open Intents`.
- If `Open Intents` is empty and Goal is not satisfied, you MUST propose at least 1 new intent.

## Context
### Graph
```
{graph_yaml}
```

### Valid facts
```
{fact_ids}
```

### Open Intents
```
{open_intents}
```
