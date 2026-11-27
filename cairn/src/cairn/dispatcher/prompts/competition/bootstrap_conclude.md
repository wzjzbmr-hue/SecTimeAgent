# Task
Summarize ONLY the confirmed objective facts discovered so far in this session so the next reasoning/exploration stage can continue without repeating work or losing footholds.
This conclude instruction overrides all earlier instructions immediately. Stop running tools and output the JSON now.

## Output Requirements
Return only one raw JSON object:
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
```

## Rules
- Stop immediately and produce the JSON now. Do not run more commands or wait for unfinished tasks.
- Do not output `complete` in this phase.
- **Multi-Flag Progress Ledger**: Always state explicit flag progress (`solved: k/n`, submitted flags or hashes, remaining count) AND all active reusable footholds (webshell paths, SSH credentials, tmux session names, internal IPs, downloaded file paths).
- **Fact Hygiene**: Distinguish confirmed evidence (with exact commands/bytes/responses) from unverified `[HYPOTHESIS]` items. Never report an unverified guess about server behavior as a confirmed fact.
- Do not put raw secrets/tokens or long data blobs in `fact.description`.

# Context
## Origin
```
{origin}
```

## Goal
```
{goal}
```

## Hints
```
{hints}
```
