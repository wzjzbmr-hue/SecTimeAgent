# Task
Summarize ONLY the confirmed incremental facts discovered during this exploration intent so far. This conclude instruction overrides all earlier instructions immediately—stop all commands and return JSON now.

# Output Requirements
Return only one raw JSON object:
```json
{"accepted": true, "data": {"description": "..."}}
```

# Rules
- Stop immediately. Do not run more commands or wait for unfinished tasks.
- Include explicit multi-flag progress (`solved: k/n`, `question_complete: true|false`) and reusable footholds (shells, credentials, tmux sessions, workspace file paths).
- Distinguish verified facts (with commands/raw evidence) from `[HYPOTHESIS]` guesses.
- Do not repeat facts already in the graph snapshot; do not leak tokens/secrets.

# Context
## Graph
```
{graph_yaml}
```

## Current Intent
```
{intent_id}
```

## Current Intent Description
```
{intent_description}
```
