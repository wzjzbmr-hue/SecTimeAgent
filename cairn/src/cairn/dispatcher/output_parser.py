from __future__ import annotations

import json
import re
from typing import Any


FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)


def _is_protocol_object(obj: dict[str, Any]) -> bool:
    if "accepted" in obj:
        return True
    keys = set(obj)
    if keys == {"complete"} and isinstance(obj.get("complete"), dict):
        return True
    if keys == {"intents"} and isinstance(obj.get("intents"), list):
        return True
    if keys == {"intent"} and isinstance(obj.get("intent"), dict):
        return True
    if keys in ({"fact"}, {"fact", "complete"}) and isinstance(obj.get("fact"), dict):
        return True
    if keys == {"description"} and isinstance(obj.get("description"), str):
        return True
    return False


def _extract_all_dicts(segment: str, decoder: json.JSONDecoder) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    stripped = segment.strip()
    if not stripped:
        return found
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(parsed, dict):
            return [parsed]

    idx = 0
    length = len(stripped)
    while idx < length:
        brace = stripped.find("{", idx)
        if brace == -1:
            break
        try:
            parsed, end = decoder.raw_decode(stripped, brace)
        except json.JSONDecodeError:
            idx = brace + 1
            continue
        if isinstance(parsed, dict):
            found.append(parsed)
        idx = max(end, brace + 1)
    return found


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the authoritative JSON object from model output.

    Models frequently quote tool JSON responses earlier in their explanation before
    emitting the final protocol JSON. Prefer the LAST JSON object matching Cairn's
    protocol schema, scanning fenced blocks first and then the full text.
    """
    decoder = json.JSONDecoder()
    fenced_matches = [match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(text)]

    protocol_candidates: list[dict[str, Any]] = []
    fallback_candidates: list[dict[str, Any]] = []

    for segment in fenced_matches:
        for obj in _extract_all_dicts(segment, decoder):
            if _is_protocol_object(obj):
                protocol_candidates.append(obj)
            else:
                fallback_candidates.append(obj)

    if protocol_candidates:
        return protocol_candidates[-1]

    for obj in _extract_all_dicts(text, decoder):
        if _is_protocol_object(obj):
            protocol_candidates.append(obj)
        else:
            fallback_candidates.append(obj)

    if protocol_candidates:
        return protocol_candidates[-1]
    if fallback_candidates:
        return fallback_candidates[-1]

    raise ValueError("no JSON object found in output")
