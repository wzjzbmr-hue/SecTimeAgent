#!/usr/bin/env python3
"""Deterministic ICS/TCP PCAP summarizer built on tshark.

Eliminates manual hex decoding errors (off-by-one byte / wrong server session) by
extracting structured tables for Modbus (mbtcp), S7 (s7comm), IEC-104 (104asdu),
and general TCP payloads with verified tshark dissector field names.

Usage:
  python3 /opt/cairn-poc/pcap_summary.py capture.pcap --proto auto
  python3 /opt/cairn-poc/pcap_summary.py capture.pcap --proto modbus --port 502
  python3 /opt/cairn-poc/pcap_summary.py capture.pcap --proto s7
  python3 /opt/cairn-poc/pcap_summary.py capture.pcap --proto iec104
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from typing import Any

PROTO_SPECS: dict[str, dict[str, Any]] = {
    "modbus": {
        "display_filter": "mbtcp || modbus",
        "fields": [
            "frame.number",
            "tcp.stream",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "mbtcp.trans_id",
            "mbtcp.unit_id",
            "modbus.func_code",
            "modbus.reference_num",
            "modbus.word_cnt",
            "modbus.regval_uint16",
            "modbus.data",
        ],
    },
    "s7": {
        "display_filter": "s7comm",
        "fields": [
            "frame.number",
            "tcp.stream",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "s7comm.header.rosctr",
            "s7comm.header.pduref",
            "s7comm.param.func",
            "s7comm.param.item.db",
            "s7comm.param.item.address",
            "s7comm.resp.data",
            "s7comm.data.returncode",
        ],
    },
    "iec104": {
        "display_filter": "104apci || 104asdu",
        "fields": [
            "frame.number",
            "tcp.stream",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "104apci.type",
            "104asdu.typeid",
            "104asdu.causetx",
            "104asdu.coa",
            "104asdu.ioa",
            "104asdu.normval",
            "104asdu.float",
        ],
    },
    "tcp": {
        "display_filter": "tcp.len > 0",
        "fields": [
            "frame.number",
            "tcp.stream",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "tcp.len",
            "tcp.payload",
        ],
    },
}


def run_tshark(pcap: str, proto: str, *, port: int | None = None, limit: int = 200) -> list[dict[str, str]]:
    if not shutil.which("tshark"):
        raise RuntimeError("tshark is not installed on PATH")
    spec = PROTO_SPECS[proto]
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=\t", "-E", "quote=n"]
    if proto == "modbus" and port:
        cmd += ["-d", f"tcp.port=={port},mbtcp"]
    elif proto == "iec104" and port:
        cmd += ["-d", f"tcp.port=={port},104apci"]
    cmd += ["-Y", spec["display_filter"]]
    for field in spec["fields"]:
        cmd += ["-e", field]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"tshark exited {res.returncode}")
    rows: list[dict[str, str]] = []
    for line in res.stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        row = {field: (cols[i] if i < len(cols) else "") for i, field in enumerate(spec["fields"])}
        rows.append(row)
        if limit and len(rows) >= limit:
            break
    return rows


def detect_proto(pcap: str) -> str:
    for proto in ("modbus", "s7", "iec104"):
        try:
            if run_tshark(pcap, proto, limit=1):
                return proto
        except Exception:
            continue
    return "tcp"


def main() -> int:
    ap = argparse.ArgumentParser(description="Structured ICS/TCP PCAP summary via tshark")
    ap.add_argument("pcap", help="Path to pcap/pcapng file")
    ap.add_argument("--proto", choices=["auto", "modbus", "s7", "iec104", "tcp"], default="auto")
    ap.add_argument("--port", type=int, default=None, help="Optional non-standard TCP port to decode as mbtcp/104apci")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--json", dest="as_json", action="store_true")
    args = ap.parse_args()

    proto = detect_proto(args.pcap) if args.proto == "auto" else args.proto
    rows = run_tshark(args.pcap, proto, port=args.port, limit=args.limit)
    if args.as_json:
        print(json.dumps({"proto": proto, "count": len(rows), "rows": rows}, ensure_ascii=False, indent=2))
        return 0

    print(f"# proto={proto} rows={len(rows)}")
    if not rows:
        return 0
    headers = list(rows[0].keys())
    print("\t".join(headers))
    for row in rows:
        print("\t".join(row.get(h, "") for h in headers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
