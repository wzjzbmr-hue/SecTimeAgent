#!/usr/bin/env python3
"""Deterministic pure-Python Modbus TCP client to prevent manual packet framing bugs.

Builds exact 12-byte RFC-compliant Modbus TCP (MBAP + PDU) read frames and decodes
FC1/FC2/FC3/FC4 responses into hex, ASCII, bits, and uint16 registers with zero external deps.

Usage:
  python3 /opt/cairn-poc/ics_client.py modbus-dump 127.0.0.1 502 --unit 1 --count 32
  python3 /opt/cairn-poc/ics_client.py modbus-read 127.0.0.1 502 --fc 3 --addr 0 --count 16 --unit 1
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from typing import Any


def build_mbap_read_frame(trans_id: int, unit_id: int, func_code: int, address: int, count: int) -> bytes:
    """Build an exact 12-byte Modbus TCP read request frame (MBAP 7 bytes + PDU 5 bytes)."""
    pdu = struct.pack(">BHH", func_code, address, count)
    length = 1 + len(pdu)  # unit_id (1) + PDU (5) = 6
    mbap = struct.pack(">HHHB", trans_id & 0xFFFF, 0, length, unit_id & 0xFF)
    return mbap + pdu


def parse_mbap_response(data: bytes) -> dict[str, Any]:
    if len(data) < 9:
        raise ValueError(f"truncated Modbus TCP response ({len(data)} bytes): {data.hex()}")
    trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", data[:7])
    func_code = data[7]
    if func_code & 0x80:
        exc_code = data[8]
        return {"ok": False, "trans_id": trans_id, "unit_id": unit_id, "func_code": func_code & 0x7F, "exception": exc_code}
    byte_count = data[8]
    payload = data[9 : 9 + byte_count]
    result: dict[str, Any] = {
        "ok": True,
        "trans_id": trans_id,
        "proto_id": proto_id,
        "length": length,
        "unit_id": unit_id,
        "func_code": func_code,
        "raw_hex": payload.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in payload),
    }
    if func_code in (3, 4) and len(payload) % 2 == 0:
        result["registers"] = list(struct.unpack(f">{len(payload) // 2}H", payload))
    elif func_code in (1, 2):
        bits = []
        for b in payload:
            for bit in range(8):
                bits.append((b >> bit) & 1)
        result["bits"] = bits
    return result


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def modbus_read(host: str, port: int, *, unit: int = 1, fc: int = 3, addr: int = 0, count: int = 16, timeout: float = 5.0) -> dict[str, Any]:
    frame = build_mbap_read_frame(1, unit, fc, addr, count)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(frame)
        header = _recv_exact(sock, 7)
        if len(header) < 7:
            raise RuntimeError(f"short MBAP header ({len(header)} bytes)")
        _, _, length, _ = struct.unpack(">HHHB", header)
        remaining = max(0, length - 1)
        body = _recv_exact(sock, remaining)
    parsed = parse_mbap_response(header + body)
    parsed["request_hex"] = frame.hex()
    return parsed


def modbus_dump(host: str, port: int, *, unit: int = 1, addr: int = 0, count: int = 32, timeout: float = 5.0) -> dict[str, Any]:
    out: dict[str, Any] = {"host": host, "port": port, "unit": unit, "tables": {}}
    for name, fc in (("coils_fc1", 1), ("discrete_fc2", 2), ("holding_fc3", 3), ("input_fc4", 4)):
        try:
            out["tables"][name] = modbus_read(host, port, unit=unit, fc=fc, addr=addr, count=count, timeout=timeout)
        except Exception as exc:
            out["tables"][name] = {"ok": False, "error": str(exc)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic ICS protocol client")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_read = sub.add_parser("modbus-read", help="Send a verified 12-byte Modbus TCP read frame")
    p_read.add_argument("host")
    p_read.add_argument("port", type=int)
    p_read.add_argument("--unit", type=int, default=1)
    p_read.add_argument("--fc", type=int, choices=[1, 2, 3, 4], default=3)
    p_read.add_argument("--addr", type=int, default=0)
    p_read.add_argument("--count", type=int, default=16)
    p_read.add_argument("--timeout", type=float, default=5.0)

    p_dump = sub.add_parser("modbus-dump", help="Dump FC1/FC2/FC3/FC4 tables from a Modbus TCP server")
    p_dump.add_argument("host")
    p_dump.add_argument("port", type=int)
    p_dump.add_argument("--unit", type=int, default=1)
    p_dump.add_argument("--addr", type=int, default=0)
    p_dump.add_argument("--count", type=int, default=32)
    p_dump.add_argument("--timeout", type=float, default=5.0)

    args = ap.parse_args()
    if args.cmd == "modbus-read":
        res = modbus_read(args.host, args.port, unit=args.unit, fc=args.fc, addr=args.addr, count=args.count, timeout=args.timeout)
    else:
        res = modbus_dump(args.host, args.port, unit=args.unit, addr=args.addr, count=args.count, timeout=args.timeout)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
