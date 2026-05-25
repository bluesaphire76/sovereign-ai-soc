#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path("/var/log/ai-soc/dns-telemetry.log")
HOSTNAME = socket.gethostname()

# Example tcpdump query line:
# 2026-05-25 10:10:10.123456 IP 192.168.1.148.53210 > 192.168.1.1.53: 12345+ A? example.com. (29)
QUERY_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"IP6?\s+"
    r"(?P<src>[^ ]+)\s+>\s+"
    r"(?P<dst>[^:]+):\s+"
    r".*?\s+"
    r"(?P<qtype>[A-Z0-9]+)\?\s+"
    r"(?P<qname>[^ ]+)"
)


def parse_endpoint(value: str) -> tuple[str | None, int | None]:
    value = value.strip()

    # IPv4 with port: 192.168.1.148.53210
    match = re.match(r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\.(?P<port>\d+)$", value)
    if match:
        return match.group("ip"), int(match.group("port"))

    # Fallback for IPv6 or unexpected tcpdump formatting.
    return value, None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_query_name(value: str) -> str:
    return value.strip().rstrip(".")


def write_event(event: dict) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def main() -> int:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "tcpdump",
        "-l",
        "-n",
        "-tttt",
        "-i",
        "any",
        "port",
        "53",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    write_event(
        {
            "event_type": "ai_soc_dns_collector_started",
            "event_timestamp": utc_now(),
            "host": HOSTNAME,
            "collector": "tcpdump_dns_query_collector",
            "command": " ".join(command),
        }
    )

    assert process.stdout is not None

    for raw_line in process.stdout:
        line = raw_line.strip()

        if not line:
            continue

        if "?" not in line:
            continue

        match = QUERY_RE.search(line)
        if not match:
            continue

        src_ip, src_port = parse_endpoint(match.group("src"))
        dst_ip, dst_port = parse_endpoint(match.group("dst"))

        event = {
            "event_type": "ai_soc_dns_query",
            "event_timestamp": utc_now(),
            "host": HOSTNAME,
            "collector": "tcpdump_dns_query_collector",
            "src_ip": src_ip,
            "src_port": src_port,
            "resolver_ip": dst_ip,
            "resolver_port": dst_port,
            "query_type": match.group("qtype"),
            "query_name": normalize_query_name(match.group("qname")),
            "raw_line": line,
        }

        write_event(event)

    return process.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
    except Exception as exc:
        write_event(
            {
                "event_type": "ai_soc_dns_collector_error",
                "event_timestamp": utc_now(),
                "host": HOSTNAME,
                "collector": "tcpdump_dns_query_collector",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        print(f"collector error: {exc}", file=sys.stderr)
        raise SystemExit(1)
