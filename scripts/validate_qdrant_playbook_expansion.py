from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from investigation_ai.adapters import safe_text
from playbook_retrieval_catalog import EXPANDED_PLAYBOOK_PRIMARY_INCIDENT_TYPES
from playbook_retrieval_hints import (
    build_playbook_retrieval_query,
    infer_playbook_retrieval_hints,
    playbook_retrieval_filter_stages,
)
from qdrant_knowledge import QdrantKnowledgeBase


REQUIRED_PAYLOAD_FIELDS = (
    "doc_type",
    "content_kind",
    "title",
    "domain",
    "playbook_source",
    "incident_types",
    "severity_hint",
    "mitre_tactics",
    "mitre_techniques",
    "applicability",
    "not_applicable_when",
    "recommended_for_pages",
    "tags",
    "section",
    "file_path",
)
PAYLOAD_FIELDS = [
    *REQUIRED_PAYLOAD_FIELDS,
    "content_hash",
    "section_order",
]
SCENARIOS = (
    (
        "linux",
        "Wazuh unauthorized user creation: useradd created UID 0 local account T1136.001",
        "Unauthorized Linux User Creation Playbook",
    ),
    (
        "windows",
        "Windows Event ID 7045 service installed from ADMIN$ after remote logon T1543.003",
        "Windows Service Creation Playbook",
    ),
    (
        "windows_audit_failure",
        "Windows audit failure event Event ID 5061 cryptographic operation return code 0x80090016",
        "Windows Audit Failure Investigation Playbook",
    ),
    (
        "windows_sysmon_suspicious_process",
        "Sysmon - Suspicious Process - explorer.exe Event ID 1 process anomaly T1055",
        "Windows Sysmon Suspicious Process Playbook",
    ),
    (
        "windows_netsh_firewall_rule_change",
        "Netsh used to add firewall rule netsh advfirewall firewall add rule T1562.004",
        "Windows Netsh Firewall Rule Change Playbook",
    ),
    (
        "windows_cis_benchmark_failure",
        "CIS Microsoft Windows 11 Enterprise Benchmark Wazuh SCA check result failed",
        "Windows CIS Benchmark Failure Playbook",
    ),
    (
        "wazuh_agent_queue_saturation",
        "Wazuh Agent event queue is flooded agent buffer full",
        "Wazuh Agent Queue Saturation Playbook",
    ),
    (
        "suricata",
        "Suricata ET EXPLOIT exploit attempt against public-facing application CVE T1190",
        "Suricata Exploit Attempt Playbook",
    ),
    (
        "dns",
        "DNS domain generation algorithm DGA high NXDOMAIN ratio T1568.002",
        "Domain Generation Algorithm Playbook",
    ),
    (
        "malware",
        "Reverse shell detected: Python process opened interactive outbound shell T1059",
        "Reverse Shell Detection Playbook",
    ),
    (
        "exfiltration",
        "Large outbound data transfer to rare external destination possible data exfiltration T1041",
        "Large Outbound Data Transfer Playbook",
    ),
    (
        "governance",
        "Containment approval required before host isolation and account disablement",
        "Containment Approval Playbook",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate expanded playbook metadata and scenario retrieval in Qdrant."
    )
    parser.add_argument(
        "--max-points",
        type=int,
        default=20000,
        help="Maximum Qdrant points to scan while validating payload metadata.",
    )
    return parser.parse_args()


def _expanded_playbook_documents() -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for path in sorted(Path("knowledge_base/playbooks").rglob("*.md")):
        if "_templates" in path.parts or path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        metadata = yaml.safe_load(text.split("---", 2)[1]) or {}
        incident_types = metadata.get("incident_types") or []
        if not incident_types or incident_types[0] not in {
            *EXPANDED_PLAYBOOK_PRIMARY_INCIDENT_TYPES,
            "windows_audit_failure",
        }:
            continue
        documents[str(path)] = metadata
    return documents


def _scan_payloads(
    kb: QdrantKnowledgeBase,
    *,
    max_points: int,
) -> dict[str, list[dict[str, Any]]]:
    payloads_by_source: dict[str, list[dict[str, Any]]] = {}
    scanned = 0
    offset = None

    while scanned < max_points:
        points, offset = kb.client.scroll(
            collection_name=kb.config.collection_name,
            limit=min(250, max_points - scanned),
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )
        if not points:
            break
        scanned += len(points)
        for point in points:
            payload = getattr(point, "payload", None) or {}
            source = safe_text(payload.get("source"))
            if source:
                payloads_by_source.setdefault(source, []).append(payload)
        if offset is None:
            break

    return payloads_by_source


def _validate_metadata(
    documents: dict[str, dict[str, Any]],
    payloads_by_source: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    failures: list[str] = []

    for source, metadata in documents.items():
        payloads = payloads_by_source.get(source) or []
        document_failures: list[str] = []
        if not payloads:
            document_failures.append("no indexed Qdrant points")
        for payload in payloads:
            for field_name in REQUIRED_PAYLOAD_FIELDS:
                if field_name not in payload:
                    document_failures.append(f"missing payload field {field_name}")
            if payload.get("doc_type") != "playbook":
                document_failures.append("doc_type is not playbook")
            if payload.get("content_kind") != "playbook_section":
                document_failures.append("content_kind is not playbook_section")
            if payload.get("title") != metadata.get("title"):
                document_failures.append("title does not match front matter")
            if payload.get("domain") != metadata.get("domain"):
                document_failures.append("domain does not match front matter")
            if payload.get("playbook_source") != metadata.get("source"):
                document_failures.append("source does not match front matter")
            if "recommended_playbooks" not in (
                payload.get("recommended_for_pages") or []
            ):
                document_failures.append("recommended_playbooks target is missing")

        unique_failures = sorted(set(document_failures))
        if unique_failures:
            failures.extend(f"{source}: {reason}" for reason in unique_failures)
        results.append(
            {
                "source": source,
                "title": metadata.get("title"),
                "domain": metadata.get("domain"),
                "points": len(payloads),
                "status": "OK" if not unique_failures else "FAIL",
                "failures": unique_failures,
            }
        )

    return results, failures


def _validate_scenarios(
    kb: QdrantKnowledgeBase,
) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    failures: list[str] = []

    for name, facts, expected_title in SCENARIOS:
        hints = infer_playbook_retrieval_hints(facts)
        query = build_playbook_retrieval_query(
            target_type="incident",
            facts=facts,
            hints=hints,
        )
        retrieved_titles: list[str] = []
        matched_stage = ""
        for stage in playbook_retrieval_filter_stages(hints):
            contexts = kb.retrieve_contexts(
                query,
                limit=25,
                source_type="knowledge_base",
                payload_filter=stage.payload_filter,
                payload_fields=PAYLOAD_FIELDS,
            )
            for context in contexts:
                title = safe_text(context.get("title"))
                if title and title not in retrieved_titles:
                    retrieved_titles.append(title)
            if expected_title in retrieved_titles:
                matched_stage = stage.name
                break

        status = "OK" if expected_title in retrieved_titles else "FAIL"
        if status == "FAIL":
            failures.append(
                f"{name}: expected {expected_title!r}, retrieved {retrieved_titles!r}"
            )
        results.append(
            {
                "scenario": name,
                "expected_title": expected_title,
                "retrieved_titles": retrieved_titles,
                "matched_stage": matched_stage,
                "hints": hints.to_public_dict(),
                "status": status,
            }
        )

    return results, failures


def run(*, max_points: int = 20000) -> dict[str, Any]:
    kb = QdrantKnowledgeBase()
    documents = _expanded_playbook_documents()
    payloads_by_source = _scan_payloads(kb, max_points=max_points)
    metadata_results, metadata_failures = _validate_metadata(
        documents,
        payloads_by_source,
    )
    scenario_results, scenario_failures = _validate_scenarios(kb)
    collection_info = kb.collection_info()
    failures = [*metadata_failures, *scenario_failures]

    return {
        "status": "OK" if not failures else "FAIL",
        "collection": kb.config.collection_name,
        "collection_info": collection_info,
        "expanded_playbooks_expected": 51,
        "expanded_playbooks_discovered": len(documents),
        "expanded_playbooks_indexed": sum(
            1 for result in metadata_results if result["points"] > 0
        ),
        "metadata_results": metadata_results,
        "scenario_results": scenario_results,
        "failures": failures,
    }


def main() -> None:
    args = parse_args()
    result = run(max_points=max(1, args.max_points))
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
