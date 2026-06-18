---
title: Wazuh Agent Queue Saturation Playbook
type: playbook
domain: governance
source: wazuh
incident_types:
  - wazuh_agent_queue_saturation
  - telemetry_loss_risk
  - agent_health_degradation
severity_hint:
  - medium
  - high
  - critical
mitre_tactics: []
mitre_techniques: []
applicability:
  - Wazuh reports the agent event queue at 90 percent, full, or flooded
  - Agent buffer pressure may delay or drop security telemetry
  - Wazuh rules 202, 203, or 204 report queue degradation
  - Repeated queue alerts require source-rate, configuration, connectivity, and capacity analysis
not_applicable_when:
  - A single historical warning is followed by verified recovery and no telemetry gap
  - Planned load testing produced the alert and monitoring confirms complete event delivery
  - Duplicate alerts represent the same already-tracked queue episode
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - wazuh
  - agent
  - queue
  - buffer
  - telemetry-loss
  - service-health
  - governance
---

# Wazuh Agent Queue Saturation Playbook

## Purpose

This playbook supports investigation of Wazuh agent event-buffer saturation that may delay or lose security telemetry.

It treats queue pressure as an observability and evidence-quality risk, not automatically as endpoint compromise.

## When to Use

- Wazuh reports `Agent event queue is 90% full`, `Agent event queue is full`, or `Agent event queue is flooded`.
- Raw log states the agent buffer is `90%`, `full`, or `flooded`.
- Wazuh rule ID 202, 203, or 204 or group `agent_flooding` is present.
- Repeated alerts indicate sustained event production, forwarding delay, manager backpressure, or agent misconfiguration.
- Use when current agent-health telemetry supports queue degradation or possible event loss.

## Detection Signals

- Rule 202: queue reaches the warning threshold.
- Rule 203: queue is full and events may be lost.
- Rule 204: queue is flooded and agent configuration requires review.
- Alert frequency, duration, affected agent, queue level, event rate, reconnects, and recovery time.
- Missing expected events, ingestion lag, manager pressure, network loss, or a noisy log source.

## Initial Triage

- Identify the agent ID, host, platform, queue state, first and last occurrence, duration, and recurrence.
- Determine whether the queue recovered after the warning or remained full or flooded.
- Check agent connectivity, manager availability, ingestion lag, event throughput, and relevant service health.
- Identify which log source, module, command, application, or event channel increased the event rate.
- Preserve timestamps and evidence of any visibility gap before changing queue or collection settings.

## Evidence to Collect

- Raw Wazuh rules 202, 203, and 204 and associated agent metadata.
- Agent and manager logs covering the pressure, disconnect, recovery, and normalization window.
- Event-rate, queue, ingestion-lag, CPU, memory, disk, network, and service-health metrics.
- Agent configuration, monitored sources, command output, logcollector settings, and recent changes.
- Expected-versus-received event counts and evidence of delayed, duplicated, or dropped telemetry.

## Investigation Steps

1. Build a timeline from the first warning through full recovery and identify all queue-state transitions.
2. Confirm whether events were delayed, dropped, or merely buffered using manager and downstream ingestion evidence.
3. Identify the highest-volume source, rule family, channel, file, command, or integration during the episode.
4. Review agent and manager resource pressure, connectivity, retries, restarts, and configuration changes.
5. Determine whether the volume reflects legitimate workload, a logging loop, malformed source, attack activity, or collection misconfiguration.
6. Compare affected and healthy agents with the same role and policy.
7. Assess which detections, timelines, or investigations may be incomplete because of the telemetry gap.
8. Document root cause, evidence impact, corrective action, validation, and recurrence monitoring.

## Correlation Checks

- Wazuh manager, indexer, shipper, queue, ingestion, and service-health metrics.
- Agent disconnect, reconnect, restart, upgrade, configuration, and enrollment events.
- High-volume Windows Event Log, Sysmon, auditd, file-integrity, vulnerability, command, or application sources.
- Detection spikes, log loops, repeated errors, scans, deployments, or workload changes.
- Missing expected heartbeats or events in downstream dashboards and investigations.

## False Positive Conditions

- Short planned load test causes a warning but no event loss and recovery is verified.
- Temporary manager maintenance buffers events and subsequent ingestion is complete.
- Duplicate alerts represent one already-documented episode.
- A brief warning remains below loss thresholds and all expected telemetry is accounted for.
- Closure still requires evidence that visibility was restored and no material gap remains.

## Escalation Criteria

- Queue reaches full or flooded state, events are lost, or the duration is unknown.
- Multiple agents or critical telemetry sources are affected.
- Security investigations overlap the visibility gap or cannot establish a reliable timeline.
- Root cause is unresolved, recurrent, or linked to manager capacity or systemic configuration.
- Immediate operational escalation is required when evidence availability is materially impaired.

## Containment Actions

- Do not disable high-value telemetry solely to clear the queue.
- Stabilize connectivity and service health through approved operational procedures.
- Apply temporary source-rate controls only when scope, security impact, owner, and rollback are documented.
- Preserve critical event sources and prioritize evidence required for active incidents.
- Record all operational changes in the service and security audit trail.

## Remediation Actions

- Correct noisy, recursive, duplicated, or malformed log collection at the source.
- Tune agent buffer and collection settings only against documented capacity and product guidance.
- Resolve manager, indexer, network, disk, CPU, memory, or backpressure constraints.
- Reduce unnecessary telemetry while preserving required security coverage and audit obligations.
- Validate recovery with sustained queue, ingestion-lag, event-count, and service-health monitoring.

## Closure Criteria

- Queue state returned to normal and remained stable through an appropriate observation window.
- Root cause and affected agents, sources, duration, and event-loss impact are documented.
- Expected event delivery and downstream ingestion were validated.
- Any investigation affected by the telemetry gap has an explicit evidence-quality note.
- Approved configuration or capacity remediation is complete and verified.
- Recurrence thresholds, owner, and follow-up monitoring are assigned.
- Closure requires analyst or service-owner approval according to local governance.

## Analyst Notes

- Queue saturation is a telemetry-integrity problem and can reduce confidence in every downstream conclusion.
- A healthy agent process does not prove complete event delivery.
- Qdrant and LLM output remain advisory; agent, manager, and ingestion metrics are authoritative.
- Prefer restoring reliable collection over suppressing the queue alert.
