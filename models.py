from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def utc_now():
    return datetime.now(timezone.utc)



class RawEvent(Base):
    __tablename__ = "raw_events"
    __table_args__ = (
        UniqueConstraint("source", "source_event_id", name="uq_raw_event_source_event_id"),
    )

    id = Column(Integer, primary_key=True, index=True)

    source = Column(String, default="wazuh", index=True, nullable=False)
    source_event_id = Column(String, index=True, nullable=False)
    source_index = Column(String)

    event_timestamp = Column(String, index=True)
    ingested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    agent = Column(String, index=True)
    rule_id = Column(String, index=True)
    rule_description = Column(Text)
    level = Column(Integer)

    payload_hash = Column(String, index=True, nullable=False)
    payload_json = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    __table_args__ = (
        UniqueConstraint("source", "source_event_id", name="uq_security_alert_source_event_id"),
        UniqueConstraint("raw_event_id", name="uq_security_alert_raw_event_id"),
    )

    id = Column(Integer, primary_key=True, index=True)

    raw_event_id = Column(Integer, ForeignKey("raw_events.id"), index=True, nullable=False)

    source = Column(String, default="wazuh", index=True, nullable=False)
    source_event_id = Column(String, index=True, nullable=False)

    fingerprint = Column(String, index=True)
    status = Column(String, default="OBSERVED", index=True)

    agent = Column(String, index=True)
    rule_id = Column(String, index=True)
    rule_description = Column(Text)
    level = Column(Integer)
    severity_bucket = Column(String, index=True)

    event_timestamp = Column(String, index=True)

    incident_id = Column(Integer, index=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    wazuh_doc_id = Column(String, unique=True, index=True)
    raw_event_id = Column(Integer, ForeignKey("raw_events.id"), index=True)
    security_alert_id = Column(Integer, ForeignKey("security_alerts.id"), index=True)

    status = Column(String, default="NEW")

    timestamp = Column(String)
    agent = Column(String)
    rule = Column(String)
    level = Column(Integer)
    mitre = Column(String)
    risk_score = Column(Integer)
    ai_analysis = Column(Text)
    raw_alert = Column(Text)

    correlated = Column(Boolean, default=False)
    correlation_summary = Column(Text)
    correlation_score = Column(Integer, default=0)

    attack_chain = Column(Text)
    correlation_type = Column(String)
    escalation_reason = Column(Text)
    recommended_priority = Column(String)

class IncidentAudit(Base):
    __tablename__ = "incident_audit"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True, nullable=False)

    event_type = Column(String, nullable=False)
    old_value = Column(String)
    new_value = Column(String)
    comment = Column(Text)

    created_by = Column(String, default="local_analyst")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True, nullable=False)

    note = Column(Text, nullable=False)
    created_by = Column(String, default="local_analyst")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

class IncidentCase(Base):
    __tablename__ = "incident_cases"

    id = Column(Integer, primary_key=True, index=True)
    group_key = Column(String, unique=True, index=True, nullable=False)

    title = Column(String, nullable=False)
    status = Column(String, default="OPEN")
    severity = Column(String, default="LOW")

    agent = Column(String, index=True)
    correlation_type = Column(String, index=True)
    risk_score = Column(Integer, default=0)
    summary = Column(Text)

    owner = Column(String)
    assignee = Column(String)
    sla_due_at = Column(DateTime(timezone=True))
    severity_review = Column(String)
    status_reason = Column(Text)
    last_reviewed_by = Column(String)
    last_reviewed_at = Column(DateTime(timezone=True))


    created_by = Column(String, default="system")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class CaseIncident(Base):
    __tablename__ = "case_incidents"
    __table_args__ = (
        UniqueConstraint("case_id", "incident_id", name="uq_case_incident"),
    )

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("incident_cases.id"), index=True, nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True, nullable=False)

    relationship_type = Column(String, default="CORRELATED")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

class CaseAudit(Base):
    __tablename__ = "case_audit"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("incident_cases.id"), index=True, nullable=False)

    event_type = Column(String, nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    comment = Column(Text)

    created_by = Column(String, default="local_analyst")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class CaseAction(Base):
    __tablename__ = "case_actions"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("incident_cases.id"), index=True, nullable=False)

    title = Column(String, nullable=False)
    description = Column(Text)
    category = Column(String, default="INVESTIGATION")
    priority = Column(String, default="MEDIUM")
    status = Column(String, default="OPEN")

    due_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))

    created_by = Column(String, default="local_analyst")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

class CaseClosureChecklist(Base):
    __tablename__ = "case_closure_checklists"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("incident_cases.id"), unique=True, index=True, nullable=False)

    root_cause = Column(Text)
    evidence_reviewed = Column(Text)
    actions_summary = Column(Text)
    closure_reason = Column(Text)
    closure_decision = Column(String)
    final_severity = Column(String)
    residual_risk = Column(Text)
    closure_approved = Column(Boolean, default=False)
    closure_approved_by = Column(String)
    closure_approved_at = Column(DateTime(timezone=True))

    reviewed_by = Column(String, default="local_analyst")
    reviewed_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class CaseAIAnalysis(Base):
    __tablename__ = "case_ai_analyses"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("incident_cases.id"), index=True, nullable=False)

    model = Column(String)
    analysis = Column(Text, nullable=False)
    recommended_status = Column(String)
    recommended_severity = Column(String)
    created_by = Column(String, default="llm")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class EventAggregate(Base):
    __tablename__ = "event_aggregates"

    id = Column(Integer, primary_key=True, index=True)
    fingerprint = Column(String, unique=True, index=True, nullable=False)

    source = Column(String, default="wazuh", index=True, nullable=False)
    rule_id = Column(String, index=True)
    rule_description = Column(Text)
    agent = Column(String, index=True)
    location = Column(String, index=True)
    decoder = Column(String, index=True)
    level = Column(Integer)
    severity_bucket = Column(String, index=True)

    first_seen = Column(String, index=True)
    last_seen = Column(String, index=True)
    count = Column(Integer, default=1, nullable=False)

    first_wazuh_doc_id = Column(String)
    last_wazuh_doc_id = Column(String)
    last_incident_id = Column(Integer, index=True)

    sample_event_json = Column(Text)
    last_event_json = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    component = Column(String, unique=True, index=True, nullable=False)

    status = Column(String, default="UNKNOWN")
    last_seen_at = Column(DateTime(timezone=True))
    last_success_at = Column(DateTime(timezone=True))
    last_error_at = Column(DateTime(timezone=True))
    last_error = Column(Text)
    details = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)



class AppUser(Base):
    __tablename__ = "app_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    display_name = Column(String)
    role = Column(String, default="ANALYST", nullable=False)
    password_hash = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    last_login_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"

    id = Column(Integer, primary_key=True, index=True)

    event_type = Column(String, index=True, nullable=False)
    outcome = Column(String, index=True, nullable=False)

    actor_user_id = Column(Integer, index=True)
    actor_username = Column(String, index=True)
    actor_role = Column(String, index=True)

    target_type = Column(String, index=True)
    target_id = Column(String, index=True)
    target_username = Column(String, index=True)

    method = Column(String)
    path = Column(String)
    client_ip = Column(String)
    user_agent = Column(Text)

    details_json = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InvestigationSessionRecord(Base):
    __tablename__ = "investigation_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False)
    incident_id = Column(Integer, index=True, nullable=False)

    status = Column(String, index=True, nullable=False)
    generated_by = Column(String, default="system")
    model_name = Column(String)
    parent_session_id = Column(String, index=True)

    investigation_version = Column(Integer, default=1, nullable=False)
    enrichment_pass_count = Column(Integer, default=0, nullable=False)
    fallback_used = Column(Boolean, default=False, nullable=False)

    confidence_score = Column(Integer)
    confidence_level = Column(String, index=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InvestigationSnapshotRecord(Base):
    __tablename__ = "investigation_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(String, unique=True, index=True, nullable=False)
    session_id = Column(String, ForeignKey("investigation_sessions.session_id"), index=True, nullable=False)

    snapshot_type = Column(String, default="BRIEF", index=True, nullable=False)
    investigation_version = Column(Integer, default=1, nullable=False)
    investigation_payload = Column(Text, nullable=False)

    evidence_count = Column(Integer, default=0, nullable=False)
    hypothesis_count = Column(Integer, default=0, nullable=False)
    recommended_check_count = Column(Integer, default=0, nullable=False)
    recommended_action_count = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InvestigationHypothesisHistoryRecord(Base):
    __tablename__ = "investigation_hypothesis_history"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("investigation_sessions.session_id"), index=True, nullable=False)
    hypothesis_id = Column(String, index=True, nullable=False)

    investigation_version = Column(Integer, default=1, nullable=False)
    hypothesis_status = Column(String, index=True)
    confidence_score = Column(Integer)
    claim_classification = Column(String, index=True)

    supporting_evidence_count = Column(Integer, default=0, nullable=False)
    contradictory_evidence_count = Column(Integer, default=0, nullable=False)
    missing_evidence_count = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InvestigationConfidenceHistoryRecord(Base):
    __tablename__ = "investigation_confidence_history"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("investigation_sessions.session_id"), index=True, nullable=False)
    snapshot_id = Column(String, index=True)

    investigation_version = Column(Integer, default=1, nullable=False)
    previous_score = Column(Integer)
    new_score = Column(Integer)
    previous_level = Column(String)
    new_level = Column(String, index=True)
    reason = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InvestigationRetrievalHistoryRecord(Base):
    __tablename__ = "investigation_retrieval_history"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("investigation_sessions.session_id"), index=True, nullable=False)

    investigation_version = Column(Integer, default=1, nullable=False)
    enrichment_pass = Column(Integer, default=0, nullable=False)
    request_id = Column(String, index=True)
    retrieval_type = Column(String, index=True)
    retrieval_status = Column(String, index=True)
    duration_ms = Column(Integer, default=0, nullable=False)
    evidence_count = Column(Integer, default=0, nullable=False)
    limits_applied_json = Column(Text)
    failures_json = Column(Text)
    audit_summary = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class InvestigationFeedbackRecord(Base):
    __tablename__ = "investigation_feedback"

    id = Column(Integer, primary_key=True, index=True)
    feedback_id = Column(String, unique=True, index=True, nullable=False)
    session_id = Column(String, ForeignKey("investigation_sessions.session_id"), index=True, nullable=False)

    analyst = Column(String, index=True)
    feedback_type = Column(String, index=True, nullable=False)
    feedback_text = Column(Text)
    confidence_override = Column(Integer)
    hypothesis_reference = Column(String, index=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

class WazuhIngestWatermark(Base):
    __tablename__ = "wazuh_ingest_watermarks"

    id = Column(Integer, primary_key=True, index=True)
    component = Column(String, unique=True, index=True, nullable=False)

    last_timestamp = Column(String, index=True)
    last_doc_id = Column(String)

    last_poll_at = Column(DateTime(timezone=True))
    last_success_at = Column(DateTime(timezone=True))
    last_error_at = Column(DateTime(timezone=True))
    last_error = Column(Text)

    alerts_seen = Column(Integer, default=0)
    alerts_processed = Column(Integer, default=0)
    alerts_skipped = Column(Integer, default=0)
    total_processed = Column(Integer, default=0)

    details = Column(Text)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
