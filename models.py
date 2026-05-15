from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    wazuh_doc_id = Column(String, unique=True, index=True)

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

def utc_now():
    return datetime.now(timezone.utc)


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

