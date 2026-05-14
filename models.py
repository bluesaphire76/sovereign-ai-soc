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

