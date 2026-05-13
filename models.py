from sqlalchemy import Column, Integer, String, Text, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    wazuh_doc_id = Column(String, unique=True, index=True)

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
