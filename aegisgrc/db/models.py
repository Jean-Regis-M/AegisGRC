import datetime
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON
from aegisgrc.db.base import Base


class ScanReport(Base):
    """Saves historic policy evaluation entries with full integrity hashes."""
    __tablename__ = "scan_reports"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    compliance_score = Column(Integer, nullable=False)
    total_findings = Column(Integer, default=0)
    sha256_hash = Column(String, unique=True, index=True)
    findings = Column(JSON, nullable=True) # Serialized list of OPA + AI objects


class DriftAlarm(Base):
    """Tracks out-of-band updates occurring bypassing GitHub pipeline controls."""
    __tablename__ = "drift_alarms"

    id = Column(String, primary_key=True)
    resource = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    parameter_changed = Column(String, nullable=False)
    expected_value = Column(String, nullable=False)
    actual_value = Column(String, nullable=False)
    remediated = Column(Boolean, default=False)
    remediated_at = Column(DateTime, nullable=True)


class GrcAuditTrialLog(Base):
    """System ledger recording manual recoveries, startups, and evaluation logs."""
    __tablename__ = "grc_audit_trail"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    action = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    details = Column(String, nullable=False)
    status = Column(String, nullable=False) # e.g. success, info, alert
