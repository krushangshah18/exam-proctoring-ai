from sqlalchemy import (Column, Integer, String, Boolean, Text, Float, ForeignKey, DateTime, JSON)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base import Base
from app.db.mixins import UUIDMixin, TimestampMixin, SoftDeleteMixin
from app.db.enums import *


class User(UUIDMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "users"

    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(Text, nullable=False)

    role = Column(String, default=UserRole.STUDENT.value, nullable=False)

    profile_image_path = Column(Text)
    face_embedding = Column(Text)

    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime)

    sessions = relationship("ExamSession", back_populates="user")


class Exam(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "exams"

    title = Column(String, nullable=False)

    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    exam_mode = Column(String, nullable=False)
    status = Column(String, default=ExamStatus.DRAFT.value)

    start_window = Column(DateTime)
    end_window = Column(DateTime)

    duration_minutes = Column(Integer)
    hard_join_deadline = Column(DateTime)

    flag_threshold = Column(Integer)
    terminate_threshold = Column(Integer)

    late_join_policy = Column(String, default=LateJoinPolicy.REVIEW.value, nullable=False)

    allow_late_extension = Column(Boolean, default=False)
    max_late_minutes = Column(Integer)

    config = Column(JSON)

    sessions = relationship("ExamSession", back_populates="exam")


class ExamInvite(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "exam_invites"

    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.id"))
    student_email = Column(String, nullable=False)

    token = Column(Text, unique=True, index=True)
    expires_at = Column(DateTime)

    used = Column(Boolean, default=False)


class ExamSession(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "exam_sessions"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.id"))

    status = Column(String, default=SessionStatus.CREATED.value)

    start_time = Column(DateTime)
    end_time = Column(DateTime)

    risk_score = Column(Integer, default=0)

    last_heartbeat = Column(DateTime)

    terminated_reason = Column(Text)
    terminated_by = Column(String)

    user = relationship("User", back_populates="sessions")
    exam = relationship("Exam", back_populates="sessions")

    violations = relationship("Violation", back_populates="session")
    devices = relationship("SessionDevice", back_populates="session")


class SessionDevice(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "session_devices"

    session_id = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"))

    fingerprint = Column(Text)
    ip_address = Column(INET)
    user_agent = Column(Text)

    session = relationship("ExamSession", back_populates="devices")


class ViolationType(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "violation_types"

    code = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)

    severity = Column(String)
    default_score = Column(Integer)

    default_message = Column(Text)

    is_active = Column(Boolean, default=True)

    violations = relationship("Violation", back_populates="type")


class Violation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "violations"

    session_id = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"))

    violation_type_id = Column(UUID(as_uuid=True), ForeignKey("violation_types.id"))

    client_confidence = Column(Float)
    server_confidence = Column(Float)

    final_verdict = Column(String)

    occurred_at = Column(DateTime)

    session = relationship("ExamSession", back_populates="violations")
    type = relationship("ViolationType", back_populates="violations")

    evidences = relationship("Evidence", back_populates="violation")
    model_verifications = relationship("ModelVerification", back_populates="violation", cascade="all, delete-orphan")


class Evidence(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "evidences"

    violation_id = Column(UUID(as_uuid=True), ForeignKey("violations.id"))

    file_path = Column(Text, nullable=False)
    file_hash = Column(Text, nullable=False)

    mime_type = Column(String)

    violation = relationship("Violation", back_populates="evidences")


class RiskSnapshot(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "risk_snapshots"

    session_id = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"))

    trigger_violation_id = Column(UUID(as_uuid=True), ForeignKey("violations.id"), nullable=True)

    risk_score = Column(Integer)
    reason = Column(Text)


class ResumeRequest(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "resume_requests"

    session_id = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"))

    reason = Column(Text)

    status = Column(String, default=ResumeStatus.PENDING.value)

    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    review_note = Column(Text)


class TerminationReason(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "termination_reasons"

    code = Column(String, unique=True)
    description = Column(Text)

    is_active = Column(Boolean, default=True)


class AuditLog(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "audit_logs"

    actor_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id")
    )

    action = Column(Text)
    target = Column(Text)

    ip_address = Column(INET)


class ModelVerification(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "model_verifications"

    violation_id = Column(UUID(as_uuid=True), ForeignKey("violations.id"), nullable=False)

    model_name = Column(String, nullable=False)
    model_version = Column(String, nullable=False)

    confidence = Column(Float, nullable=False)

    verdict = Column(String, default=ModelVerdict.PASS.value, nullable=False)

    violation = relationship("Violation", back_populates="model_verifications")
