from sqlalchemy import (Column, Integer, String, Boolean, Text, Float, ForeignKey, DateTime, JSON, Index)
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
    must_change_password = Column(Boolean, default=False, server_default='false', nullable=False)
    
    last_login = Column(DateTime)

    last_profile_image_update = Column(DateTime, nullable=True)

    # Security
    failed_login_attempts = Column(Integer, default=0,nullable=False)
    locked_until = Column(DateTime, nullable=True)
    unlock_requests = Column(Integer, default=0, nullable=False)

    # Privacy / Consent
    consent_given = Column(Boolean, default=False)
    consent_at = Column(DateTime)
    privacy_version = Column(String, default="v1.0-2026")

    sessions = relationship("ExamSession", back_populates="user")


class RefreshToken(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "refresh_tokens"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    token = Column(Text, unique=True, nullable=False)

    device_fingerprint = Column(String, nullable=False)

    expires_at = Column(DateTime, nullable=False)

    revoked = Column(Boolean, default=False)

    user = relationship("User")


class PasswordResetToken(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "password_reset_tokens"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )

    token_hash = Column(Text, nullable=False)

    expires_at = Column(DateTime, nullable=False)

    used = Column(Boolean, default=False)

    user = relationship("User")


class Exam(UUIDMixin, TimestampMixin, SoftDeleteMixin, Base):
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

    late_join_policy = Column(String, default=LateJoinPolicy.REVIEW.value, nullable=False)

    allow_late_extension = Column(Boolean, default=False)
    max_late_minutes = Column(Integer)

    config = Column(JSON)

    # Proctoring engine — exam-admin-controlled detection toggles (13 booleans)
    detection_config = Column(JSON, nullable=True)

    sessions = relationship("ExamSession", back_populates="exam", cascade="all, delete-orphan")
    invites = relationship("ExamInvite", back_populates="exam", cascade="all, delete-orphan")
    engine_assignments = relationship("ExamEngineAssignment", back_populates="exam", cascade="all, delete-orphan")


class ExamInvite(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "exam_invites"

    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.id"))
    student_email = Column(String, nullable=False)

    token = Column(Text, unique=True, index=True)
    expires_at = Column(DateTime)

    used = Column(Boolean, default=False)

    exam = relationship("Exam", back_populates="invites")


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
    terminated_at = Column(DateTime, nullable=True)

    time_extension_seconds = Column(Integer, default=0, server_default='0', nullable=False)

    device_fingerprint = Column(String, nullable=False)
    ip_address = Column(String)
    user_agent = Column(Text)

    # Proctoring engine — set when WebRTC handshake completes
    proctor_pc_id = Column(String, nullable=True)
    proctor_engine_url = Column(String, nullable=True)
    # Set when session closes — used to fetch full report from engine
    proctor_report_id = Column(String, nullable=True)

    user = relationship("User", back_populates="sessions")
    exam = relationship("Exam", back_populates="sessions")

    devices = relationship("SessionDevice", back_populates="session", cascade="all, delete-orphan")
    resume_requests = relationship("ResumeRequest", back_populates="session", cascade="all, delete-orphan")
    proctor_alerts = relationship("ProctorAlert", back_populates="session", cascade="all, delete-orphan", order_by="ProctorAlert.occurred_at")
    proctor_warnings = relationship("ProctorWarning", back_populates="session", cascade="all, delete-orphan", order_by="ProctorWarning.occurred_at")


class SessionDevice(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "session_devices"

    session_id = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"))

    fingerprint = Column(Text)
    ip_address = Column(INET)
    user_agent = Column(Text)

    session = relationship("ExamSession", back_populates="devices")


class ResumeRequest(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "resume_requests"

    session_id = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"))

    reason = Column(Text)

    status = Column(String, default=ResumeStatus.PENDING.value)

    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)

    review_note = Column(Text)
    time_extension_minutes = Column(Integer, nullable=True)

    session = relationship("ExamSession", back_populates="resume_requests")


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


class AdminApplication(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "admin_applications"

    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)

    organization = Column(String)
    contact_number = Column(String)

    reason = Column(Text, nullable=False)

    status = Column(
        String,
        default=ApplicationStatus.PENDING.value,
        nullable=False
    )

    reviewed_by = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )

    review_note = Column(Text)

    approved_at = Column(DateTime)
    rejected_at = Column(DateTime)

    reviewer = relationship("User", foreign_keys=[reviewed_by])


class UserDevice(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "user_devices"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    fingerprint = Column(Text, nullable=False)
    user_agent = Column(Text)
    ip_address = Column(INET)

    last_seen = Column(DateTime)

    trusted = Column(Boolean, default=False)
    pending = Column(Boolean, default=True)
    revoked = Column(Boolean, default=False)

    user = relationship("User")
    __table_args__ = (
        Index("idx_user_device_user", "user_id"),
        Index("idx_user_device_fp", "fingerprint"),
    )


# ── Proctoring Engine Infrastructure ─────────────────────────────────────────

class EngineContainer(UUIDMixin, TimestampMixin, Base):
    """
    One row per Docker container running the AI proctoring engine.
    Seeded at startup from PROCTOR_ENGINE_URLS env var.
    Each container has a fixed capacity (MAX_SESSIONS=3 on current EC2).
    """
    __tablename__ = "engine_containers"

    url = Column(String, unique=True, nullable=False)   # e.g. "http://13.201.166.165:8000"
    max_sessions = Column(Integer, default=3, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # EC2 instance management
    ec2_instance_id  = Column(String, nullable=True)    # e.g. "i-0abc123def456"
    ec2_region       = Column(String, nullable=True)    # e.g. "ap-south-1"
    container_name   = Column(String, nullable=True)    # Docker container name e.g. "proctor1"
    container_port   = Column(Integer, nullable=True)   # 8000 or 8001

    assignments = relationship("ExamEngineAssignment", back_populates="container")


class ExamEngineAssignment(UUIDMixin, TimestampMixin, Base):
    """
    Maps a LIVE exam to the engine container(s) it owns.
    One container → exactly one LIVE exam at a time.
    One exam may own multiple containers (when it is the only LIVE exam).
    Released when the exam ends.
    """
    __tablename__ = "exam_engine_assignments"

    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.id"), nullable=False)
    container_id = Column(UUID(as_uuid=True), ForeignKey("engine_containers.id"), nullable=False)

    exam = relationship("Exam", back_populates="engine_assignments")
    container = relationship("EngineContainer", back_populates="assignments")

    __table_args__ = (
        Index("idx_engine_assign_exam", "exam_id"),
        Index("idx_engine_assign_container", "container_id"),
    )


class ProctorAlert(UUIDMixin, Base):
    """
    One row per proctoring alert event, written by the engine directly to RDS.
    Replaces polling engine's /session/{pc_id}/log and /report/{id} for alert history.
    """
    __tablename__ = "proctor_alerts"

    session_id  = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"), nullable=False, index=True)
    message     = Column(String, nullable=False)
    alert_key   = Column(String, nullable=True)          # e.g. "phone", "looking_away"
    elapsed_s   = Column(Float, nullable=False, default=0.0)
    time_str    = Column(String, nullable=True)          # "MM:SS" display string
    score_added = Column(Float, nullable=False, default=0.0)
    proof_s3_key = Column(String, nullable=True)         # S3 object key for proof image/audio
    proof_type  = Column(String, nullable=True)          # "image" | "audio"
    proof_size_bytes = Column(Integer, nullable=True)    # uploaded proof object size in bytes
    occurred_at = Column(DateTime, nullable=False, default=func.now())

    session = relationship("ExamSession", back_populates="proctor_alerts")

    __table_args__ = (
        Index("idx_proctor_alert_session", "session_id"),
    )


class ProctorWarning(UUIDMixin, Base):
    """
    One row per proctoring warning event, written by the engine directly to RDS.
    """
    __tablename__ = "proctor_warnings"

    session_id  = Column(UUID(as_uuid=True), ForeignKey("exam_sessions.id"), nullable=False, index=True)
    message     = Column(String, nullable=False)
    elapsed_s   = Column(Float, nullable=False, default=0.0)
    time_str    = Column(String, nullable=True)
    occurred_at = Column(DateTime, nullable=False, default=func.now())

    session = relationship("ExamSession", back_populates="proctor_warnings")

    __table_args__ = (
        Index("idx_proctor_warning_session", "session_id"),
    )


class EngineSettings(UUIDMixin, TimestampMixin, Base):
    """
    System-admin-controlled global engine configuration.
    Single row — updated in place. Created at startup with defaults if absent.
    Applied to every /proctor-connect request merged with the exam's detection_config.
    """
    __tablename__ = "engine_settings"

    # Head pose thresholds
    look_away_yaw = Column(Float, default=0.20, nullable=False)
    look_down_pitch = Column(Float, default=0.13, nullable=False)
    look_up_pitch = Column(Float, default=-0.10, nullable=False)
    gaze_left = Column(Float, default=-0.13, nullable=False)
    gaze_right = Column(Float, default=0.13, nullable=False)

    # Duration gates (seconds)
    looking_away_threshold = Column(Float, default=2.0, nullable=False)
    gaze_threshold = Column(Float, default=1.5, nullable=False)
    fake_window = Column(Float, default=15.0, nullable=False)

    # Risk scores
    gaze_score = Column(Float, default=5.0, nullable=False)
    phone_score_2nd = Column(Float, default=25.0, nullable=False)
    phone_score_3rd = Column(Float, default=50.0, nullable=False)
    book_score = Column(Float, default=20.0, nullable=False)
    headphone_score = Column(Float, default=20.0, nullable=False)
    earbud_score = Column(Float, default=20.0, nullable=False)
    tab_switch_score = Column(Float, default=15.0, nullable=False)
    multi_people_score_2nd = Column(Float, default=20.0, nullable=False)
    multi_people_score_3rd = Column(Float, default=50.0, nullable=False)
    no_person_score_1 = Column(Float, default=25.0, nullable=False)
    no_person_score_2 = Column(Float, default=50.0, nullable=False)
    fake_presence_score_1 = Column(Float, default=30.0, nullable=False)
    fake_presence_score_2 = Column(Float, default=60.0, nullable=False)

    # State thresholds
    state_warning = Column(Float, default=30.0, nullable=False)
    state_high_risk = Column(Float, default=60.0, nullable=False)
    state_admin_review = Column(Float, default=100.0, nullable=False)

    # Decay
    decay_amount = Column(Float, default=5.0, nullable=False)

    # Termination rules
    tab_switch_terminate_count = Column(Integer, default=3, nullable=False)
    multi_people_terminate_s = Column(Float, default=20.0, nullable=False)
    no_person_terminate_s = Column(Float, default=20.0, nullable=False)

    # YOLO confidence thresholds
    yolo_phone_conf = Column(Float, default=0.65, nullable=False)
    yolo_book_conf = Column(Float, default=0.70, nullable=False)
    yolo_audio_conf = Column(Float, default=0.41, nullable=False)
    yolo_person_conf = Column(Float, default=0.30, nullable=False)

    # Detection toggles
    detect_looking_away    = Column(Boolean, default=True, nullable=False)
    detect_looking_down    = Column(Boolean, default=True, nullable=False)
    detect_looking_up      = Column(Boolean, default=True, nullable=False)
    detect_looking_side    = Column(Boolean, default=True, nullable=False)
    detect_face_hidden     = Column(Boolean, default=True, nullable=False)
    detect_partial_face    = Column(Boolean, default=True, nullable=False)
    detect_fake_presence   = Column(Boolean, default=True, nullable=False)
    detect_speaker_audio   = Column(Boolean, default=True, nullable=False)
    detect_phone           = Column(Boolean, default=True, nullable=False)
    detect_book            = Column(Boolean, default=True, nullable=False)
    detect_headphone       = Column(Boolean, default=True, nullable=False)
    detect_earbud          = Column(Boolean, default=True, nullable=False)
    detect_multiple_people = Column(Boolean, default=True, nullable=False)

    # Duration gates
    partial_face_duration_gate = Column(Float, default=5.0, nullable=False)
    face_hidden_dur_1          = Column(Float, default=5.0, nullable=False)
    face_hidden_dur_2          = Column(Float, default=10.0, nullable=False)
    no_person_dur_1            = Column(Float, default=5.0, nullable=False)
    no_person_dur_2            = Column(Float, default=10.0, nullable=False)
    fake_presence_dur_1        = Column(Float, default=10.0, nullable=False)
    fake_presence_dur_2        = Column(Float, default=25.0, nullable=False)

    # Tiered scores (missing ones)
    partial_face_score   = Column(Float, default=2.0,  nullable=False)
    face_hidden_score_1  = Column(Float, default=10.0, nullable=False)
    face_hidden_score_2  = Column(Float, default=20.0, nullable=False)

    # Speaker audio
    speaker_warn_cooldown    = Column(Float, default=3.0,  nullable=False)
    speaker_alert_cooldown   = Column(Float, default=10.0, nullable=False)
    speaker_occ1_warn_s      = Column(Float, default=3.0,  nullable=False)
    speaker_occ1_score       = Column(Float, default=10.0, nullable=False)
    speaker_occ1_repeat      = Column(Float, default=20.0, nullable=False)
    speaker_occ2_warn_s      = Column(Float, default=5.0,  nullable=False)
    speaker_occ2_score       = Column(Float, default=20.0, nullable=False)
    speaker_occ2_repeat      = Column(Float, default=20.0, nullable=False)
    speaker_repeat_interval  = Column(Float, default=10.0, nullable=False)

    # Score cooldowns (per violation type, seconds)
    score_cd_looking_away    = Column(Float, default=5.0,  nullable=False)
    score_cd_looking_down    = Column(Float, default=5.0,  nullable=False)
    score_cd_looking_up      = Column(Float, default=5.0,  nullable=False)
    score_cd_looking_side    = Column(Float, default=5.0,  nullable=False)
    score_cd_partial_face    = Column(Float, default=5.0,  nullable=False)
    score_cd_face_hidden     = Column(Float, default=5.0,  nullable=False)
    score_cd_fake_presence   = Column(Float, default=10.0, nullable=False)
    score_cd_phone           = Column(Float, default=15.0, nullable=False)
    score_cd_multiple_people = Column(Float, default=10.0, nullable=False)
    score_cd_no_person       = Column(Float, default=10.0, nullable=False)
    score_cd_book            = Column(Float, default=30.0, nullable=False)
    score_cd_headphone       = Column(Float, default=30.0, nullable=False)
    score_cd_earbud          = Column(Float, default=30.0, nullable=False)
    score_cd_speaker_audio   = Column(Float, default=10.0, nullable=False)

    # Warning cooldowns (per violation type, seconds)
    warn_cd_looking_away     = Column(Float, default=3.0,  nullable=False)
    warn_cd_looking_down     = Column(Float, default=3.0,  nullable=False)
    warn_cd_looking_up       = Column(Float, default=3.0,  nullable=False)
    warn_cd_looking_side     = Column(Float, default=3.0,  nullable=False)
    warn_cd_partial_face     = Column(Float, default=3.0,  nullable=False)
    warn_cd_face_hidden      = Column(Float, default=3.0,  nullable=False)
    warn_cd_fake_presence    = Column(Float, default=5.0,  nullable=False)
    warn_cd_phone            = Column(Float, default=8.0,  nullable=False)
    warn_cd_multiple_people  = Column(Float, default=5.0,  nullable=False)
    warn_cd_no_person        = Column(Float, default=5.0,  nullable=False)
    warn_cd_book             = Column(Float, default=15.0, nullable=False)
    warn_cd_headphone        = Column(Float, default=15.0, nullable=False)
    warn_cd_earbud           = Column(Float, default=15.0, nullable=False)
    warn_cd_speaker_audio    = Column(Float, default=3.0,  nullable=False)

    # Head pose & detection sensitivity
    min_face_width           = Column(Integer, default=110, nullable=False)
    min_face_height          = Column(Integer, default=120, nullable=False)
    face_hidden_recency_s    = Column(Float, default=4.0,  nullable=False)

    # In-exam identity verification
    identity_check_count       = Column(Integer, default=5,   nullable=False)  # random checks per exam
    identity_check_retries     = Column(Integer, default=3,   nullable=False)  # retries after first silent fail
    identity_check_retry_delay = Column(Float,   default=5.0, nullable=False)  # seconds between retries

    # Object detection temporal voting (min votes to confirm detection within window)
    phone_min_votes     = Column(Integer, default=9,  nullable=False)
    book_min_votes      = Column(Integer, default=10, nullable=False)
    headphone_min_votes = Column(Integer, default=9,  nullable=False)
    earbud_min_votes    = Column(Integer, default=9,  nullable=False)
    object_min_votes    = Column(Integer, default=5,  nullable=False)
    object_window       = Column(Integer, default=15, nullable=False)
