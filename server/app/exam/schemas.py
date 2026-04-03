from typing import List
from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime, timezone

from app.db.enums import ExamMode, LateJoinPolicy, ExamStatus


class MonitoringConfig(BaseModel):
    eye_gaze: bool = True
    looking_away: bool = True
    static_photo: bool = True
    phone_detected: bool = True
    book_detected: bool = True
    earphones: bool = True
    audio_analysis: bool = True
    multiple_person: bool = True
    tab_switching: bool = True


class DetectionConfig(BaseModel):
    """
    Per-exam AI detection toggles — controlled by the exam admin.
    Sent to the proctoring engine on each student's WebRTC handshake.
    All 13 flags default to True (fully enabled).
    """
    # Head & Gaze
    DETECT_LOOKING_AWAY:    bool = True
    DETECT_LOOKING_DOWN:    bool = True
    DETECT_LOOKING_UP:      bool = True
    DETECT_LOOKING_SIDE:    bool = True
    # Presence
    DETECT_FACE_HIDDEN:     bool = True
    DETECT_PARTIAL_FACE:    bool = True
    DETECT_FAKE_PRESENCE:   bool = True
    # Audio
    DETECT_SPEAKER_AUDIO:   bool = True
    # Objects
    DETECT_PHONE:           bool = True
    DETECT_BOOK:            bool = True
    DETECT_HEADPHONE:       bool = True
    DETECT_EARBUD:          bool = True
    DETECT_MULTIPLE_PEOPLE: bool = True


def _make_utc_aware(v):
    """Ensure a datetime is UTC-aware."""
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)
    return v


class ExamCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=150)

    exam_mode: ExamMode

    start_window: datetime
    end_window: datetime
    duration_minutes: int = Field(..., gt=0)
    # FLEXIBLE: backend auto-derives as end_window − duration; FIXED: admin-provided
    hard_join_deadline: datetime | None = None

    flag_threshold: int = Field(default=3, ge=0)

    late_join_policy: LateJoinPolicy = LateJoinPolicy.REVIEW
    # FIXED mode: always forced False by backend
    allow_late_extension: bool = False
    max_late_minutes: int = Field(default=0, ge=0)

    config: MonitoringConfig

    # AI proctoring engine detection toggles (exam admin controlled)
    detection_config: DetectionConfig = Field(default_factory=DetectionConfig)

    invites: List[EmailStr] = Field(default_factory=list)

    @validator("start_window", "end_window", "hard_join_deadline", pre=True, always=True)
    def ensure_utc_aware(cls, v):
        return _make_utc_aware(v)

    @validator("end_window")
    def end_must_be_after_start(cls, v, values):
        start = values.get("start_window")
        if start and v <= start:
            raise ValueError("end_window must be after start_window")
        return v

    @validator("invites", each_item=True)
    def lowercase_emails(cls, v):
        return v.lower()

    @validator("invites")
    def at_least_one_invite(cls, v):
        if len(v) < 1:
            raise ValueError("At least one student must be invited")
        return v


class ExamUpdateRequest(BaseModel):
    """
    Separate from ExamCreateRequest to avoid applying start_window future
    validation on updates (the 15-minute edit lock in the route handles that).
    """
    title: str = Field(..., min_length=3, max_length=150)

    exam_mode: ExamMode

    start_window: datetime
    end_window: datetime
    duration_minutes: int = Field(..., gt=0)
    # FLEXIBLE: backend auto-derives as end_window − duration; FIXED: admin-provided
    hard_join_deadline: datetime | None = None

    flag_threshold: int = Field(default=3, ge=0)

    late_join_policy: LateJoinPolicy = LateJoinPolicy.REVIEW
    allow_late_extension: bool = False
    max_late_minutes: int = Field(default=0, ge=0)

    config: MonitoringConfig

    # AI proctoring engine detection toggles (exam admin controlled)
    detection_config: DetectionConfig = Field(default_factory=DetectionConfig)

    invites: List[EmailStr] = Field(default_factory=list)

    @validator("start_window", "end_window", "hard_join_deadline", pre=True, always=True)
    def ensure_utc_aware(cls, v):
        return _make_utc_aware(v)

    @validator("end_window")
    def end_must_be_after_start(cls, v, values):
        start = values.get("start_window")
        if start and v <= start:
            raise ValueError("end_window must be after start_window")
        return v

    @validator("invites", each_item=True)
    def lowercase_emails(cls, v):
        return v.lower()

    @validator("invites")
    def at_least_one_invite(cls, v):
        if len(v) < 1:
            raise ValueError("At least one student must be invited")
        return v


class ExamInviteAddRequest(BaseModel):
    invites: List[EmailStr] = Field(default_factory=list)

    @validator("invites", each_item=True)
    def lowercase_emails(cls, v):
        return v.lower()

    @validator("invites")
    def at_least_one_invite(cls, v):
        if len(v) < 1:
            raise ValueError("At least one student must be invited")
        return v


class ExamListResponse(BaseModel):
    id: str
    title: str
    exam_mode: str
    status: str
    start_window: datetime
    end_window: datetime
    duration_minutes: int
    created_at: datetime
    invite_count: int = 0

    class Config:
        from_attributes = True


class ExamInviteResponse(BaseModel):
    id: str
    student_email: str
    token: str
    expires_at: datetime
    used: bool
    session_status: str | None = None

    class Config:
        from_attributes = True


class ExamDetailResponse(ExamListResponse):
    hard_join_deadline: datetime
    flag_threshold: int
    late_join_policy: str
    allow_late_extension: bool
    max_late_minutes: int
    config: dict
    detection_config: dict | None = None
    invites: List[ExamInviteResponse] = []

    class Config:
        from_attributes = True
