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
    hard_join_deadline: datetime

    flag_threshold: int = Field(default=30, ge=0)

    late_join_policy: LateJoinPolicy = LateJoinPolicy.REVIEW
    allow_late_extension: bool = False
    max_late_minutes: int = Field(default=0, ge=0)

    config: MonitoringConfig

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

    @validator("hard_join_deadline")
    def deadline_in_window(cls, v, values):
        start = values.get("start_window")
        end = values.get("end_window")
        if start and end:
            if v < start or v > end:
                raise ValueError("hard_join_deadline must be between start_window and end_window")
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
    hard_join_deadline: datetime

    flag_threshold: int = Field(default=30, ge=0)

    late_join_policy: LateJoinPolicy = LateJoinPolicy.REVIEW
    allow_late_extension: bool = False
    max_late_minutes: int = Field(default=0, ge=0)

    config: MonitoringConfig

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

    @validator("hard_join_deadline")
    def deadline_in_window(cls, v, values):
        start = values.get("start_window")
        end = values.get("end_window")
        if start and end:
            if v < start or v > end:
                raise ValueError("hard_join_deadline must be between start_window and end_window")
        return v

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

    class Config:
        from_attributes = True


class ExamDetailResponse(ExamListResponse):
    hard_join_deadline: datetime
    flag_threshold: int
    late_join_policy: str
    allow_late_extension: bool
    max_late_minutes: int
    config: dict
    invites: List[ExamInviteResponse] = []

    class Config:
        from_attributes = True
