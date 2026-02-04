import enum

class UserRole(str, enum.Enum):
    STUDENT = "STUDENT"
    ADMIN = "ADMIN"
    SYSADMIN = "SYSADMIN"

class ExamMode(str,enum.Enum):
    FLEXIBLE = "FLEXIBLE"
    FIXED = "FIXED"

class ExamStatus(str,enum.Enum):
    DRAFT = "DRAFT"
    LIVE = "LIVE"
    ENDED = "ENDED"
    CANCELLED = "CANCELLED"

class SessionStatus(str,enum.Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"
    ENDED = "ENDED"
    TERMINATED = "TERMINATED" 

class ResumeStatus(str,enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"

class VerdictType(str,enum.Enum):
    CONFIRMED = "CONFIRMED"
    REVIEW = "REVIEW"
    REJECTED = "REJECTED"

class ViolationSeverity(str,enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class TerminatedBy(str,enum.Enum):
    SYSTEM = "SYSTEM"
    ADMIN = "ADMIN"

class LateJoinPolicy(str, enum.Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"

class ModelVerdict(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"