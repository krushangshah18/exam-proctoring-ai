# Pydantic models
from pydantic import BaseModel, EmailStr, Field
from fastapi import Form

# BASE USER SCHEMAS
class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=100)

class UserCreate(UserBase):
    password: str = Field(
        ..., 
        min_length=8,
        max_length=128,
        description="Strong Password"
    )

class UserStudentCreate(UserCreate):
    @classmethod
    def as_form(
        cls,
        email: EmailStr = Form(...),
        full_name: str = Form(...),
        password: str = Form(...),
    ):
        return cls(
            email=email,
            full_name=full_name,
            password=password,
        )

class UserAdminCreate(UserCreate):
    pass

class UserLogin(BaseModel):
    email: EmailStr
    password: str


# TOKEN SCHEMAS
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenPayload(BaseModel):
    sub: str
    type: str


#Password Management
class ChangePassword(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8,max_length=128,description="Strong Password")

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


#Refresh Token
class RefreshRequest(BaseModel):
    refresh_token: str


#Public Apply Schema
class AdminApplyRequest(BaseModel):
    full_name: str = Field(..., min_length=2)
    email: EmailStr

    organization: str | None = None
    contact_number: str | None = None

    reason: str = Field(..., min_length=10)

class AdminReviewRequest(BaseModel):
    approve: bool
    review_note: str | None = None

class AdminApplicationOut(BaseModel):
    id: str
    full_name: str
    email: str
    status: str
    created_at: str

class UpdateProfile(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
