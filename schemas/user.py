from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    email: Optional[EmailStr] = None


class UserCreate(UserBase):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserUpdate(UserBase):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)


class UserInDBBase(UserBase):
    id: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class User(UserInDBBase):
    pass