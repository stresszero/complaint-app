from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr


class BaseComplaint(BaseModel):
    title: str
    description: str
    photo_url: str
    amount: float
