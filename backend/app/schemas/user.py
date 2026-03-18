from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    role: str
    organization: str = Field(min_length=2, max_length=120)
    purpose: str = Field(min_length=20, max_length=500)
    job_title: str = Field(min_length=2, max_length=80)
    phone: str = Field(min_length=8, max_length=20)


class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str

    class Config:
        from_attributes = True


class UserProfileOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    full_name: str
    organization: str
    purpose: str
    job_title: str
    phone: str
