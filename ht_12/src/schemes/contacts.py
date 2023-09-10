from datetime import date
# from typing import List

from pydantic import BaseModel, Field, EmailStr
from pydantic_extra_types.phone_numbers import PhoneNumber


class ContactModel(BaseModel):
    first_name: str = Field(min_length=3, max_length=25)
    last_name: str = Field(min_length=4, max_length=30)
    email: EmailStr
    phone_number: PhoneNumber
    birth_date: date = None
    notes: str


class ContactResponse(BaseModel):
    id: int = 1
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: PhoneNumber
    birth_date: date = None
    notes: str

    class Config:
        from_attributes = True
