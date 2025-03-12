# app/models/user.py
from pydantic import BaseModel, Field
from typing import Optional

class UserCreate(BaseModel):
    username: str
    email: str

class User(BaseModel):
    id: str = Field(alias="_id")  # MongoDB _id를 string으로 변환
    username: str
    email: str

    class Config:
        allow_population_by_field_name = True
