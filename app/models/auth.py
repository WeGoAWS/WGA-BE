# app/models/auth.py
from pydantic import BaseModel

# 로그인 요청과 응답 모델 정의
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    id_token: str
    access_token: str
    refresh_token: str

class TokenVerifyRequest(BaseModel):
    id_token: str
    access_token: str = None
    refresh_token: str = None
    provider: str = "cognito"