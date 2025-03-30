# app/services/user_service.py

from fastapi.encoders import jsonable_encoder
from app.core.database import db

async def store_cognito_user_info(id_token: str, claims: dict, provider: str = "cognito"):
    """
    Cognito 사용자의 JWT 토큰 정보와 클레임(유저 정보)을 MongoDB에 저장합니다.

    매개변수:
        id_token: 검증된 JWT 토큰 문자열
        claims: 토큰의 디코딩된 클레임 정보 (예: sub, email, iss, exp 등)
        provider: OAuth 제공자 정보, 기본값은 'cognito'
    
    반환값:
        데이터베이스에 저장(업데이트 또는 삽입)한 결과
    """
    user_id = claims.get("sub")
    if not user_id:
        raise ValueError("Token claims에 'sub' 필드가 없습니다.")

    user_data = {
        "sub": user_id,
        "email": claims.get("email"),
        "issuer": claims.get("iss"),
        "token": id_token,
        "provider": provider,
        "claims": claims  # 추가적인 클레임 정보를 함께 저장합니다.
    }

    # JSON 직렬화를 수행합니다.
    data = jsonable_encoder(user_data)

    # 기존에 해당 사용자가 저장되어 있는지 확인한 후,
    # 있으면 업데이트, 없으면 새로 삽입합니다.
    existing_user = await db.users.find_one({"sub": user_id})
    if existing_user:
        result = await db.users.update_one({"sub": user_id}, {"$set": data})
    else:
        result = await db.users.insert_one(data)

    return result
