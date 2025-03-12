# app/api/api_v1/endpoints/user.py
from fastapi import APIRouter, HTTPException
from app.core.database import db
from app.models.user import UserCreate, User
from bson import ObjectId

router = APIRouter()

@router.post("/", response_model=User)
async def create_user(user_create: UserCreate):
    # users 컬렉션
    user_collection = db["users"]
    
    # username 중복 체크 예시
    existing_user = await user_collection.find_one({"username": user_create.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    # MongoDB에 삽입
    new_user = {
        "username": user_create.username,
        "email": user_create.email
    }
    result = await user_collection.insert_one(new_user)

    # _id를 포함해 다시 가져오기
    created_user = await user_collection.find_one({"_id": result.inserted_id})

    # ObjectId → 문자열 변환
    created_user["_id"] = str(created_user["_id"])
    
    # pydantic User 모델에 맞춰 반환
    return User(**created_user)

@router.get("/{user_id}", response_model=User)
async def get_user(user_id: str):
    user_collection = db["users"]
    doc = await user_collection.find_one({"_id": ObjectId(user_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Python dict로 가져온 doc["_id"]를 str로 변환
    doc["_id"] = str(doc["_id"])
    
    return User(**doc)
