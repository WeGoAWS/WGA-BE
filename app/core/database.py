# app/core/database.py
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

# MongoDB 클라이언트 초기화
client = AsyncIOMotorClient(settings.MONGODB_URI)
db = client[settings.MONGODB_DB_NAME]