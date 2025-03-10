from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User

router = APIRouter()

@router.get("/{user_id}")
def read_user(user_id: int, db: Session = Depends(get_db)):
    # 예시: DB에서 유저 가져오기
    return db.query(User).filter(User.id == user_id).first()
