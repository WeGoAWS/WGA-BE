import uvicorn
from fastapi import FastAPI
from app.api.api_v1.endpoints import user, item

app = FastAPI(title="My Fullstack App")

# 엔드포인트 등록
app.include_router(user.router, prefix="/users", tags=["Users"])
app.include_router(item.router, prefix="/items", tags=["Items"])

@app.get("/")
def root():
    return {"message": "Hello from FastAPI backend!"}

# 애플리케이션 실행
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",      
        host="0.0.0.0",
        port=8000,
        reload=True     # 코드 변경 시 자동으로 서버 재시작
    )