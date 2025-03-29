# app/main.py
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.api.api_v1.endpoints import user, bedrock, auth, cloudtrail, gcp, azure, policy_recommendation
from app.tests import test

app = FastAPI(title="Multi-Cloud Logs Analysis")

# 세션 미들웨어 추가 (비밀키는 운영 환경에서 안전하게 관리하세요)
app.add_middleware(SessionMiddleware, secret_key="temporary_secret_key_1234567890")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# 엔드포인트 등록
app.include_router(user.router, prefix="/users", tags=["Users"])
app.include_router(bedrock.router, prefix="/bedrock", tags=["Bedrock"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(test.router, prefix="/test", tags=["Test"])
app.include_router(cloudtrail.router, prefix="/cloudtrail", tags=["CloudTrail Logs"])
app.include_router(gcp.router, prefix="/gcp", tags=["GCP Logs"])
app.include_router(azure.router, prefix="/azure", tags=["Azure Logs"])
app.include_router(policy_recommendation.router, prefix="/policy-recommendation", tags=["IAM Policy Recommendations"])

@app.get("/")
def root():
    return {"message": "Multi-Cloud Logs Analysis API"}

# 애플리케이션 실행
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",      
        host="0.0.0.0",
        port=8000,
        reload=True     # 코드 변경 시 자동으로 서버 재시작
    )