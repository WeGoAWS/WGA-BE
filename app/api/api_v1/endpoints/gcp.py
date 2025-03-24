# app/api/api_v1/endpoints/gcp.py
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.services.gcp_service import get_gcp_client, list_gcp_logs
from app.core.config import settings

router = APIRouter()

@router.get("/logs")
async def get_gcp_logs(request: Request, max_results: int = 50):
    """
    로그인한 사용자의 인증 정보를 이용하여 GCP 인증을 수행하고,
    GCP 로그를 가져옵니다.
    """
    # 세션에서 인증 정보 가져오기
    provider = request.session.get("provider", "")
    token_info = {}
    
    # 로그인 확인
    if not request.session.get("user_info"):
        raise HTTPException(status_code=401, detail="User not logged in.")
    
    # 제공자가 GCP인 경우 access_token 사용, 그렇지 않으면 id_token 사용
    if provider == "google":
        token_info = {
            "access_token": request.session.get("access_token"),
            "refresh_token": request.session.get("refresh_token"),
            "provider": provider
        }
    else:
        token_info = request.session.get("id_token")
    
    # GCP 클라이언트 얻기
    gcp_client = get_gcp_client(token_info)
    
    try:
        # GCP 로그 가져오기
        logs = list_gcp_logs(gcp_client, max_results=max_results)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GCP logs lookup error: {str(e)}")
    
    return JSONResponse(content=jsonable_encoder({"GCP_Logs": logs}))

@router.get("/projects")
async def get_gcp_projects(request: Request):
    """
    사용자가 접근할 수 있는 GCP 프로젝트 목록을 가져옵니다.
    """
    # 세션에서 인증 정보 가져오기
    provider = request.session.get("provider", "")
    
    # 로그인 확인
    if not request.session.get("user_info"):
        raise HTTPException(status_code=401, detail="User not logged in.")
    
    # 제공자가 GCP인 경우 access_token 사용, 그렇지 않으면 id_token 사용
    if provider == "google":
        token_info = {
            "access_token": request.session.get("access_token"),
            "refresh_token": request.session.get("refresh_token"),
            "provider": provider
        }
    else:
        token_info = request.session.get("id_token")
    
    # GCP 클라이언트 가져오기
    try:
        from google.cloud import resourcemanager_v3
        
        # 리소스 매니저 클라이언트 생성 (프로젝트 목록용)
        # GCP 클라이언트 얻기와 동일한 인증 방식 사용
        client = get_gcp_client(token_info)
        
        # 리소스 매니저 클라이언트는 다른 방식으로 인증해야 할 수 있음
        # 서비스 계정 인증 방식 사용
        resource_client = resourcemanager_v3.ProjectsClient.from_service_account_json(
            settings.GCP_SERVICE_ACCOUNT_FILE
        )
        
        # 프로젝트 목록 가져오기
        projects = []
        for project in resource_client.list_projects():
            projects.append({
                "project_id": project.project_id,
                "name": project.name,
                "state": project.state.name
            })
        
        return JSONResponse(content=jsonable_encoder({"GCP_Projects": projects}))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GCP projects lookup error: {str(e)}")