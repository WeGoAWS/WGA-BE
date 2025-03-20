# app/api/api_v1/endpoints/azure.py
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.services.azure_service import get_azure_client, query_azure_logs
from app.core.config import settings

router = APIRouter()

@router.get("/logs")
async def get_azure_logs(request: Request, max_results: int = 50):
    """
    로그인한 사용자의 인증 정보를 이용하여 Azure 인증을 수행하고,
    Azure Monitor 로그를 가져옵니다.
    """
    # 세션에서 인증 정보 가져오기
    provider = request.session.get("provider", "")
    
    # 로그인 확인
    if not request.session.get("user_info"):
        raise HTTPException(status_code=401, detail="User not logged in.")
    
    # 제공자가 Azure인 경우 모든 토큰 정보 사용, 그렇지 않으면 id_token 사용
    if provider == "azure":
        token_info = {
            "access_token": request.session.get("access_token"),
            "refresh_token": request.session.get("refresh_token"),
            "provider": provider
        }
    else:
        token_info = request.session.get("id_token")
    
    # Azure 클라이언트 얻기
    azure_client = get_azure_client(token_info)
    
    try:
        # Azure 로그 쿼리
        logs = query_azure_logs(azure_client, max_results=max_results)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Azure logs lookup error: {str(e)}")
    
    return JSONResponse(content=jsonable_encoder({"Azure_Logs": logs}))

@router.get("/resources")
async def get_azure_resources(request: Request):
    """
    사용자가 접근할 수 있는 Azure 리소스 목록을 가져옵니다.
    """
    # 세션에서 인증 정보 가져오기
    provider = request.session.get("provider", "")
    
    # 로그인 확인
    if not request.session.get("user_info"):
        raise HTTPException(status_code=401, detail="User not logged in.")
    
    # 제공자가 Azure인 경우 모든 토큰 정보 사용, 그렇지 않으면 id_token 사용
    if provider == "azure":
        token_info = {
            "access_token": request.session.get("access_token"),
            "refresh_token": request.session.get("refresh_token"),
            "provider": provider
        }
    else:
        token_info = request.session.get("id_token")
    
    try:
        from azure.mgmt.resource import ResourceManagementClient
        from azure.identity import ClientSecretCredential
        
        # Azure 인증 정보 (동일한 인증 흐름 사용)
        credential = ClientSecretCredential(
            tenant_id=settings.AZURE_TENANT_ID,
            client_id=settings.AZURE_CLIENT_ID,
            client_secret=settings.AZURE_CLIENT_SECRET
        )
        
        # 리소스 관리 클라이언트
        resource_client = ResourceManagementClient(credential, settings.AZURE_SUBSCRIPTION_ID)
        
        # 리소스 그룹 가져오기
        resource_groups = []
        for rg in resource_client.resource_groups.list():
            resource_groups.append({
                "name": rg.name,
                "location": rg.location,
                "provisioning_state": rg.properties.provisioning_state if hasattr(rg.properties, "provisioning_state") else None
            })
        
        return JSONResponse(content=jsonable_encoder({"Azure_Resources": resource_groups}))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Azure resources lookup error: {str(e)}")