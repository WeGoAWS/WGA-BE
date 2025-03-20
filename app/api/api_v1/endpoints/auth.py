# app/api/api_v1/endpoints/auth.py
from fastapi import APIRouter, Request, HTTPException, Depends, Form
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.integrations.base_client import OAuthError as BaseOAuthError
from app.core.config import settings
from typing import Optional

router = APIRouter()

# OAuth 클라이언트 등록
oauth = OAuth()

# AWS Cognito
oauth.register(
    name="cognito",
    authority=settings.COGNITO_DOMAIN,
    client_id=settings.COGNITO_CLIENT_ID,
    client_secret=settings.COGNITO_CLIENT_SECRET,
    server_metadata_url=f"{settings.COGNITO_DOMAIN}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"}
)

# GCP
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=settings.GCP_CLIENT_ID,
    client_secret=settings.GCP_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/cloud-platform"}
)

# Azure
oauth.register(
    name="azure",
    server_metadata_url=f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}/v2.0/.well-known/openid-configuration",
    client_id=settings.AZURE_CLIENT_ID,
    client_secret=settings.AZURE_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"}
)

@router.get("/login")
async def login(request: Request, provider: str = "cognito"):
    """
    사용자를 선택한 제공자의 로그인 페이지로 리다이렉트합니다.
    provider: 'cognito' (AWS), 'google' (GCP), 'azure' (Azure)
    """
    if provider not in ["cognito", "google", "azure"]:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    
    # 제공자별 리다이렉트 URI
    redirect_uri = {
        "cognito": settings.COGNITO_REDIRECT_URI,
        "google": settings.GCP_REDIRECT_URI,
        "azure": settings.AZURE_REDIRECT_URI
    }.get(provider)
    
    # 세션에 사용자가 선택한 공급자 저장
    request.session["oauth_provider"] = provider
    
    # 로그인 리다이렉션
    client = oauth.create_client(provider)
    return await client.authorize_redirect(request, redirect_uri, prompt="login")

@router.get("/authorize")
async def authorize(request: Request):
    """
    OAuth 제공자로부터 받은 인증 코드를 처리합니다.
    """
    # 기본값으로 cogntio를 사용
    provider = request.session.get("oauth_provider", "cognito")
    
    try:
        client = oauth.create_client(provider)
        token = await client.authorize_access_token(request)
    except (OAuthError, BaseOAuthError) as error:
        raise HTTPException(status_code=400, detail=f"Authentication error: {str(error)}")
    
    access_token = token.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Access token not found in response")
    
    print(f"Token: {token}")
        
    # 세션에 토큰 정보 저장
    request.session["id_token"] = token.get("id_token")
    request.session["access_token"] = access_token

    return RedirectResponse(url="/auth/")

@router.get("/logout")
async def logout(request: Request):
    # 제거 대상 키 목록 (기존 키와 _state_로 시작하는 키 모두 포함)
    keys_to_remove = []
    for key in request.session.keys():
        if key in ["user_info", "id_token", "access_token", "refresh_token", "provider", "oauth_provider", "oauth_state"] or key.startswith("_state_"):
            keys_to_remove.append(key)
    
    for key in keys_to_remove:
        request.session.pop(key)
    
    return RedirectResponse(url="/auth/")

@router.get("/")
async def index(request: Request):
    """
    현재 로그인 상태에 따라 사용자 정보를 반환하거나 로그인 안내 메시지를 출력합니다.
    """
    access_token = request.session.get("access_token")
    provider = request.session.get("oauth_provider", "unknown")
    
    if access_token:
        return JSONResponse({
            "message": f"Logged in with {provider}",
        })
    
    return JSONResponse({"message": "Hello, please login!"})

@router.post("/token-refresh")
async def refresh_token(request: Request):
    """
    토큰 갱신 엔드포인트 (필요시 구현)
    """
    provider = request.session.get("provider")
    refresh_token = request.session.get("refresh_token")
    
    if not provider or not refresh_token:
        raise HTTPException(status_code=400, detail="No active session or refresh token")
    
    # 여기에 provider별 토큰 갱신 로직 구현
    # 실제 구현은 각 제공자의 토큰 갱신 방식에 따라 달라짐
    
    return JSONResponse({"message": "Token refresh not implemented yet"})