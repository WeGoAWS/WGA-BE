import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
from app.core.config import settings

router = APIRouter()

# OAuth 클라이언트 등록 (OIDC)
oauth = OAuth()
oauth.register(
    name="oidc",
    authority=settings.COGNITO_DOMAIN,
    client_id=settings.COGNITO_CLIENT_ID,
    client_secret=settings.COGNITO_CLIENT_SECRET,
    server_metadata_url=f"{settings.COGNITO_DOMAIN}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"}
)

@router.get("/login")
async def login(request: Request):
    """
    사용자를 Cognito 호스티드 UI 로그인 페이지로 리다이렉트합니다.
    """
    # 로그인 후 Cognito가 redirect_uri로 인증 코드를 전달합니다.
    redirect_uri = settings.COGNITO_REDIRECT_URI
    return await oauth.oidc.authorize_redirect(request, redirect_uri, prompt="login")

@router.get("/authorize")
async def authorize(request: Request):
    try:
        token = await oauth.oidc.authorize_access_token(request)
    except OAuthError as error:
        raise HTTPException(status_code=400, detail=str(error))
    
    # token 응답에 id_token이 없다면 access_token을 사용해서 userinfo endpoint를 호출합니다.
    access_token = token.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Access token not found in response")

    userinfo_endpoint = oauth.oidc.server_metadata.get("userinfo_endpoint")
    async with httpx.AsyncClient() as client:
        r = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail="Failed to fetch user info")
        user = r.json()
    
    # 세션에 사용자 정보 저장
    request.session["user"] = dict(user) if user else {}
    return RedirectResponse(url="/auth/")

@router.get("/logout")
async def logout(request: Request):
    """
    세션에서 사용자 정보를 삭제하여 로그아웃 처리합니다.
    """
    request.session.pop("user", None)
    return RedirectResponse(url="/auth/")

@router.get("/")
async def index(request: Request):
    """
    현재 로그인 상태에 따라 사용자 정보를 반환하거나 로그인 안내 메시지를 출력합니다.
    """
    user = request.session.get("user")
    if user:
        return JSONResponse({"message": "Logged in", "user": user})
    return JSONResponse({"message": "Hello, please login!"})
