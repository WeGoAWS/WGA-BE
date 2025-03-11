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
    client_kwargs={"scope": "email"}
)

@router.get("/login")
async def login(request: Request):
    """
    사용자를 Cognito 호스티드 UI 로그인 페이지로 리다이렉트합니다.
    """
    # 로그인 후 Cognito가 redirect_uri로 인증 코드를 전달합니다.
    redirect_uri = settings.COGNITO_REDIRECT_URI
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@router.get("/authorize")
async def authorize(request: Request):
    """
    Cognito가 리다이렉트한 후 authorization code를 받아 토큰으로 교환합니다.
    """
    try:
        token = await oauth.oidc.authorize_access_token(request)
    except OAuthError as error:
        raise HTTPException(status_code=400, detail=str(error))
    user = token.get("userinfo")
    request.session["user"] = dict(user) if user else {}
    return RedirectResponse(url="/")

@router.get("/logout")
async def logout(request: Request):
    """
    세션에서 사용자 정보를 삭제하여 로그아웃 처리합니다.
    """
    request.session.pop("user", None)
    return RedirectResponse(url="/")

@router.get("/")
async def index(request: Request):
    """
    현재 로그인 상태에 따라 사용자 정보를 반환하거나 로그인 안내 메시지를 출력합니다.
    """
    user = request.session.get("user")
    if user:
        return JSONResponse({"message": "Logged in", "user": user})
    return JSONResponse({"message": "Hello, please login!"})
