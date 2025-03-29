# app/api/api_v1/endpoints/auth.py
import boto3
from jose import jwk, jwt
from jose.utils import base64url_decode
import json
import time
import urllib.request
from fastapi import APIRouter, Request, HTTPException, Depends, Form
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.integrations.base_client import OAuthError as BaseOAuthError
from app.core.config import settings
from app.models.auth import TokenVerifyRequest
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

@router.post("/verify-token")
async def verify_token(request: Request, token_data: TokenVerifyRequest):
    """
    프론트엔드에서 받은 토큰을 검증하고 유효한 경우 세션에 저장합니다.
    """
    print(token_data)
    if token_data.provider not in ["cognito", "google", "azure"]:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    
    id_token = token_data.id_token
    
    try:
        # 토큰 검증 - AWS Cognito
        if token_data.provider == "cognito":
            # Cognito 사용자 풀 정보
            region = settings.AWS_REGION
            user_pool_id = settings.USER_POOL_ID
            client_id = settings.COGNITO_CLIENT_ID
            
            # JWT 토큰 검증을 위한 공개키 가져오기
            keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
            
            try:
                with urllib.request.urlopen(keys_url) as f:
                    response = f.read()
                keys = json.loads(response.decode('utf-8'))['keys']
            except Exception as e:
                raise HTTPException(status_code=401, detail=f'Failed to fetch JWKS: {str(e)}')
            
            # JWT 토큰 헤더 디코딩
            try:
                headers = jwt.get_unverified_headers(id_token)
                kid = headers['kid']
            except Exception as e:
                raise HTTPException(status_code=401, detail=f'Invalid JWT headers: {str(e)}')
            
            # 검증할 키 찾기
            key_index = -1
            for i in range(len(keys)):
                if kid == keys[i]['kid']:
                    key_index = i
                    break
            
            if key_index == -1:
                raise HTTPException(status_code=401, detail='Public key not found in jwks.json')
            
            # 공개키 가져오기
            try:
                public_key = jwk.construct(keys[key_index])
            except Exception as e:
                raise HTTPException(status_code=401, detail=f'Failed to construct public key: {str(e)}')
            
            # 토큰 서명 검증
            try:
                message, encoded_signature = id_token.rsplit('.', 1)
                decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
                
                # 서명 검증 수행
                is_verified = public_key.verify(message.encode("utf8"), decoded_signature)
                
                if not is_verified:
                    raise HTTPException(status_code=401, detail='Signature verification failed')
            except Exception as e:
                raise HTTPException(status_code=401, detail=f'Signature verification error: {str(e)}')
            
            # 클레임 검증
            try:
                claims = jwt.get_unverified_claims(id_token)
                
                # 만료 시간 확인
                current_time = time.time()
                expiration_time = claims['exp']
                
                if current_time > expiration_time:
                    raise HTTPException(status_code=401, detail='Token is expired')
                
                # 발행자 확인
                expected_issuer = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}'
                actual_issuer = claims['iss']
                
                if actual_issuer != expected_issuer:
                    raise HTTPException(status_code=401, detail='Token was not issued by expected provider')
                
                # 클라이언트 ID 확인
                if claims['aud'] != client_id and claims.get('client_id') != client_id:
                    raise HTTPException(status_code=401, detail='Token was not issued for this client')
                
                # ID 토큰에서 직접 사용자 정보 추출
                # 이제 GetUser API 호출 대신 ID 토큰의 클레임에서 사용자 정보를 가져옵니다
                user_attributes = {}
                
                # 일반적으로 사용되는 Cognito 속성 매핑
                attribute_mapping = {
                    "sub": "sub",
                    "email": "email",
                    "email_verified": "email_verified",
                    "username": "cognito:username",
                    "name": "name",
                    "given_name": "given_name",
                    "family_name": "family_name",
                    "preferred_username": "preferred_username",
                    "groups": "cognito:groups",
                    "roles": "cognito:roles"
                }
                
                # 클레임에서 사용자 속성 추출
                for attr_name, claim_name in attribute_mapping.items():
                    if claim_name in claims:
                        user_attributes[attr_name] = claims[claim_name]
                
                # 사용자 정보를 세션에 저장
                request.session["user_info"] = {
                    "username": claims.get("cognito:username", claims.get("sub")),
                    "attributes": user_attributes
                }
                
            except KeyError as e:
                raise HTTPException(status_code=401, detail=f'Missing required claim: {str(e)}')
            except Exception as e:
                raise HTTPException(status_code=401, detail=f'Error validating claims: {str(e)}')
            
        # GCP 또는 Azure 토큰 검증 로직도 필요하다면 이곳에 추가
        
        # 검증 성공 시 세션에 토큰 저장
        request.session["id_token"] = id_token
        if token_data.access_token:
            request.session["access_token"] = token_data.access_token
        if token_data.refresh_token:
            request.session["refresh_token"] = token_data.refresh_token
        request.session["oauth_provider"] = token_data.provider
        
        response = JSONResponse({"status": "success", "message": "Token verified successfully"})

        print("Response headers:", response.headers)
    
        return response
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")