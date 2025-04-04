# app/api/api_v1/endpoints/auth.py
from jose import jwk, jwt
from jose.utils import base64url_decode
import json
import time
import urllib.request
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from app.core.config import settings
from app.models.auth import TokenVerifyRequest
from app.services.user_service import store_cognito_user_info

router = APIRouter()

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
                
            except KeyError as e:
                raise HTTPException(status_code=401, detail=f'Missing required claim: {str(e)}')
            except Exception as e:
                raise HTTPException(status_code=401, detail=f'Error validating claims: {str(e)}')
            
        # GCP 또는 Azure 토큰 검증 로직도 필요하다면 이곳에 추가

        # 검증 성공 시 세션에 토큰 저장
        request.session.clear()  # 기존 세션 데이터 모두 삭제
        request.session["id_token"] = id_token
        request.session["oauth_provider"] = token_data.provider
        
        response = JSONResponse({"status": "success", "message": "Token verified successfully"})
    
        return response
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")