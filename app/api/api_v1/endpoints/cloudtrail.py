# app/api/api_v1/endpoints/cloudtrail.py
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.services.aws_service import get_aws_session

router = APIRouter()

@router.get("/logs")
async def get_cloudtrail_logs(request: Request, max_results: int = 50):
    """
    로그인한 사용자의 인증 정보를 이용하여 AWS 임시 자격 증명을 받고,
    CloudTrail의 lookup_events API를 통해 로그 이벤트를 수집합니다.
    """
    # 로그인 확인
    if not request.session.get("user_info"):
        raise HTTPException(status_code=401, detail="User not logged in.")
    
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="ID token not found.")
    
    # 임시 AWS 세션 얻기
    session = get_aws_session(id_token)
    cloudtrail_client = session.client("cloudtrail")
    
    try:
        events_response = cloudtrail_client.lookup_events(MaxResults=max_results)
        events = events_response.get("Events", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CloudTrail lookup error: {str(e)}")
    
    return JSONResponse(content=jsonable_encoder({"CloudTrail_Events": events}))