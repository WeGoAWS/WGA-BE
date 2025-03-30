# app/api/api_v1/endpoints/cloudtrail.py
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.services.aws_service import * 
from app.services.aws_log_processor import process_logs

router = APIRouter()

@router.get("/logs")
async def get_cloudtrail_logs(request: Request, max_results: int = 50):
    """
    로그인한 사용자의 인증 정보를 이용하여 AWS 임시 자격 증명을 받고,
    CloudTrail의 lookup_events API를 통해 로그 이벤트를 수집합니다.
    """
    # 로그인 확인    
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

@router.get("/analyze-logs")
async def analyze_cloudtrail_logs(request: Request):
    """
    분석 결과를 지정된 S3 버킷에 업로드합니다.
    """
    # 세션을 통한 인증 확인 (필요 시 추가 처리)
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="ID token not found.")

    # cloudtrail 추적이 활성화된 s3 버킷 리스트
    s3_bucket = get_active_cloudtrail_s3_buckets(id_token)

    # process_logs 함수를 호출하여 로그 분석 진행 및 결과 S3 업로드
    try:
        result = process_logs(s3_bucket)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"로그 분석 실패: {str(e)}")
    return JSONResponse(content=jsonable_encoder({
        "message": "CloudTrail 로그 분석이 성공적으로 완료되었습니다.",
        "result": result
    }))