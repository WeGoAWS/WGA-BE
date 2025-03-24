# app/api/api_v1/endpoints/cloudtrail.py
import json
import time
import random
from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.services.aws_service import get_aws_session
from app.services.aws_log_processor import analyze_log, analyze_policy, save_analysis_to_s3

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
async def analyze_cloudtrail_logs(
    request: Request, 
    max_results: int = Query(10, description="Maximum number of log events to analyze"),
    output_bucket_name: str = Query(None, description="Optional: S3 bucket to save analysis results"),
    output_file_key: str = Query(None, description="Optional: File key for analysis results in S3")
):
    """
    CloudTrail API에서 로그 이벤트를 가져와 분석합니다.
    
    각 로그 항목에 대해:
    1. 보안 위험도 평가
    2. IAM 정책 추천
    3. 이벤트 요약
    
    결과는 응답으로 반환되며, 선택적으로 S3 버킷에 저장될 수 있습니다.
    """
    # 로그인 확인    
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="ID token not found.")
    
    # 임시 AWS 세션 얻기
    session = get_aws_session(id_token)
    cloudtrail_client = session.client("cloudtrail")
    iam_client = session.client("iam")
    s3_client = session.client("s3") if output_bucket_name and output_file_key else None
    
    try:
        # CloudTrail API에서 로그 이벤트 가져오기
        events_response = cloudtrail_client.lookup_events(MaxResults=max_results)
        events = events_response.get("Events", [])
        
        if not events:
            return JSONResponse(content=jsonable_encoder({
                "message": "No CloudTrail events found for analysis"
            }))
        
        # 로그 항목 파싱 및 분석
        analysis_results = []
        for i, event in enumerate(events):
            # CloudTrail API 응답을 파싱하여 필요한 정보 추출
            event_dict = {
                "eventTime": event.get("EventTime").isoformat() if hasattr(event.get("EventTime"), "isoformat") else event.get("EventTime"),
                "eventName": event.get("EventName"),
                "eventSource": event.get("EventSource"),
                "awsRegion": event.get("AwsRegion"),
                "sourceIPAddress": event.get("SourceIPAddress"),
                "userIdentity": json.loads(event.get("CloudTrailEvent", "{}")).get("userIdentity", {})
            }
            
            # 사용자 ARN 추출
            user_arn = event_dict["userIdentity"].get("arn", "unknown")
            
            # 로그 분석 실행 - 각 API 호출 사이에 지연 추가
            if i > 0:
                # 요청 사이에 2-3초 지연
                time.sleep(random.uniform(2.0, 3.0))
                
            security_analysis = analyze_log(event_dict)
            
            # 두 번째 API 호출 전에 추가 지연
            time.sleep(random.uniform(2.0, 3.0))
            
            policy_recommendation = analyze_policy(event_dict, user_arn, iam_client)
            
            analysis_results.append({
                "log_event": event_dict,
                "user_arn": user_arn,
                "analysis_comment": security_analysis,
                "policy_recommendation": policy_recommendation
            })
        
        # 선택적으로 결과를 S3에 저장
        if s3_client and output_bucket_name and output_file_key:
            save_analysis_to_s3(s3_client, output_bucket_name, output_file_key, analysis_results)
            output_location = f"s3://{output_bucket_name}/{output_file_key}"
        else:
            output_location = None
        
        # 분석 결과 요약 생성
        summary = {
            "total_logs_analyzed": len(analysis_results),
            "users": list(set([result["user_arn"] for result in analysis_results])),
            "output_location": output_location
        }
        
        return JSONResponse(content=jsonable_encoder({
            "message": "CloudTrail logs analysis completed successfully",
            "summary": summary,
            "analysis_results": analysis_results
        }))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CloudTrail analysis error: {str(e)}")