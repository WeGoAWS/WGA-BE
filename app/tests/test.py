# app/tests/test.py
from fastapi import Request, HTTPException, APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from app.services import aws_service

router= APIRouter()

@router.get("/aws/s3")
async def test_s3_access(request: Request):
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    s3_client = session.client("s3")
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"S3 access error: {str(e)}")
    return JSONResponse(content=jsonable_encoder({"S3_Buckets": buckets}))

@router.get("/aws/cloudtrail")
async def test_cloudtrail_access(request: Request):
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    cloudtrail_client = session.client("cloudtrail")
    try:
        trails = cloudtrail_client.describe_trails().get("trailList", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CloudTrail access error: {str(e)}")
    return JSONResponse({"CloudTrail_Trails": trails})

@router.get("/aws/iam")
async def test_iam_access(request: Request):
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    iam_client = session.client("iam")
    try:
        user_info = iam_client.get_user().get("User")
    except Exception as e:
        user_info = f"Error: {str(e)}"
    return JSONResponse({"IAM_User": user_info})

@router.get("/debug-session")
async def debug_session(request: Request):
    # 주의: 민감한 정보를 노출할 수 있으므로 개발 환경에서만 사용해야 합니다.
    return JSONResponse(request.session)
