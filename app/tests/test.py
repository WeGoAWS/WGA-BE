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
    
    # 특정 CloudTrail 버킷에만 접근 테스트
    cloudtrail_bucket = "aws-cloudtrail-logs-248189903808-6efbc744"
    
    results = {
        "bucket_name": cloudtrail_bucket,
        "tests": {}
    }
    
    # 테스트 1: 버킷 위치 확인
    try:
        location = s3_client.get_bucket_location(Bucket=cloudtrail_bucket)
        results["tests"]["get_bucket_location"] = {
            "status": "Access Granted",
            "result": location
        }
    except Exception as e:
        results["tests"]["get_bucket_location"] = {
            "status": "Access Denied",
            "error": str(e),
            "error_type": type(e).__name__
        }
    
    # 테스트 2: 버킷 내 객체 리스팅
    try:
        objects = s3_client.list_objects_v2(
            Bucket=cloudtrail_bucket,
            MaxKeys=5  # 최대 5개만 가져오기
        )
        
        if "Contents" in objects:
            results["tests"]["list_objects"] = {
                "status": "Access Granted",
                "count": len(objects.get("Contents", [])),
                "sample": [obj["Key"] for obj in objects.get("Contents", [])[:2]]  # 처음 2개만 표시
            }
        else:
            results["tests"]["list_objects"] = {
                "status": "Access Granted",
                "count": 0,
                "message": "Bucket exists but is empty or you don't have permission to see contents"
            }
    except Exception as e:
        results["tests"]["list_objects"] = {
            "status": "Access Denied",
            "error": str(e),
            "error_type": type(e).__name__
        }
    
    # 테스트 3: 버킷 정책 확인
    try:
        policy = s3_client.get_bucket_policy(Bucket=cloudtrail_bucket)
        results["tests"]["get_bucket_policy"] = {
            "status": "Access Granted",
            "has_policy": "Policy" in policy
        }
    except Exception as e:
        results["tests"]["get_bucket_policy"] = {
            "status": "Access Denied",
            "error": str(e),
            "error_type": type(e).__name__
        }
    
    return JSONResponse(content=jsonable_encoder(results))

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

# 새로 추가된 테스트 엔드포인트들 - 권한이 없는 서비스 접근 테스트

@router.get("/aws/ec2")
async def test_ec2_access(request: Request):
    """EC2 서비스 접근 테스트 - 권한이 없을 것으로 예상"""
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    ec2_client = session.client("ec2")
    try:
        instances = ec2_client.describe_instances()
        return JSONResponse({"EC2_Instances": "Access granted - This might indicate too many permissions"})
    except Exception as e:
        return JSONResponse({
            "EC2_Access": "Denied - Expected behavior",
            "Error_Message": str(e),
            "Error_Type": type(e).__name__
        })

@router.get("/aws/dynamodb")
async def test_dynamodb_access(request: Request):
    """DynamoDB 서비스 접근 테스트 - 권한이 없을 것으로 예상"""
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    dynamodb_client = session.client("dynamodb")
    try:
        tables = dynamodb_client.list_tables()
        return JSONResponse({"DynamoDB_Tables": "Access granted - This might indicate too many permissions"})
    except Exception as e:
        return JSONResponse({
            "DynamoDB_Access": "Denied - Expected behavior",
            "Error_Message": str(e),
            "Error_Type": type(e).__name__
        })

@router.get("/aws/lambda")
async def test_lambda_access(request: Request):
    """Lambda 서비스 접근 테스트 - 권한이 없을 것으로 예상"""
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    lambda_client = session.client("lambda")
    try:
        functions = lambda_client.list_functions()
        return JSONResponse({"Lambda_Functions": "Access granted - This might indicate too many permissions"})
    except Exception as e:
        return JSONResponse({
            "Lambda_Access": "Denied - Expected behavior",
            "Error_Message": str(e),
            "Error_Type": type(e).__name__
        })

@router.get("/aws/sqs")
async def test_sqs_access(request: Request):
    """SQS 서비스 접근 테스트 - 권한이 없을 것으로 예상"""
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    session = aws_service.get_aws_session(id_token)
    sqs_client = session.client("sqs")
    try:
        queues = sqs_client.list_queues()
        return JSONResponse({"SQS_Queues": "Access granted - This might indicate too many permissions"})
    except Exception as e:
        return JSONResponse({
            "SQS_Access": "Denied - Expected behavior",
            "Error_Message": str(e),
            "Error_Type": type(e).__name__
        })

@router.get("/aws/permissions-test")
async def test_all_services(request: Request):
    """여러 AWS 서비스에 대한 접근 권한을 한 번에 테스트"""
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")
    
    session = aws_service.get_aws_session(id_token)
    
    # 사용자 정보 가져오기
    try:
        sts_client = session.client('sts')
        user_identity = sts_client.get_caller_identity()
    except Exception as e:
        user_identity = {"Error": str(e)}
    
    results = {}
    
    # S3 테스트 - 특정 CloudTrail 버킷만 테스트
    cloudtrail_bucket = "aws-cloudtrail-logs-248189903808-6efbc744"
    s3_client = session.client("s3")
    try:
        # 테스트: 버킷 내 객체 리스팅
        objects = s3_client.list_objects_v2(
            Bucket=cloudtrail_bucket,
            MaxKeys=1  # 단일 객체만 확인
        )
        results["s3"] = {
            "status": "Access Granted",
            "bucket": cloudtrail_bucket,
            "has_contents": "Contents" in objects and len(objects.get("Contents", [])) > 0,
            "expected_for_app": True
        }
    except Exception as e:
        results["s3"] = {
            "status": "Access Denied",
            "bucket": cloudtrail_bucket,
            "error": str(e),
            "error_type": type(e).__name__,
            "expected_for_app": True
        }
    
    # 나머지 서비스 테스트
    other_services = [
        {"name": "cloudtrail", "method": "describe_trails", "params": {}},
        {"name": "iam", "method": "get_user", "params": {}},
        {"name": "ec2", "method": "describe_instances", "params": {}},
        {"name": "dynamodb", "method": "list_tables", "params": {}},
        {"name": "lambda", "method": "list_functions", "params": {}},
        {"name": "sqs", "method": "list_queues", "params": {}}
    ]
    
    for service in other_services:
        try:
            client = session.client(service["name"])
            method = getattr(client, service["method"])
            response = method(**service["params"])
            results[service["name"]] = {
                "status": "Access Granted",
                "expected_for_app": service["name"] in ["cloudtrail", "iam"]
            }
        except Exception as e:
            results[service["name"]] = {
                "status": "Access Denied",
                "error": str(e),
                "error_type": type(e).__name__,
                "expected_for_app": service["name"] in ["cloudtrail", "iam"]
            }
    
    # Bedrock 테스트 추가
    try:
        bedrock_client = session.client("bedrock-runtime")
        results["bedrock-runtime"] = {
            "status": "Client Created Successfully",
            "expected_for_app": True
        }
        
        # 실제 모델 호출 테스트는 여기서 구현할 수 있습니다
        # 예: bedrock_client.invoke_model() 
    except Exception as e:
        results["bedrock-runtime"] = {
            "status": "Access Denied or Service Unavailable",
            "error": str(e),
            "error_type": type(e).__name__,
            "expected_for_app": True
        }
    
    # 사용자 정보 추가
    results["user_info"] = user_identity
    
    return JSONResponse(content=jsonable_encoder(results))

@router.get("/debug-session")
async def debug_session(request: Request):
    session_id = request.cookies.get('session')
    print(f"Session ID during debug: {session_id}")
    return {"session_data": dict(request.session)}