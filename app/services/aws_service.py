# app/services/aws_service.py
import boto3
import datetime
from fastapi import HTTPException
from app.core.config import settings

def get_aws_session(id_token: str):
    login_provider = settings.COGNITO_DOMAIN.removeprefix("https://")
    cognito_identity = boto3.client("cognito-identity", region_name=settings.AWS_REGION)
    identity_response = cognito_identity.get_id(
        IdentityPoolId=settings.COGNITO_IDENTITY_POOL_ID,
        Logins={login_provider: id_token}
    )
    identity_id = identity_response.get("IdentityId")
    credentials_response = cognito_identity.get_credentials_for_identity(
        IdentityId=identity_id,
        Logins={login_provider: id_token}
    )
    creds = credentials_response.get("Credentials")
    if not creds:
        raise HTTPException(status_code=400, detail="Failed to obtain temporary credentials.")
    # datetime 객체를 ISO 포맷 문자열로 변환
    if "Expiration" in creds and isinstance(creds["Expiration"], (datetime.datetime,)):
        creds["Expiration"] = creds["Expiration"].isoformat()

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
        region_name=settings.AWS_REGION,
    )
    return session

def get_active_cloudtrail_s3_buckets(id_token: str) -> list:
    if not id_token:
        raise HTTPException(status_code=401, detail="User not logged in.")

    session = get_aws_session(id_token)
    cloudtrail_client = session.client("cloudtrail")

    try:
        trails = cloudtrail_client.describe_trails().get("trailList", [])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CloudTrail access error: {str(e)}")

    active_buckets = []
    for trail in trails:
        s3_bucket = trail.get("S3BucketName")
        if s3_bucket:
            try:
                # 각 트레일의 상태를 확인하여 로깅이 활성화되어 있는지 체크
                status = cloudtrail_client.get_trail_status(Name=trail.get("Name"))
                if status.get("IsLogging"):
                    active_buckets.append(s3_bucket)
            except Exception:
                # 개별 트레일 상태 조회 실패 시 해당 트레일은 건너뜁니다.
                continue

    return active_buckets