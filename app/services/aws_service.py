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