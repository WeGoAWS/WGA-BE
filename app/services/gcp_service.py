# app/services/gcp_service.py
from google.oauth2 import id_token as google_id_token
from google.oauth2.credentials import Credentials
from google.auth.transport import requests
from google.cloud import logging
from fastapi import HTTPException
from app.core.config import settings

def get_gcp_client(token_info):
    """
    인증 토큰을 사용하여 GCP 클라이언트를 생성합니다.
    
    token_info: id_token 또는 access_token 정보
    """
    try:
        # 1. OAuth 토큰으로 인증 (사용자 로그인 경우)
        if isinstance(token_info, str):
            # ID 토큰인 경우 (Cognito 등에서 전달된 토큰)
            # 서비스 계정으로 대체
            logging_client = logging.Client.from_service_account_json(
                settings.GCP_SERVICE_ACCOUNT_FILE
            )
        else:
            # access_token이 있는 경우 (GCP OAuth 로그인)
            credentials = Credentials(
                token=token_info.get('access_token'),
                refresh_token=token_info.get('refresh_token'),
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.GCP_CLIENT_ID,
                client_secret=settings.GCP_CLIENT_SECRET,
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            logging_client = logging.Client(credentials=credentials)
            
        return logging_client
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to authenticate with GCP: {str(e)}")

def list_gcp_logs(client, project_id=None, max_results=50):
    """
    GCP 로그 항목을 가져옵니다.
    """
    if not project_id:
        project_id = settings.GCP_PROJECT_ID
    
    try:
        # 로깅 클라이언트에서 로그 엔트리 가져오기
        logger = client.logger("global")
        entries = []
        
        # 최근 로그 항목을 가져옵니다
        for entry in logger.list_entries(
            max_results=max_results,
            order_by=logging.DESCENDING,
            filter_=f"resource.type=gce_instance"
        ):
            # 필요한 필드만 추출
            log_entry = {
                "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                "log_name": entry.log_name,
                "severity": entry.severity,
                "payload": entry.payload,
                "resource": {
                    "type": entry.resource.type,
                    "labels": entry.resource.labels
                } if entry.resource else None
            }
            entries.append(log_entry)
        
        return entries
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GCP log retrieval error: {str(e)}")