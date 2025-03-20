# app/services/azure_service.py
import datetime
from azure.identity import ClientSecretCredential, DeviceCodeCredential
from azure.monitor.query import LogsQueryClient
from fastapi import HTTPException
from app.core.config import settings

def get_azure_client(token_info=None):
    """
    인증 토큰으로부터 Azure 클라이언트를 생성합니다.
    token_info: id_token(문자열) 또는 token_dict(액세스 토큰 등 포함)
    """
    try:
        # Azure 액세스 방식에 따라 다른 인증 방식 사용
        if token_info and not isinstance(token_info, str) and 'provider' in token_info and token_info['provider'] == 'azure':
            # Azure OAuth로 로그인한 경우 - 사용자 인증 토큰 활용
            # 실제 구현에서는 MSAL 또는 다른 방식으로 Azure AD 토큰을 활용
            # 이 예제에서는 간소화를 위해 Device Code 방식 사용
            credential = DeviceCodeCredential(
                client_id=settings.AZURE_CLIENT_ID,
                tenant_id=settings.AZURE_TENANT_ID
            )
        else:
            # 서비스 프린시펄 인증 정보 사용 (기본 방식)
            credential = ClientSecretCredential(
                tenant_id=settings.AZURE_TENANT_ID,
                client_id=settings.AZURE_CLIENT_ID,
                client_secret=settings.AZURE_CLIENT_SECRET
            )
        
        # Azure 로그 쿼리 클라이언트 생성
        logs_client = LogsQueryClient(credential)
        return logs_client
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to authenticate with Azure: {str(e)}")

def query_azure_logs(client, max_results=50):
    """
    Azure 로그 분석에서 로그를 쿼리합니다.
    """
    try:
        # 시간 범위 설정
        now = datetime.datetime.utcnow()
        query_start_time = now - datetime.timedelta(hours=24)  # 지난 24시간
        
        # 로그 분석 쿼리
        query = f"""
        AzureActivity
        | sort by TimeGenerated desc
        | limit {max_results}
        """
        
        # 쿼리 실행
        response = client.query_workspace(
            workspace_id=settings.AZURE_LOG_WORKSPACE_ID,
            query=query,
            timespan=(query_start_time, now)
        )
        
        # 결과 처리
        logs = []
        if response and response.tables:
            for row in response.tables[0].rows:
                # 테이블 열 이름 가져오기
                column_names = [col.name for col in response.tables[0].columns]
                # 행 데이터와 열 이름을 결합
                log_entry = dict(zip(column_names, row))
                logs.append(log_entry)
        
        return logs
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Azure log query error: {str(e)}")