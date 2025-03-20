# app/services/bedrock_service.py
import json
import boto3
from app.core.config import settings

# 모델 인퍼런스 호출용으로 bedrock-runtime 클라이언트 생성
bedrock_client = boto3.client(
    "bedrock-runtime",
    region_name=settings.AWS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

def invoke_bedrock_model(input_text: str) -> dict:
    """
    Bedrock 모델에 텍스트를 전달하고 결과를 받아오는 함수.
    input_text: 사용자 입력
    return: 모델의 응답(JSON 형태)
    """
    # Bedrock에 보낼 payload(모델별 요구 포맷이 상이할 수 있음)
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1000,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": input_text
                    }
                ]
            }
        ]
    }

    response = bedrock_client.invoke_model(
        modelId="anthropic.claude-3-sonnet-20240229-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps(payload)
    )

    # response["body"]는 StreamingBody 형태일 수 있으므로, read()가 필요
    raw_body = response["body"].read()
    result_json = json.loads(raw_body)
    return result_json
