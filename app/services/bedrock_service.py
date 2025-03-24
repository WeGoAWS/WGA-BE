# app/services/bedrock_service.py
import json
import boto3
import time
import random
from app.core.config import settings

# 모델 인퍼런스 호출용으로 bedrock-runtime 클라이언트 생성
bedrock_client = boto3.client(
    "bedrock-runtime",
    region_name=settings.AWS_REGION,
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
)

def invoke_bedrock_model(input_text: str, max_retries=3, base_delay=1.0) -> dict:
    """
    Bedrock 모델에 텍스트를 전달하고 결과를 받아오는 함수.
    Throttling 에러 발생 시 지수 백오프 방식으로 재시도합니다.
    
    input_text: 사용자 입력
    max_retries: 최대 재시도 횟수
    base_delay: 초기 대기 시간 (초)
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

    # 지수 백오프를 사용한 재시도 로직
    for attempt in range(max_retries + 1):
        try:
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
            
        except bedrock_client.exceptions.ThrottlingException as e:
            if attempt == max_retries:
                # 최대 재시도 횟수에 도달하면 예외 발생
                raise e
                
            # 지수 백오프 계산 (2^시도 횟수 * 기본 대기 시간)
            delay = (2 ** attempt) * base_delay
            # 무작위 지터 추가 (0~1초)
            delay += random.uniform(0, 1.0)
            print(f"Throttling detected. Retrying in {delay:.2f} seconds... (Attempt {attempt+1}/{max_retries})")
            time.sleep(delay)
        except Exception as e:
            # 기타 예외는 바로 상위로 전달
            raise e