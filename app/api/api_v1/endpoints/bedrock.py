from fastapi import APIRouter
from app.services.bedrock_service import invoke_bedrock_model

router = APIRouter()

@router.post("/generate-text")
def generate_text(input_text: str):
    """
    input_text을 받아
    Bedrock 모델에 인퍼런스를 요청한다.
    """
    result = invoke_bedrock_model(input_text)
    return {"bedrock_response": result}
