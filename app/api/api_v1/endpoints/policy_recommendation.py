# app/api/api_v1/endpoints/policy_recommendation.py
from fastapi import APIRouter, Request, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import json
from app.services.aws_service import get_aws_session
from app.models.policy_recommendation import AnalysisResult, PolicyUpdates

router = APIRouter()

@router.post("/process-analysis")
async def process_analysis_result(
    request: Request,
    analysis_result: AnalysisResult = Body(..., description="파이프라인에서 받은 로그 분석 결과")
):
    """
    외부 파이프라인에서 받은 로그 분석 결과를 처리하고 클라이언트에 전달합니다.
    """
    # 인증 확인
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    
    # 권한 추천이 있는지 확인하고 적용 여부 초기화
    if analysis_result.add_permissions:
        for perm in analysis_result.add_permissions:
            if "apply" not in perm:
                perm["apply"] = False
    
    if analysis_result.remove_permissions:
        for perm in analysis_result.remove_permissions:
            if "apply" not in perm:
                perm["apply"] = False
    
    # 클라이언트에 전달할 형태로 반환
    return JSONResponse(content=jsonable_encoder(analysis_result))

@router.post("/apply-policy-changes")
async def apply_policy_changes(
    request: Request,
    updates: PolicyUpdates = Body(..., description="적용할 정책 변경 사항")
):
    """
    사용자가 선택한 권한 변경 사항을 실제 IAM 정책에 적용합니다.
    """
    # 인증 확인
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    
    # AWS 세션 가져오기
    session = get_aws_session(id_token)
    iam_client = session.client("iam")
    
    # 사용자 ARN에서 IAM 사용자 이름 추출
    user_arn = updates.user_arn
    if ":user/" in user_arn:
        user_name = user_arn.split("/")[-1]
    elif ":assumed-role/" in user_arn:
        # 역할일 경우 처리
        return JSONResponse(content={
            "status": "error",
            "message": "역할(Role) 권한은 현재 수정할 수 없습니다. IAM 사용자(User)만 지원됩니다."
        })
    else:
        return JSONResponse(content={
            "status": "error",
            "message": f"지원되지 않는 ARN 형식입니다: {user_arn}"
        })
    
    # 적용할 권한 변경 사항 필터링
    add_permissions = [item.action for item in updates.add_permissions if item.apply]
    remove_permissions = [item.action for item in updates.remove_permissions if item.apply]
    
    if not add_permissions and not remove_permissions:
        return JSONResponse(content={
            "status": "info",
            "message": "적용할 변경 사항이 없습니다."
        })
    
    results = {
        "user": user_name,
        "added_permissions": [],
        "removed_permissions": [],
        "errors": []
    }
    
    try:
        # 사용자의 현재 인라인 정책 가져오기
        policy_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
        
        # WGA 로그 분석 정책 찾기 또는 생성
        wga_policy_name = "WGALogAnalysisInlinePolicy"
        policy_document = None
        
        if wga_policy_name in policy_names:
            # 기존 정책 가져오기
            policy_response = iam_client.get_user_policy(
                UserName=user_name,
                PolicyName=wga_policy_name
            )
            policy_document = policy_response.get("PolicyDocument", {})
        else:
            # 새 정책 문서 생성
            policy_document = {
                "Version": "2012-10-17",
                "Statement": []
            }
        
        # 권한 추가
        if add_permissions:
            # Allow 문 찾기 또는 생성
            allow_stmt = None
            for stmt in policy_document.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    allow_stmt = stmt
                    break
            
            if not allow_stmt:
                allow_stmt = {
                    "Effect": "Allow",
                    "Action": [],
                    "Resource": "*"
                }
                policy_document["Statement"].append(allow_stmt)
            
            # Action 필드가 없으면 생성
            if "Action" not in allow_stmt:
                allow_stmt["Action"] = []
            
            # 문자열인 경우 리스트로 변환
            if isinstance(allow_stmt["Action"], str):
                allow_stmt["Action"] = [allow_stmt["Action"]]
            
            # 권한 추가
            for permission in add_permissions:
                if permission not in allow_stmt["Action"]:
                    allow_stmt["Action"].append(permission)
                    results["added_permissions"].append(permission)
        
        # 권한 제거
        if remove_permissions:
            for stmt in policy_document.get("Statement", []):
                if stmt.get("Effect") == "Allow" and "Action" in stmt:
                    # 문자열인 경우 처리
                    if isinstance(stmt["Action"], str):
                        if stmt["Action"] in remove_permissions:
                            stmt["Action"] = []
                            results["removed_permissions"].append(stmt["Action"])
                    else:
                        # 리스트에서 제거
                        for permission in remove_permissions:
                            if permission in stmt["Action"]:
                                stmt["Action"].remove(permission)
                                results["removed_permissions"].append(permission)
        
        # 정책 업데이트
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=wga_policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        
        return JSONResponse(content={
            "status": "success",
            "message": "IAM 정책이 성공적으로 업데이트되었습니다.",
            "details": results
        })
        
    except Exception as e:
        results["errors"].append(str(e))
        return JSONResponse(content={
            "status": "error",
            "message": f"IAM 정책 업데이트 중 오류가 발생했습니다: {str(e)}",
            "details": results
        })