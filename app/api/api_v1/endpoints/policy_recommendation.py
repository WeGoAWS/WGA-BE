from fastapi import APIRouter, Request, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import json
from typing import List
from app.services.aws_service import get_aws_session
from app.models.policy_recommendation import PolicyUpdates, AnalysisResultList

router = APIRouter()

@router.post("/process-multiple-analyses")
async def process_multiple_analyses(
    request: Request,
    analysis_results: AnalysisResultList = Body(..., description="파이프라인에서 받은 여러 로그 분석 결과")
):
    """
    여러 분석 결과를 한 번에 처리합니다.
    """
    # 인증 확인
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    
    processed_results = []
    
    for result in analysis_results.results:
        processed_result = {
            "date": result.date,
            "user": result.user,
            "log_count": result.log_count,
            "analysis_timestamp": result.analysis_timestamp,
            "analysis_comment": result.get_summary(),
            "add_permissions": result.get_add_permissions(),
            "policy_recommendation": result.policy_recommendation
        }
        processed_results.append(processed_result)
    
    return JSONResponse(content=jsonable_encoder(processed_results))

@router.post("/apply-policy-changes")
async def apply_policy_changes(
    request: Request,
    updates: List[PolicyUpdates] = Body(..., description="적용할 정책 변경 사항 목록")
):
    """
    사용자가 선택한 권한 변경 사항들을 실제 IAM 정책에 적용합니다.
    """
    # 인증 확인
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    
    session = get_aws_session(id_token)
    iam_client = session.client("iam")
    
    overall_results = []
    
    for update in updates:
        result = {
            "user": None,
            "added_permissions": [],
            "removed_permissions": [],
            "errors": []
        }
        
        user_arn = update.user_arn
        if ":user/" in user_arn:
            user_name = user_arn.split("/")[-1]
            result["user"] = user_name
        elif ":assumed-role/" in user_arn:
            overall_results.append({
                "status": "error",
                "message": "역할(Role) 권한은 현재 수정할 수 없습니다. IAM 사용자(User)만 지원됩니다.",
                "details": {"user": user_arn}
            })
            continue
        else:
            overall_results.append({
                "status": "error",
                "message": f"지원되지 않는 ARN 형식입니다: {user_arn}",
                "details": {"user": user_arn}
            })
            continue
        
        add_permissions = [item.action for item in update.add_permissions if item.apply]
        remove_permissions = [item.action for item in update.remove_permissions if item.apply]
        
        if not add_permissions and not remove_permissions:
            overall_results.append({
                "status": "info",
                "message": "적용할 변경 사항이 없습니다.",
                "details": result
            })
            continue
        
        try:
            policy_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
            wga_policy_name = "WGALogAnalysisInlinePolicy"
            if wga_policy_name in policy_names:
                policy_response = iam_client.get_user_policy(
                    UserName=user_name,
                    PolicyName=wga_policy_name
                )
                policy_document = policy_response.get("PolicyDocument", {})
            else:
                policy_document = {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            
            if add_permissions:
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
                
                if "Action" not in allow_stmt:
                    allow_stmt["Action"] = []
                
                if isinstance(allow_stmt["Action"], str):
                    allow_stmt["Action"] = [allow_stmt["Action"]]
                
                for permission in add_permissions:
                    if permission not in allow_stmt["Action"]:
                        allow_stmt["Action"].append(permission)
                        result["added_permissions"].append(permission)
            
            if remove_permissions:
                for stmt in policy_document.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and "Action" in stmt:
                        if isinstance(stmt["Action"], str):
                            if stmt["Action"] in remove_permissions:
                                result["removed_permissions"].append(stmt["Action"])
                                # 문자열 형태일 경우 빈 문자열로 설정
                                stmt["Action"] = ""
                        elif isinstance(stmt["Action"], list):
                            for permission in remove_permissions:
                                if permission in stmt["Action"]:
                                    stmt["Action"].remove(permission)
                                    result["removed_permissions"].append(permission)

            # 삭제 후, "Action" 필드가 빈 리스트이거나 빈 문자열인 statement를 제거
            policy_document["Statement"] = [
                stmt for stmt in policy_document.get("Statement", [])
                if (
                    (isinstance(stmt.get("Action"), list) and len(stmt.get("Action")) > 0)
                    or (isinstance(stmt.get("Action"), str) and stmt.get("Action").strip() != "")
                )
            ]
            
            if not policy_document["Statement"]:
                # 모든 statement가 제거되었으므로, 인라인 정책을 삭제
                iam_client.delete_user_policy(
                    UserName=user_name,
                    PolicyName=wga_policy_name
                )
            else:
                iam_client.put_user_policy(
                    UserName=user_name,
                    PolicyName=wga_policy_name,
                    PolicyDocument=json.dumps(policy_document)
                )
            
            overall_results.append({
                "status": "success",
                "message": "IAM 정책이 성공적으로 업데이트되었습니다.",
                "details": result
            })
            
        except Exception as e:
            result["errors"].append(str(e))
            overall_results.append({
                "status": "error",
                "message": f"IAM 정책 업데이트 중 오류가 발생했습니다: {str(e)}",
                "details": result
            })
    
    return JSONResponse(content=jsonable_encoder(overall_results))