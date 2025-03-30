from fastapi import APIRouter, Request, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import json
from typing import List
from app.services.aws_service import get_aws_session
from app.models.policy_recommendation import PolicyUpdates, AnalysisResultList

router = APIRouter()

@router.get("/process-multiple-analyses")
async def process_multiple_analyses(request: Request):
    """
    여러 분석 결과를 한 번에 처리합니다.
    S3 버킷 'wga-outputbucket'의 results 폴더에서 가장 최신 JSON 파일을 불러와서 처리합니다.
    """
    # 인증 확인
    id_token = request.session.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="인증이 필요합니다.")
    session = get_aws_session(id_token)
    s3 = session.client("s3")
    bucket_name = "wga-outputbucket"
    prefix = "results/"

    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"S3 버킷 접근 중 오류 발생: {str(e)}")

    if 'Contents' not in response or not response['Contents']:
        raise HTTPException(status_code=404, detail="결과 파일이 존재하지 않습니다.")

    # 최신 파일 선택 (LastModified 기준)
    latest_file = max(response['Contents'], key=lambda x: x['LastModified'])
    latest_key = latest_file['Key']

    try:
        obj = s3.get_object(Bucket=bucket_name, Key=latest_key)
        file_content = obj['Body'].read()
        analysis_results_data = json.loads(file_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"파일 불러오기 실패: {str(e)}")

    processed_results = []
    
    # JSON 데이터가 리스트 형태일 경우 각 항목을 처리합니다.
    if isinstance(analysis_results_data, list):
        for result in analysis_results_data:
            processed_result = {
                "date": result.get("date"),
                "user": result.get("user"),
                "log_count": result.get("log_count"),
                "analysis_timestamp": result.get("analysis_timestamp"),
                "analysis_comment": result.get("analysis_comment"),
                "risk_level": result.get("risk_level"),
                "policy_recommendation": result.get("policy_recommendation"),
                "type": result.get("type")  # daily_global_summary 등 추가 정보가 있을 수 있음
            }
            processed_results.append(processed_result)
    else:
        # JSON 데이터 구조가 예상과 다른 경우 예외 처리합니다.
        raise HTTPException(status_code=400, detail="JSON 구조가 예상과 다릅니다.")

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