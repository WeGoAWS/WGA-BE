# app/models/policy_recommendation.py
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class PermissionChange(BaseModel):
    """권한 변경 사항 모델"""
    action: str
    apply: bool
    reason: str

class PolicyUpdates(BaseModel):
    """정책 업데이트 요청 모델"""
    user_arn: str
    add_permissions: List[PermissionChange] = []
    remove_permissions: List[PermissionChange] = []
    
class AnalysisResult(BaseModel):
    """파이프라인에서 받은 분석 결과 모델"""
    log_id: str
    user_arn: str
    event_name: str
    event_source: str
    timestamp: str
    security_risk: Optional[str] = None
    classification: Optional[str] = None
    severity: Optional[str] = None
    rationale: Optional[str] = None
    recommendations: Optional[List[str]] = None
    summary: Optional[str] = None
    add_permissions: Optional[List[Dict[str, Any]]] = None
    remove_permissions: Optional[List[Dict[str, Any]]] = None