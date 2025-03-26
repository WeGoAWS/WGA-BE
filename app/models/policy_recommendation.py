from pydantic import BaseModel
from typing import List, Dict, Any

class PermissionChange(BaseModel):
    """권한 변경 사항 모델"""
    action: str
    apply: bool = False
    reason: str = ""

class PolicyRecommendation(BaseModel):
    """정책 추천 모델"""
    REMOVE: List[str] = []
    ADD: List[str] = []
    Reason: str = ""

class AnalysisResult(BaseModel):
    """파이프라인에서 받은 분석 결과 모델"""
    date: str
    user: str
    log_count: int
    analysis_timestamp: str
    analysis_comment: str
    policy_recommendation: PolicyRecommendation
    
    def get_add_permissions(self) -> List[Dict[str, Any]]:
        return [{"action": action, "apply": False, "reason": self.policy_recommendation.Reason} 
                for action in self.policy_recommendation.ADD]
    
    def get_remove_permissions(self) -> List[Dict[str, Any]]:
        return [{"action": action, "apply": False, "reason": self.policy_recommendation.Reason} 
                for action in self.policy_recommendation.REMOVE]
    
    def get_summary(self) -> str:
        """
        분석 결과에서 요약 문장을 추출합니다.
        여러 marker("Summary Sentence:", "Summary:", "요약:")를 확인하여 해당하는 경우 요약 문장을 반환하며,
        없으면 전체 분석 결과를 반환합니다.
        """
        markers = ["Summary Sentence:", "Summary:", "요약:"]
        for marker in markers:
            if marker in self.analysis_comment:
                return self.analysis_comment.split(marker)[-1].strip()
        return self.analysis_comment.strip()

class PolicyUpdates(BaseModel):
    """정책 업데이트 요청 모델"""
    user_arn: str
    add_permissions: List[PermissionChange] = []
    remove_permissions: List[PermissionChange] = []

class AnalysisResultList(BaseModel):
    """분석 결과 목록을 담기 위한 모델"""
    results: List[AnalysisResult]