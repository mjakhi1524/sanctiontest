from pydantic import BaseModel, Field, validator
from typing import List, Optional, Literal
from datetime import datetime

# Existing models...

class SanctionsManageRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Optional reason for adding the address to sanctions")
    
    class Config:
        schema_extra = {
            "example": {
                "reason": "High risk wallet with suspicious transaction patterns"
            }
        }

class SanctionsResponse(BaseModel):
    success: bool
    message: str
    address: str
    action: str
    risk_profile: Optional[dict] = None
    total_count: int
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class WalletRiskAssessmentRequest(BaseModel):
    address: str = Field(..., description="Ethereum address to assess")
    chain: str = Field("ethereum", description="Blockchain network")
    
    @validator('address')
    def validate_address(cls, v):
        if not v.startswith('0x') or len(v) != 42:
            raise ValueError('Invalid Ethereum address format')
        return v.lower()

class WalletRiskAssessmentResponse(BaseModel):
    address: str
    risk_score: int
    risk_band: str
    risk_factors: List[str]
    confidence: float
    data_sources: List[str]
    transaction_count: Optional[int]
    total_volume: Optional[str]
    last_activity: Optional[str]
    suspicious_patterns: List[str]
    assessment_timestamp: str
    recommendation: str

class SanctionsAuditLog(BaseModel):
    partner_id: str
    action: str
    address: str
    risk_score: int
    risk_factors: List[str]
    data_sources: List[str]
    reason: Optional[str]
    timestamp: str
    ip_address: Optional[str]
    user_agent: Optional[str]

# Keep existing models if they exist...
