from pydantic import BaseModel, Field, validator
from typing import List, Optional, Literal
from datetime import datetime

# Existing models...

class SanctionsManageRequest(BaseModel):
    address: str = Field(..., description="Ethereum address to manage")
    action: Literal["add", "remove"] = Field(..., description="Action to perform")
    confirmation_code: Optional[str] = Field(None, description="Confirmation code required for removal")
    reason: Optional[str] = Field(None, description="Optional reason for the action")
    chain: str = Field("ethereum", description="Blockchain network")
    
    @validator('address')
    def validate_address(cls, v):
        if not v.startswith('0x') or len(v) != 42:
            raise ValueError('Invalid Ethereum address format')
        return v.lower()
    
    @validator('confirmation_code')
    def validate_confirmation_code(cls, v, values):
        if values.get('action') == 'remove' and not v:
            raise ValueError('Confirmation code is required for removal actions')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "address": "0x742d35Cc6645C0532979A1f8A4D5fB2C61a8BaF6",
                "action": "add",
                "reason": "High risk wallet with suspicious transaction patterns",
                "chain": "ethereum"
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
