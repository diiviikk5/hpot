"""
Enhanced Pydantic models for comprehensive API request/response validation.
Optimized for maximum intelligence capture.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ScamType(str, Enum):
    """Comprehensive scam type classification."""
    LOTTERY_FRAUD = "lottery_fraud"
    BANK_IMPERSONATION = "bank_impersonation"
    GOVERNMENT_IMPERSONATION = "government_impersonation"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    ADVANCE_FEE_FRAUD = "advance_fee_fraud"
    PHISHING = "phishing"
    UPI_FRAUD = "upi_fraud"
    JOB_SCAM = "job_scam"
    INVESTMENT_SCAM = "investment_scam"
    ROMANCE_SCAM = "romance_scam"
    DELIVERY_SCAM = "delivery_scam"
    KYC_SCAM = "kyc_scam"
    UNKNOWN = "unknown"


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class URLAnalysis(BaseModel):
    """Detailed URL threat analysis."""
    url: str
    is_suspicious: bool = False
    threat_indicators: List[str] = Field(default_factory=list)
    threat_level: str = "low"


class FinancialIntelligence(BaseModel):
    """Extracted financial information."""
    upi_ids: List[str] = Field(default_factory=list)
    bank_accounts: List[str] = Field(default_factory=list)
    ifsc_codes: List[str] = Field(default_factory=list)
    money_amounts: List[str] = Field(default_factory=list)


class ContactIntelligence(BaseModel):
    """Extracted contact information."""
    phone_numbers: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    messaging_numbers: List[str] = Field(default_factory=list)


class IdentityIntelligence(BaseModel):
    """Extracted identity/PII information."""
    names: List[str] = Field(default_factory=list)
    organizations: List[str] = Field(default_factory=list)
    aadhaar_numbers: List[str] = Field(default_factory=list)
    pan_numbers: List[str] = Field(default_factory=list)
    reference_numbers: List[str] = Field(default_factory=list)


class IntelligenceOutput(BaseModel):
    """Comprehensive extracted intelligence from conversation."""
    # Financial data
    upi_ids: List[str] = Field(default_factory=list, description="Extracted UPI IDs")
    bank_accounts: List[str] = Field(default_factory=list, description="Bank account numbers")
    ifsc_codes: List[str] = Field(default_factory=list, description="IFSC codes")
    
    # Contact data
    phone_numbers: List[str] = Field(default_factory=list, description="Phone numbers")
    email_addresses: List[str] = Field(default_factory=list, description="Email addresses")
    
    # Web/URL data
    urls: List[URLAnalysis] = Field(default_factory=list, description="Analyzed URLs")
    
    # Identity data
    scammer_names: List[str] = Field(default_factory=list, description="Names mentioned by scammer")
    organizations: List[str] = Field(default_factory=list, description="Organizations claimed")
    reference_numbers: List[str] = Field(default_factory=list, description="Case/reference numbers")
    
    # Scam tactics used
    scam_tactics: List[str] = Field(default_factory=list, description="Identified tactics")
    
    # Additional extracted entities
    extracted_entities: Dict[str, Any] = Field(default_factory=dict)
    
    # Meta
    total_entities_extracted: int = 0


class EngagementMetrics(BaseModel):
    """Detailed engagement metrics."""
    turn_count: int = 1
    information_extracted_count: int = 0
    engagement_quality: str = "medium"
    conversation_stage: str = "initial"
    persona_used: str = "Unknown"
    extraction_success_rate: float = 0.0


class DetectionDetails(BaseModel):
    """Detailed detection analysis."""
    keyword_matches: Dict[str, List[str]] = Field(default_factory=dict)
    heuristic_triggers: List[str] = Field(default_factory=list)
    risk_score: float = 0.0


class HoneypotRequest(BaseModel):
    """Flexible request body for the honeypot endpoint."""
    message: Optional[str] = Field(None, description="The incoming scam message")
    text: Optional[str] = Field(None, description="Alternative: message text")
    content: Optional[str] = Field(None, description="Alternative: content")
    input: Optional[str] = Field(None, description="Alternative: input")
    msg: Optional[str] = Field(None, description="Alternative: msg")
    conversation_id: Optional[str] = Field(None, description="Conversation ID for multi-turn")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    def get_message(self) -> str:
        """Get message from any of the accepted field names."""
        return self.message or self.text or self.content or self.input or self.msg or ""
    
    class Config:
        extra = "allow"


class HoneypotResponse(BaseModel):
    """Comprehensive response from the honeypot endpoint."""
    # Core response
    conversation_id: str = Field(..., description="Unique conversation identifier")
    is_scam: bool = Field(..., description="Whether scam was detected")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    scam_type: Optional[str] = Field(None, description="Classified scam type")
    
    # AI engagement
    response: str = Field(..., description="AI-generated engagement response")
    
    # Intelligence
    intelligence: IntelligenceOutput = Field(..., description="Extracted intelligence")
    
    # Metrics
    engagement_metrics: EngagementMetrics = Field(..., description="Engagement metrics")
    
    # Optional detailed analysis
    detection_details: Optional[DetectionDetails] = Field(None, description="Detection analysis")
    
    # Timestamp
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    
    class Config:
        json_schema_extra = {
            "example": {
                "conversation_id": "conv_abc123",
                "is_scam": True,
                "confidence": 0.94,
                "scam_type": "bank_impersonation",
                "response": "Oh no! Which branch are you calling from? What is your name?",
                "intelligence": {
                    "upi_ids": ["scammer@ybl"],
                    "bank_accounts": ["1234567890123"],
                    "phone_numbers": ["9876543210"],
                    "scam_tactics": ["authority_impersonation", "fear_tactics"]
                },
                "engagement_metrics": {
                    "turn_count": 2,
                    "information_extracted_count": 3,
                    "engagement_quality": "high"
                },
                "timestamp": "2026-02-05T14:30:00Z"
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    model: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
