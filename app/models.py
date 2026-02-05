"""
Pydantic models for request/response validation.
Defines the API contract for the honeypot endpoint.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ScamType(str, Enum):
    """Classification of scam types."""
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
    UNKNOWN = "unknown"


class URLAnalysis(BaseModel):
    """Analysis of a detected URL."""
    url: str
    is_suspicious: bool = False
    threat_indicators: List[str] = Field(default_factory=list)


class IntelligenceOutput(BaseModel):
    """Extracted intelligence from the conversation."""
    upi_ids: List[str] = Field(default_factory=list, description="Extracted UPI IDs")
    bank_accounts: List[str] = Field(default_factory=list, description="Extracted bank account numbers")
    ifsc_codes: List[str] = Field(default_factory=list, description="Extracted IFSC codes")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted phone numbers")
    urls: List[URLAnalysis] = Field(default_factory=list, description="Extracted and analyzed URLs")
    email_addresses: List[str] = Field(default_factory=list, description="Extracted email addresses")
    scam_tactics: List[str] = Field(default_factory=list, description="Identified scam tactics")
    extracted_entities: Dict[str, Any] = Field(default_factory=dict, description="Other extracted entities")


class EngagementMetrics(BaseModel):
    """Metrics about the honeypot engagement."""
    turn_count: int = 1
    information_extracted_count: int = 0
    engagement_quality: str = "medium"
    conversation_stage: str = "initial"


class HoneypotRequest(BaseModel):
    """Request body for the honeypot endpoint."""
    message: Optional[str] = Field(None, description="The incoming message to analyze")
    text: Optional[str] = Field(None, description="Alternative field name for message")
    content: Optional[str] = Field(None, description="Alternative field name for message")
    input: Optional[str] = Field(None, description="Alternative field name for message")
    conversation_id: Optional[str] = Field(None, description="Optional conversation ID for multi-turn conversations")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional metadata about the message")
    
    def get_message(self) -> str:
        """Get the message from whichever field was provided."""
        return self.message or self.text or self.content or self.input or ""

    class Config:
        extra = "allow"  # Allow extra fields
        json_schema_extra = {
            "example": {
                "message": "Congratulations! You won Rs 50 lakh lottery. Send Rs 5000 to claim prize. UPI: claim@ybl",
                "conversation_id": "conv_abc123",
                "metadata": {"source": "sms", "sender": "+919876543210"}
            }
        }


class HoneypotResponse(BaseModel):
    """Response body from the honeypot endpoint."""
    conversation_id: str = Field(..., description="Unique conversation identifier")
    is_scam: bool = Field(..., description="Whether the message is detected as a scam")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score of scam detection")
    scam_type: Optional[str] = Field(None, description="Type of scam detected")
    response: str = Field(..., description="AI-generated response to engage the scammer")
    intelligence: IntelligenceOutput = Field(..., description="Extracted intelligence from the conversation")
    engagement_metrics: EngagementMetrics = Field(..., description="Metrics about the engagement")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    class Config:
        json_schema_extra = {
            "example": {
                "conversation_id": "conv_abc123",
                "is_scam": True,
                "confidence": 0.94,
                "scam_type": "lottery_fraud",
                "response": "Oh my! 50 lakh rupees? This is wonderful news! But I'm confused about the process. How do I send the money?",
                "intelligence": {
                    "upi_ids": ["claim@ybl"],
                    "bank_accounts": [],
                    "ifsc_codes": [],
                    "phone_numbers": ["+919876543210"],
                    "urls": [],
                    "email_addresses": [],
                    "scam_tactics": ["lottery_bait", "advance_fee_fraud"],
                    "extracted_entities": {"claimed_amount": "50 lakh", "demanded_amount": "5000"}
                },
                "engagement_metrics": {
                    "turn_count": 1,
                    "information_extracted_count": 2,
                    "engagement_quality": "high",
                    "conversation_stage": "initial"
                },
                "timestamp": "2026-02-05T14:30:00Z"
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
