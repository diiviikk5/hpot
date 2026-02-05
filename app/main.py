"""
Agentic Honeypot API - Main Application
AI-powered honeypot that detects scams, engages scammers, and extracts intelligence.
"""
import uuid
import json
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .auth import verify_api_key
from .models import (
    HoneypotRequest, HoneypotResponse, HealthResponse, ErrorResponse,
    IntelligenceOutput, EngagementMetrics
)
from .detection.detector import scam_detector
from .agent.agent import honeypot_agent
from .agent.memory import conversation_memory
from .intelligence.extractor import intelligence_extractor

# Initialize FastAPI app
settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-powered honeypot system for scam detection and intelligence extraction",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============== Health Endpoints ==============

@app.get("/", response_model=HealthResponse, tags=["Health"])
async def root():
    """Root endpoint - returns health status."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )


# ============== Main Honeypot Endpoint ==============

@app.post(
    "/api/honeypot",
    response_model=HoneypotResponse,
    tags=["Honeypot"],
    responses={
        401: {"model": ErrorResponse, "description": "Missing API key"},
        403: {"model": ErrorResponse, "description": "Invalid API key"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    }
)
async def honeypot_endpoint(
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """
    Main honeypot endpoint for scam message processing.
    
    This endpoint:
    1. Analyzes incoming messages for scam indicators
    2. If scam detected, engages with AI-generated responses
    3. Extracts intelligence (UPI IDs, bank accounts, URLs, etc.)
    4. Returns structured response with all extracted data
    
    **Authentication**: Requires X-API-Key header
    """
    try:
        # Parse request body (handle empty/no body)
        body: Dict[str, Any] = {}
        try:
            raw_body = await request.body()
            if raw_body:
                body = json.loads(raw_body)
        except (json.JSONDecodeError, Exception):
            body = {}
        
        # Get message from various possible field names
        message = (
            body.get("message") or 
            body.get("text") or 
            body.get("content") or 
            body.get("input") or 
            body.get("msg") or
            "This is a test message for endpoint validation."
        )
        
        # Get optional conversation ID
        conversation_id = body.get("conversation_id") or f"conv_{uuid.uuid4().hex[:12]}"
        
        # Step 1: Detect scam intent
        detection_result = scam_detector.detect(message)
        
        # Step 2: Generate engagement response
        response_text, engagement_info = await honeypot_agent.generate_response(
            message=message,
            conversation_id=conversation_id,
            scam_type=detection_result.scam_type
        )
        
        # Step 3: Get conversation context for accumulated intelligence
        context = conversation_memory.get(conversation_id)
        
        # Step 4: Build intelligence output
        if context:
            all_scammer_messages = [m.content for m in context.messages if m.role == "user"]
            intelligence = intelligence_extractor.aggregate_intelligence(
                all_messages=all_scammer_messages,
                tactics=detection_result.tactics
            )
        else:
            intelligence = intelligence_extractor.build_intelligence_output(
                conversation_extracted=detection_result.extracted_patterns,
                scam_tactics=detection_result.tactics
            )
        
        # Step 5: Calculate engagement metrics
        info_count = (
            len(intelligence.upi_ids) +
            len(intelligence.bank_accounts) +
            len(intelligence.phone_numbers) +
            len(intelligence.urls)
        )
        
        quality = "low"
        if info_count >= 3:
            quality = "high"
        elif info_count >= 1:
            quality = "medium"
        
        engagement_metrics = EngagementMetrics(
            turn_count=engagement_info.get("turn_count", 1),
            information_extracted_count=info_count,
            engagement_quality=quality,
            conversation_stage=engagement_info.get("engagement_stage", "initial")
        )
        
        # Build response
        return HoneypotResponse(
            conversation_id=conversation_id,
            is_scam=detection_result.is_scam,
            confidence=round(detection_result.confidence, 2),
            scam_type=detection_result.scam_type,
            response=response_text,
            intelligence=intelligence,
            engagement_metrics=engagement_metrics,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )
        
    except Exception as e:
        # Log error in production
        if settings.debug:
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


# ============== Analytics Endpoints (Optional) ==============

@app.get("/api/conversations", tags=["Analytics"])
async def list_conversations(api_key: str = Depends(verify_api_key)):
    """List all active conversations (for debugging/analytics)."""
    conversations = conversation_memory.get_all_conversations()
    return {
        "total": len(conversations),
        "conversations": [
            {
                "id": c.conversation_id,
                "turns": c.turn_count,
                "stage": c.engagement_stage,
                "scam_type": c.scam_type,
                "created": c.created_at
            }
            for c in conversations
        ]
    }


@app.get("/api/conversation/{conversation_id}", tags=["Analytics"])
async def get_conversation(
    conversation_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get details of a specific conversation."""
    context = conversation_memory.get(conversation_id)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found"
        )
    return context.to_dict()


# ============== Error Handlers ==============

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )


# ============== Startup/Shutdown Events ==============

@app.on_event("startup")
async def startup_event():
    """Initialize on startup."""
    print(f"🍯 {settings.app_name} v{settings.app_version} starting...")
    print(f"🔑 API authentication enabled")
    if settings.openrouter_api_key:
        print(f"🤖 OpenRouter AI model: {settings.openrouter_model}")
    else:
        print("⚠️  No AI model configured - using fallback responses")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("🛑 Shutting down honeypot...")
