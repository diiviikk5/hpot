"""
AI Agent for honeypot engagement using OpenRouter API (FREE models).
Generates realistic responses while extracting intelligence.
"""
import httpx
from typing import Optional, Dict, Any, Tuple
from .personas import Persona, PersonaLibrary
from .memory import ConversationContext, conversation_memory
from ..detection.patterns import pattern_matcher
from ..config import get_settings


class HoneypotAgent:
    """
    AI agent that engages scammers using realistic victim personas.
    Uses OpenRouter API with free models for response generation.
    """
    
    def __init__(self):
        self.settings = get_settings()
    
    def _get_extraction_guidance(self, context: ConversationContext) -> str:
        """Get guidance for what information to extract based on conversation stage."""
        if context.turn_count < 2:
            return """
Focus on:
- Appearing confused but interested
- Asking for the caller's name and organization
- Requesting more explanation about the situation
"""
        elif context.turn_count < 4:
            return """
Focus on:
- Asking for their contact number or alternative way to reach them
- Requesting official documentation or reference numbers
- Showing willingness but asking for verification details
- If payment is mentioned, ask for bank details "to verify legitimacy"
"""
        else:
            return """
Focus on:
- Asking for exact bank account or UPI ID for payment
- Requesting their supervisor's contact
- Asking for written confirmation before proceeding
- Expressing slight hesitation to encourage more persuasion
"""
    
    def _build_messages(self, message: str, context: ConversationContext, 
                       persona: Persona) -> list:
        """Build the messages array for OpenRouter API."""
        history = context.get_conversation_history()
        extraction_guidance = self._get_extraction_guidance(context)
        
        system_content = f"""{persona.system_prompt}

CURRENT CONVERSATION STAGE: {context.engagement_stage}
TURN COUNT: {context.turn_count}

{extraction_guidance}

IMPORTANT RULES:
- Keep responses natural, 1-3 sentences typically
- Ask questions to extract information (contact details, bank info, UPI IDs)
- Do NOT use any AI-like phrases. Sound like a real person
- Never reveal you are an AI or that you suspect a scam
"""
        
        messages = [{"role": "system", "content": system_content}]
        
        # Add conversation history
        for msg in history[:-1] if history else []:
            role = "user" if msg["role"] == "user" else "assistant"
            messages.append({"role": role, "content": msg["content"]})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        return messages
    
    async def generate_response(
        self,
        message: str,
        conversation_id: str,
        scam_type: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate a response to engage the scammer.
        
        Args:
            message: The scammer's message
            conversation_id: Unique conversation identifier
            scam_type: Detected type of scam
            
        Returns:
            Tuple of (response text, extracted intelligence)
        """
        # Get or create conversation context
        context = conversation_memory.get_or_create(conversation_id)
        
        # Select persona based on scam type (first message) or use existing
        if context.turn_count == 0 and scam_type:
            persona = PersonaLibrary.get_persona_for_scam_type(scam_type)
            context.persona_name = persona.name
            context.scam_type = scam_type
        else:
            persona = self._get_persona_by_name(context.persona_name)
        
        # Add incoming message to context
        context.add_message("user", message)
        
        # Extract intelligence from the message
        extracted = pattern_matcher.extract_all(message)
        context.merge_intelligence(extracted)
        
        # Generate response using OpenRouter
        if self.settings.openrouter_api_key:
            try:
                response = await self._generate_with_openrouter(message, context, persona)
            except Exception as e:
                print(f"OpenRouter error: {e}")
                response = self._generate_fallback_response(message, context, persona)
        else:
            response = self._generate_fallback_response(message, context, persona)
        
        # Add response to context
        context.add_message("assistant", response)
        
        return response, {
            "turn_count": context.turn_count,
            "engagement_stage": context.engagement_stage,
            "extracted_this_turn": {k: v for k, v in extracted.items() if v}
        }
    
    async def _generate_with_openrouter(
        self, 
        message: str, 
        context: ConversationContext,
        persona: Persona
    ) -> str:
        """Generate response using OpenRouter API with free model."""
        messages = self._build_messages(message, context, persona)
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.settings.openrouter_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.settings.openrouter_api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://honeypot-api.onrender.com",
                    "X-Title": "Agentic Honeypot"
                },
                json={
                    "model": self.settings.openrouter_model,
                    "messages": messages,
                    "max_tokens": 150,
                    "temperature": 0.8,
                }
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
    
    def _generate_fallback_response(
        self,
        message: str,
        context: ConversationContext,
        persona: Persona
    ) -> str:
        """Generate a template-based fallback response."""
        message_lower = message.lower()
        
        if context.turn_count == 1:
            if persona.name == "Elderly Person":
                return "Oh my! This is very confusing for me. Can you please explain again? Who are you calling from?"
            elif persona.name == "Young Professional":
                return "Hey, I'm a bit busy right now. Can you give me your name and company details? I'll verify and get back."
            elif persona.name == "Small Business Owner":
                return "What is this regarding? Is this about my business GST? Please tell me clearly what is the issue."
            else:
                return "Oh wow, really? This sounds interesting! Can you tell me more? What's your name?"
        
        elif context.turn_count == 2:
            if "pay" in message_lower or "send" in message_lower or "transfer" in message_lower:
                return "I want to help but I need to verify first. Can you share your official ID or bank details so I know this is legitimate?"
            else:
                return "I understand. But how do I confirm you are genuine? Can you give me a number to call you back on?"
        
        elif context.turn_count >= 3:
            if any(word in message_lower for word in ['upi', 'bank', 'account', 'paytm', 'phonepe']):
                return "OK I am ready to proceed. Just confirm the exact bank account number or UPI ID where I should send? And your full name for my records."
            else:
                return "I am getting confused with all this. Can you just tell me step by step what I need to do? And give me your supervisor's number also."
        
        return "I don't understand properly. Can you explain again please? What exactly should I do?"
    
    def _get_persona_by_name(self, name: str) -> Persona:
        """Get persona by name."""
        personas = {
            "Elderly Person": PersonaLibrary.ELDERLY_RELATIVE,
            "Young Professional": PersonaLibrary.YOUNG_PROFESSIONAL,
            "Small Business Owner": PersonaLibrary.SMALL_BUSINESS_OWNER,
            "College Student": PersonaLibrary.STUDENT,
        }
        return personas.get(name, PersonaLibrary.get_random_persona())


# Singleton instance
honeypot_agent = HoneypotAgent()
