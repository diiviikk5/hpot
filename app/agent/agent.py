"""
Elite AI Agent for honeypot engagement.
Optimized for maximum intelligence extraction from scammers.
"""
import httpx
from typing import Optional, Dict, Any, Tuple, List
from .personas import Persona, PersonaLibrary
from .memory import ConversationContext, conversation_memory
from ..detection.patterns import pattern_matcher
from ..config import get_settings


class HoneypotAgent:
    """
    Advanced AI agent for engaging scammers and extracting intelligence.
    Uses strategic conversation tactics to maximize information extraction.
    """
    
    def __init__(self):
        self.settings = get_settings()
    
    def _get_extraction_strategy(self, context: ConversationContext, scam_type: str = None) -> str:
        """Get targeted extraction strategy based on conversation stage and scam type."""
        
        base_strategy = """
YOUR EXTRACTION TARGETS (get these from the scammer):
- Their full name and designation
- Organization/company they claim to represent
- Phone number or WhatsApp to "call back"
- Bank account number or UPI ID for "payment"
- Reference/case/complaint numbers they mention
- Names of their "supervisors" or "senior officers"
"""
        
        if context.turn_count < 2:
            return f"""
STAGE: INITIAL CONTACT - Build Trust
{base_strategy}
TACTICS:
- Act confused but interested
- Ask them to repeat/clarify
- Request their name and organization
- Sound slightly worried but cooperative
- Ask "How did you get my number?"
"""
        
        elif context.turn_count < 4:
            return f"""
STAGE: BUILDING RAPPORT - Verify & Extract
{base_strategy}
TACTICS:
- Show you're taking it seriously
- Ask for official reference number or case ID
- Request their callback number "in case we get disconnected"
- If payment mentioned, ask for bank details "to verify legitimacy"
- Ask about their office location and supervisor name
- Say "My son/daughter handles banking, can you explain to them?"
"""
        
        elif context.turn_count < 6:
            return f"""
STAGE: COMPLIANCE PHASE - Extract Financial Details
{base_strategy}
TACTICS:
- Appear convinced and ready to comply
- Ask for EXACT bank account or UPI ID for payment
- Request written confirmation via WhatsApp
- Ask for their personal mobile number
- Request supervisor's number "for my records"
- Ask "How much exactly and to whose account?"
"""
        
        else:
            return f"""
STAGE: DEEP EXTRACTION - Maximum Intelligence
{base_strategy}
TACTICS:
- Create delays to keep extracting information
- Say "Bank is asking for beneficiary name and IFSC"
- Ask for their Aadhaar/PAN for "tax purposes"
- Request alternative payment methods
- Ask about their organization's head office
- Keep asking verification questions
"""
    
    def _get_scam_specific_prompts(self, scam_type: str) -> str:
        """Get scam-type specific response guidance."""
        
        prompts = {
            'lottery_fraud': """
SCAM TYPE: LOTTERY/PRIZE
- Act excited but cautious
- Ask "Which lottery did I enter?"
- Request official winner certificate
- Ask for their office address to collect prize
- When fee mentioned, ask for exact UPI/account details
""",
            'bank_impersonation': """
SCAM TYPE: BANK IMPERSONATION
- Sound worried about your account
- Ask "Which branch are you calling from?"
- Request branch manager's name and number
- Ask for official email to send documents
- If OTP requested, ask for their employee ID first
""",
            'government_impersonation': """
SCAM TYPE: GOVERNMENT/POLICE
- Act scared and cooperative
- Ask for their badge number or employee ID
- Request case number and court details
- Ask for official notice via email/WhatsApp
- Request their senior officer's contact
""",
            'upi_fraud': """
SCAM TYPE: UPI/PAYMENT FRAUD
- Act confused about UPI
- Ask them to repeat the UPI ID clearly
- Request the beneficiary name
- Ask for alternative payment methods
- Request receipt format before paying
""",
            'job_scam': """
SCAM TYPE: JOB SCAM
- Act interested in the opportunity
- Ask for company address and website
- Request HR contact details
- Ask for job offer letter before payment
- Request company GST number
""",
            'investment_scam': """
SCAM TYPE: INVESTMENT SCAM
- Show interest but want to verify
- Ask for SEBI registration number
- Request their portfolio manager's details
- Ask for office address to visit
- Request bank account details for "due diligence"
""",
        }
        
        return prompts.get(scam_type, """
SCAM TYPE: UNKNOWN
- Act confused and cooperative
- Ask lots of verification questions
- Request official documentation
- Ask for callback number
- Try to get payment details if mentioned
""")
    
    def _build_elite_messages(self, message: str, context: ConversationContext, 
                             persona: Persona, scam_type: str = None) -> list:
        """Build optimized messages array for maximum extraction."""
        
        history = context.get_conversation_history()
        extraction_strategy = self._get_extraction_strategy(context, scam_type)
        scam_specific = self._get_scam_specific_prompts(scam_type) if scam_type else ""
        
        # Build comprehensive system prompt
        system_content = f"""{persona.system_prompt}

{extraction_strategy}

{scam_specific}

CRITICAL RULES:
1. Keep responses SHORT (1-3 sentences max)
2. Always ask at least ONE question to extract information
3. Sound like a real confused person, NOT an AI
4. Never use corporate language or perfect grammar
5. Add natural hesitation: "umm", "actually", "wait", "hmm"
6. Never reveal suspicion or that you know it's a scam
7. If they give UPI/account, ask for name and IFSC too
8. If they give phone number, ask for WhatsApp number too
9. Create believable delays: "let me check with my family"
10. Use simple, colloquial language

EXTRACTED SO FAR: {', '.join(context.extracted_intelligence.keys()) if context.extracted_intelligence else 'Nothing yet'}

Generate a response that continues the conversation and extracts more information.
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
        """Generate optimal response for intelligence extraction."""
        
        # Get or create conversation context
        context = conversation_memory.get_or_create(conversation_id)
        
        # Select persona
        if context.turn_count == 0 and scam_type:
            persona = PersonaLibrary.get_persona_for_scam_type(scam_type)
            context.persona_name = persona.name
            context.scam_type = scam_type
        else:
            persona = self._get_persona_by_name(context.persona_name)
            if scam_type and not context.scam_type:
                context.scam_type = scam_type
        
        # Add incoming message to context
        context.add_message("user", message)
        
        # Extract intelligence from message
        extracted = pattern_matcher.extract_all(message)
        context.merge_intelligence(extracted)
        
        # Generate response
        response = await self._generate_response(
            message, context, persona, context.scam_type
        )
        
        # Add response to context
        context.add_message("assistant", response)
        
        return response, {
            "turn_count": context.turn_count,
            "engagement_stage": context.engagement_stage,
            "persona": persona.name,
            "extracted_this_turn": {k: v for k, v in extracted.items() if v}
        }
    
    async def _generate_response(
        self, 
        message: str, 
        context: ConversationContext,
        persona: Persona,
        scam_type: str = None
    ) -> str:
        """Generate response using AI or fallback."""
        
        if self.settings.openrouter_api_key:
            try:
                return await self._generate_with_openrouter(message, context, persona, scam_type)
            except Exception as e:
                print(f"OpenRouter error: {e}")
                return self._generate_fallback_response(message, context, persona)
        else:
            return self._generate_fallback_response(message, context, persona)
    
    async def _generate_with_openrouter(
        self, 
        message: str, 
        context: ConversationContext,
        persona: Persona,
        scam_type: str = None
    ) -> str:
        """Generate response using OpenRouter API."""
        
        messages = self._build_elite_messages(message, context, persona, scam_type)
        
        async with httpx.AsyncClient(timeout=25.0) as client:
            response = await client.post(
                f"{self.settings.openrouter_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.settings.openrouter_api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://incepta.onrender.com",
                    "X-Title": "Incepta Honeypot"
                },
                json={
                    "model": self.settings.openrouter_model,
                    "messages": messages,
                    "max_tokens": 120,
                    "temperature": 0.85,
                    "top_p": 0.9,
                }
            )
            response.raise_for_status()
            data = response.json()
            
            generated = data["choices"][0]["message"]["content"].strip()
            
            # Post-process to ensure quality
            return self._post_process_response(generated, context)
    
    def _post_process_response(self, response: str, context: ConversationContext) -> str:
        """Clean and validate generated response."""
        
        # Remove AI-like phrases
        ai_phrases = [
            "As an AI", "I'm an AI", "I cannot", "I don't have feelings",
            "I'm programmed", "artificial intelligence", "language model",
            "I'm sorry, but", "I understand your concern",
        ]
        
        for phrase in ai_phrases:
            if phrase.lower() in response.lower():
                return self._generate_fallback_response("", context, PersonaLibrary.get_random_persona())
        
        # Ensure response isn't too long
        if len(response) > 300:
            sentences = response.split('.')
            response = '. '.join(sentences[:2]) + '.'
        
        # Ensure response isn't too short
        if len(response) < 10:
            response += " Can you please explain more?"
        
        return response
    
    def _generate_fallback_response(
        self,
        message: str,
        context: ConversationContext,
        persona: Persona
    ) -> str:
        """Generate intelligent fallback response."""
        
        message_lower = message.lower() if message else ""
        turn = context.turn_count
        
        # Persona-specific responses
        responses_by_persona = {
            "Elderly Person": {
                1: "Oh my! This is very confusing... Can you please explain again slowly? What is your name and where are you calling from?",
                2: "Beta, I don't understand all this. Can you give me a number to call you back? My grandson will help me understand.",
                3: "Okay okay, I want to help. But first tell me - what is your office address? And your supervisor's name?",
                4: "I am ready to pay. Just tell me exactly - what is the account number and whose name should I write?",
                5: "Wait wait, this is too fast. Give me your WhatsApp number, I will ask my son to send the money."
            },
            "Young Professional": {
                1: "Hey, hold on - who is this? Can you share your employee ID and official email?",
                2: "Look, I'm busy rn. Just send me the details on WhatsApp - what's your number?",
                3: "Fine, if this is legit, share the account details. I'll verify with my bank first.",
                4: "What's the UPI ID? And send me the beneficiary name too for confirmation.",
                5: "I need your supervisor's number before I proceed. This is standard verification on my end."
            },
            "Small Business Owner": {
                1: "What is this about exactly? Is this about my business? Give me your name and which department you're from.",
                2: "I don't have time for this. Give me a reference number and your direct number, I'll call back.",
                3: "If I have to pay, I need proper invoice. What's your company GST number and account details?",
                4: "Okay, share the UPI ID. Also give me IFSC code and beneficiary name for my accountant.",
                5: "Before paying, send me written confirmation on WhatsApp. What's your number?"
            },
            "College Student": {
                1: "Wait what?? This sounds confusing... Can you tell me your name and what exactly is happening?",
                2: "Omg this sounds serious! But like, how do I know you're legit? What's your phone number?",
                3: "Okay fine, how much do I have to pay? And like, what's the UPI ID?",
                4: "My dad handles payments. Can you talk to him? Give me your WhatsApp, I'll share with him.",
                5: "I don't have that much money rn. Can you give me bank account details, I'll do NEFT from dad's account."
            }
        }
        
        # Get persona responses or use default
        persona_responses = responses_by_persona.get(persona.name, responses_by_persona["Young Professional"])
        
        # Context-aware responses based on what was said
        if any(word in message_lower for word in ['otp', 'cvv', 'pin', 'password']):
            return "Wait, you're asking for OTP/PIN? My bank says never to share that. Can you give me your supervisor's number to verify?"
        
        if any(word in message_lower for word in ['upi', 'paytm', 'phonepe', 'gpay']):
            return "Okay, what's the exact UPI ID? And tell me the name that will show when I send."
        
        if any(word in message_lower for word in ['bank', 'account', 'transfer', 'neft']):
            return "Fine, give me the account number, IFSC code, and beneficiary name. I'll do NEFT."
        
        if any(word in message_lower for word in ['arrest', 'police', 'court', 'legal']):
            return "Oh god, this is serious! Please, what is your officer ID? And which station are you from?"
        
        if any(word in message_lower for word in ['lottery', 'prize', 'won', 'winner']):
            return "Really?! I won something?! That's amazing! But wait, where is your office located? How do I claim it?"
        
        # Default to turn-based responses
        return persona_responses.get(min(turn, 5), 
            "I need more time to understand this. Can you give me your contact details to call back?")
    
    def _get_persona_by_name(self, name: str) -> Persona:
        """Get persona by name."""
        personas = {
            "Elderly Person": PersonaLibrary.ELDERLY_RELATIVE,
            "Young Professional": PersonaLibrary.YOUNG_PROFESSIONAL,
            "Small Business Owner": PersonaLibrary.SMALL_BUSINESS_OWNER,
            "College Student": PersonaLibrary.STUDENT,
        }
        return personas.get(name, PersonaLibrary.get_random_persona())


    async def verify_scam_with_ai(self, message: str) -> Dict[str, Any]:
        """
        Use the LLM to perform a high-accuracy secondary verification of a scam message.
        This provides the 'best training' performance by utilizing the LLM's classification abilities.
        """
        prompt = f"""Analyze the following message and determine if it is a scam. 
Return your response in EXACTLY this JSON format (no other text):
{{
  "is_scam": true/false,
  "confidence": 0.0 to 1.0,
  "scam_type": "one of: lottery_fraud, bank_impersonation, government_impersonation, upi_fraud, job_scam, investment_scam, phishing, other",
  "reason": "brief explanation"
}}

MESSAGE to analyze:
"{message}"
"""
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.settings.openrouter_base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.settings.openrouter_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.settings.openrouter_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 150,
                        "temperature": 0.1, # Low temperature for accurate classification
                    }
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"].strip()
                
                # Extract JSON if there's surrounding text
                import json
                if "{" in content and "}" in content:
                    content = content[content.find("{"):content.rfind("}")+1]
                
                return json.loads(content)
        except Exception as e:
            print(f"Internal AI Verify error: {e}")
            return {"is_scam": False, "confidence": 0.0}

# Singleton instance
honeypot_agent = HoneypotAgent()

