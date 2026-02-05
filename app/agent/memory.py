"""
Conversation memory management for multi-turn engagement.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json


@dataclass
class Message:
    """A single message in the conversation."""
    role: str  # "user" (scammer) or "assistant" (honeypot)
    content: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    extracted_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationContext:
    """Context for a conversation session."""
    conversation_id: str
    persona_name: str
    messages: List[Message] = field(default_factory=list)
    extracted_intelligence: Dict[str, List] = field(default_factory=dict)
    scam_type: Optional[str] = None
    engagement_stage: str = "initial"  # initial, engaged, extracting, closing
    turn_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def add_message(self, role: str, content: str, extracted_info: Dict = None):
        """Add a message to the conversation."""
        msg = Message(role=role, content=content, extracted_info=extracted_info or {})
        self.messages.append(msg)
        self.turn_count = len([m for m in self.messages if m.role == "user"])
        self.updated_at = datetime.utcnow().isoformat()
        
        # Update engagement stage based on turn count
        if self.turn_count >= 5:
            self.engagement_stage = "extracting"
        elif self.turn_count >= 2:
            self.engagement_stage = "engaged"
    
    def get_conversation_history(self, max_messages: int = 10) -> List[Dict]:
        """Get conversation history for AI context."""
        recent = self.messages[-max_messages:] if len(self.messages) > max_messages else self.messages
        return [{"role": m.role, "content": m.content} for m in recent]
    
    def merge_intelligence(self, new_intel: Dict[str, List]):
        """Merge newly extracted intelligence."""
        for key, values in new_intel.items():
            if key not in self.extracted_intelligence:
                self.extracted_intelligence[key] = []
            for v in values:
                if v not in self.extracted_intelligence[key]:
                    self.extracted_intelligence[key].append(v)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            "conversation_id": self.conversation_id,
            "persona_name": self.persona_name,
            "messages": [{"role": m.role, "content": m.content, "timestamp": m.timestamp} for m in self.messages],
            "extracted_intelligence": self.extracted_intelligence,
            "scam_type": self.scam_type,
            "engagement_stage": self.engagement_stage,
            "turn_count": self.turn_count,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


class ConversationMemory:
    """
    In-memory storage for conversation contexts.
    Enables multi-turn conversation tracking.
    """
    
    def __init__(self):
        self._conversations: Dict[str, ConversationContext] = {}
    
    def get_or_create(self, conversation_id: str, persona_name: str = "Unknown") -> ConversationContext:
        """Get existing conversation or create new one."""
        if conversation_id not in self._conversations:
            self._conversations[conversation_id] = ConversationContext(
                conversation_id=conversation_id,
                persona_name=persona_name
            )
        return self._conversations[conversation_id]
    
    def get(self, conversation_id: str) -> Optional[ConversationContext]:
        """Get conversation by ID."""
        return self._conversations.get(conversation_id)
    
    def exists(self, conversation_id: str) -> bool:
        """Check if conversation exists."""
        return conversation_id in self._conversations
    
    def update_persona(self, conversation_id: str, persona_name: str):
        """Update the persona for a conversation."""
        if conversation_id in self._conversations:
            self._conversations[conversation_id].persona_name = persona_name
    
    def get_all_conversations(self) -> List[ConversationContext]:
        """Get all conversations."""
        return list(self._conversations.values())
    
    def cleanup_old_conversations(self, max_age_hours: int = 24):
        """Remove conversations older than max_age_hours."""
        now = datetime.utcnow()
        to_remove = []
        for cid, ctx in self._conversations.items():
            created = datetime.fromisoformat(ctx.created_at)
            if (now - created).total_seconds() > max_age_hours * 3600:
                to_remove.append(cid)
        for cid in to_remove:
            del self._conversations[cid]


# Global memory instance
conversation_memory = ConversationMemory()
