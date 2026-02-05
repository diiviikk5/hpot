"""
Keyword databases for scam detection.
Categorized by scam type and linguistic patterns.
"""
from typing import Dict, List, Set


class ScamKeywords:
    """
    Keyword database for detecting scam indicators.
    Organized by category with confidence weights.
    """
    
    # Urgency signals - create pressure to act quickly
    URGENCY_KEYWORDS: Dict[str, float] = {
        'urgent': 0.7,
        'immediately': 0.8,
        'right now': 0.7,
        'today only': 0.8,
        'expires': 0.6,
        'last chance': 0.8,
        'limited time': 0.7,
        'act now': 0.8,
        'hurry': 0.6,
        'quick': 0.4,
        'asap': 0.6,
        'deadline': 0.5,
        'within 24 hours': 0.7,
        'within 1 hour': 0.8,
        'before midnight': 0.7,
        'don\'t delay': 0.7,
        'time sensitive': 0.7,
        'final notice': 0.8,
        'last warning': 0.8,
    }
    
    # Authority impersonation - pretending to be official entities
    AUTHORITY_KEYWORDS: Dict[str, float] = {
        'rbi': 0.8,
        'reserve bank': 0.8,
        'income tax': 0.8,
        'it department': 0.7,
        'police': 0.7,
        'cyber cell': 0.8,
        'court': 0.6,
        'legal': 0.5,
        'government': 0.6,
        'ministry': 0.7,
        'official': 0.5,
        'authorized': 0.5,
        'verified': 0.4,
        'cbi': 0.8,
        'ed': 0.7,
        'enforcement': 0.7,
        'customs': 0.7,
        'sebi': 0.7,
        'bank manager': 0.7,
        'customer care': 0.6,
        'security team': 0.7,
    }
    
    # Reward/lottery bait - promises of money or prizes
    REWARD_KEYWORDS: Dict[str, float] = {
        'lottery': 0.9,
        'winner': 0.7,
        'won': 0.6,
        'prize': 0.7,
        'reward': 0.6,
        'cashback': 0.5,
        'bonus': 0.5,
        'lucky': 0.6,
        'congratulations': 0.6,
        'selected': 0.5,
        'chosen': 0.5,
        'jackpot': 0.9,
        'crore': 0.5,
        'lakh': 0.4,
        'gift': 0.4,
        'free money': 0.9,
        'claim': 0.6,
        'redeem': 0.5,
    }
    
    # Threat indicators - scare tactics
    THREAT_KEYWORDS: Dict[str, float] = {
        'arrest': 0.9,
        'arrested': 0.9,
        'warrant': 0.9,
        'legal action': 0.8,
        'case filed': 0.8,
        'fir': 0.8,
        'complaint': 0.5,
        'suspend': 0.7,
        'suspended': 0.7,
        'blocked': 0.6,
        'frozen': 0.7,
        'freeze': 0.7,
        'terminate': 0.6,
        'penalty': 0.7,
        'fine': 0.5,
        'prosecution': 0.8,
        'jail': 0.9,
        'prison': 0.9,
        'court summons': 0.9,
        'blacklisted': 0.8,
    }
    
    # Payment requests - asking for money
    PAYMENT_KEYWORDS: Dict[str, float] = {
        'pay': 0.4,
        'payment': 0.4,
        'send': 0.3,
        'transfer': 0.5,
        'deposit': 0.5,
        'processing fee': 0.8,
        'registration fee': 0.8,
        'tax fee': 0.8,
        'clearance fee': 0.8,
        'advance': 0.6,
        'token amount': 0.8,
        'security deposit': 0.7,
        'refundable': 0.6,
        'upi': 0.4,
        'bank transfer': 0.4,
        'google pay': 0.3,
        'phonepe': 0.3,
        'paytm': 0.3,
    }
    
    # Personal info requests
    INFO_REQUEST_KEYWORDS: Dict[str, float] = {
        'otp': 0.8,
        'pin': 0.7,
        'password': 0.8,
        'cvv': 0.9,
        'card number': 0.9,
        'bank details': 0.8,
        'account number': 0.6,
        'aadhaar': 0.6,
        'pan card': 0.5,
        'kyc': 0.5,
        'verify': 0.4,
        'verification': 0.4,
        'update details': 0.7,
        'confirm identity': 0.7,
        'share': 0.3,
    }
    
    # Job scam indicators
    JOB_SCAM_KEYWORDS: Dict[str, float] = {
        'work from home': 0.6,
        'part time job': 0.6,
        'easy money': 0.8,
        'earn daily': 0.7,
        'no experience': 0.5,
        'guaranteed income': 0.8,
        'high salary': 0.6,
        'immediate joining': 0.5,
        'data entry': 0.5,
        'typing job': 0.6,
        'copy paste': 0.7,
        'task': 0.3,
        'rating': 0.4,
    }
    
    # Investment scam indicators
    INVESTMENT_KEYWORDS: Dict[str, float] = {
        'investment': 0.4,
        'double money': 0.9,
        'guaranteed returns': 0.9,
        'high returns': 0.7,
        'trading': 0.4,
        'crypto': 0.4,
        'bitcoin': 0.4,
        'forex': 0.5,
        'stock tip': 0.7,
        'insider': 0.7,
        'profit': 0.4,
        'roi': 0.5,
        'scheme': 0.5,
        'mlm': 0.8,
    }
    
    @classmethod
    def get_all_categories(cls) -> Dict[str, Dict[str, float]]:
        """Return all keyword categories."""
        return {
            'urgency': cls.URGENCY_KEYWORDS,
            'authority': cls.AUTHORITY_KEYWORDS,
            'reward': cls.REWARD_KEYWORDS,
            'threat': cls.THREAT_KEYWORDS,
            'payment': cls.PAYMENT_KEYWORDS,
            'info_request': cls.INFO_REQUEST_KEYWORDS,
            'job_scam': cls.JOB_SCAM_KEYWORDS,
            'investment': cls.INVESTMENT_KEYWORDS,
        }
    
    @classmethod
    def get_all_keywords(cls) -> Set[str]:
        """Return all keywords as a flat set."""
        all_kw = set()
        for category in cls.get_all_categories().values():
            all_kw.update(category.keys())
        return all_kw
