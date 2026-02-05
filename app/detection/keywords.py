"""
Comprehensive scam keyword database for Indian scam detection.
Optimized for maximum detection accuracy.
"""
from typing import Dict, List, Set


class ScamKeywords:
    """
    Extensive keyword database categorized by scam tactics.
    Each keyword has an associated confidence weight.
    """
    
    # Urgency/Pressure tactics - immediate action required
    URGENCY_KEYWORDS: Dict[str, float] = {
        'urgent': 0.7, 'immediately': 0.8, 'right now': 0.8, 'asap': 0.7,
        'within 24 hours': 0.8, 'within 2 hours': 0.9, 'expires today': 0.85,
        'last chance': 0.8, 'final notice': 0.85, 'act now': 0.8,
        'time sensitive': 0.75, 'hurry': 0.7, 'quickly': 0.6,
        'dont delay': 0.75, "don't delay": 0.75, 'deadline': 0.7,
        'limited time': 0.75, 'expiring': 0.7, 'about to expire': 0.8,
        'running out': 0.7, 'last warning': 0.85, 'must act': 0.8,
        'instant': 0.6, 'now only': 0.7, 'today only': 0.75,
        'before midnight': 0.8, 'before 6 pm': 0.8, 'before closing': 0.75,
        'turant': 0.8, 'abhi': 0.7, 'jaldi': 0.7, 'fatafat': 0.75,
    }
    
    # Authority impersonation - official entities
    AUTHORITY_KEYWORDS: Dict[str, float] = {
        # Banks
        'rbi': 0.8, 'reserve bank': 0.85, 'sbi': 0.7, 'state bank': 0.7,
        'hdfc': 0.65, 'icici': 0.65, 'axis bank': 0.65, 'kotak': 0.6,
        'pnb': 0.65, 'punjab national': 0.65, 'bank of baroda': 0.65,
        'canara bank': 0.65, 'union bank': 0.65, 'bob': 0.6,
        'bank manager': 0.75, 'bank officer': 0.75, 'bank executive': 0.7,
        # Government
        'government': 0.7, 'police': 0.75, 'cyber cell': 0.8, 'cyber crime': 0.8,
        'income tax': 0.8, 'it department': 0.8, 'tax department': 0.8,
        'customs': 0.75, 'central bureau': 0.8, 'cbi': 0.85, 'enforcement': 0.8,
        'ed': 0.8, 'narcotics': 0.85, 'ncb': 0.85, 'court': 0.75,
        'high court': 0.8, 'supreme court': 0.85, 'legal action': 0.8,
        'warrant': 0.85, 'arrest warrant': 0.9, 'fir': 0.8, 'case registered': 0.8,
        'ministry': 0.7, 'central government': 0.75, 'state government': 0.7,
        # Telecom
        'trai': 0.8, 'telecom authority': 0.8, 'airtel': 0.6, 'jio': 0.6,
        'vodafone': 0.6, 'bsnl': 0.6, 'sim block': 0.8, 'number block': 0.8,
        # Other
        'customer care': 0.65, 'customer service': 0.65, 'support team': 0.6,
        'technical support': 0.6, 'helpdesk': 0.6, 'official': 0.6,
        'sarkar': 0.7, 'sarkari': 0.7, 'adhikari': 0.7,
    }
    
    # Reward/Prize bait
    REWARD_KEYWORDS: Dict[str, float] = {
        'congratulations': 0.8, 'winner': 0.85, 'won': 0.8, 'prize': 0.8,
        'lottery': 0.9, 'lucky draw': 0.9, 'jackpot': 0.9, 'bumper': 0.85,
        'crore': 0.7, 'lakh': 0.6, 'lakhs': 0.6, 'crores': 0.7,
        'cash prize': 0.9, 'gift': 0.6, 'reward': 0.7, 'bonus': 0.65,
        'selected': 0.7, 'chosen': 0.7, 'special offer': 0.7,
        'free': 0.5, 'complimentary': 0.6, 'exclusive': 0.55,
        'guaranteed': 0.7, 'assured': 0.7, 'confirmed winner': 0.9,
        'claim your': 0.8, 'collect your': 0.8, 'redeem': 0.7,
        'iphone': 0.7, 'samsung': 0.6, 'car': 0.6, 'bike': 0.6,
        'gold coin': 0.75, 'amazon voucher': 0.7, 'flipkart voucher': 0.7,
        'badhai ho': 0.8, 'mubaarak': 0.8, 'jeet gaye': 0.85,
        'inaam': 0.8, 'uphaar': 0.7,
    }
    
    # Threat/Fear tactics
    THREAT_KEYWORDS: Dict[str, float] = {
        'blocked': 0.75, 'suspended': 0.8, 'frozen': 0.8, 'deactivated': 0.75,
        'terminated': 0.75, 'closed': 0.6, 'compromised': 0.8, 'hacked': 0.8,
        'unauthorized': 0.75, 'suspicious activity': 0.8, 'fraud detected': 0.85,
        'illegal': 0.8, 'criminal': 0.8, 'arrest': 0.85, 'jail': 0.85,
        'penalty': 0.75, 'fine': 0.7, 'legal action': 0.8, 'case': 0.6,
        'money laundering': 0.9, 'drug trafficking': 0.9, 'terrorism': 0.9,
        'pornography': 0.85, 'child porn': 0.95, 'illegal transaction': 0.85,
        'court summons': 0.9, 'non-bailable': 0.9, 'imprisonment': 0.85,
        'seize': 0.8, 'confiscate': 0.8, 'blacklist': 0.8,
        'cibil': 0.7, 'credit score': 0.65, 'loan default': 0.75,
        'emi bounce': 0.7, 'cheque bounce': 0.75,
        'giraftar': 0.85, 'kaid': 0.85, 'saza': 0.8, 'jurmana': 0.75,
    }
    
    # Payment/Money transfer requests
    PAYMENT_KEYWORDS: Dict[str, float] = {
        'transfer': 0.7, 'send money': 0.8, 'pay': 0.6, 'payment': 0.6,
        'processing fee': 0.85, 'registration fee': 0.85, 'verification fee': 0.85,
        'tax': 0.6, 'gst': 0.6, 'tds': 0.65, 'charges': 0.55,
        'deposit': 0.65, 'advance': 0.65, 'token amount': 0.8,
        'refundable': 0.7, 'security deposit': 0.75, 'insurance': 0.6,
        'courier charges': 0.8, 'delivery charges': 0.75, 'shipping fee': 0.75,
        'clearance fee': 0.8, 'customs duty': 0.75, 'release fee': 0.85,
        'activation fee': 0.8, 'subscription': 0.55, 'membership': 0.6,
        'upi': 0.65, 'paytm': 0.6, 'phonepe': 0.6, 'gpay': 0.6,
        'google pay': 0.6, 'bhim': 0.6, 'bank transfer': 0.65,
        'neft': 0.6, 'rtgs': 0.6, 'imps': 0.6,
        'rupees': 0.5, 'rs': 0.5, 'inr': 0.5, '₹': 0.5,
        'bhejo': 0.7, 'paisa bhejo': 0.8, 'amount transfer': 0.75,
    }
    
    # Information request - PII solicitation  
    INFO_REQUEST_KEYWORDS: Dict[str, float] = {
        'otp': 0.9, 'one time password': 0.9, 'verification code': 0.85,
        'pin': 0.75, 'cvv': 0.9, 'card number': 0.9, 'credit card': 0.8,
        'debit card': 0.8, 'atm pin': 0.95, 'bank details': 0.85,
        'account number': 0.8, 'account details': 0.85, 'ifsc': 0.75,
        'aadhaar': 0.7, 'aadhar': 0.7, 'pan card': 0.7, 'pan number': 0.75,
        'date of birth': 0.6, 'dob': 0.6, 'mother maiden': 0.8,
        'password': 0.8, 'login': 0.65, 'credentials': 0.8,
        'net banking': 0.75, 'mobile banking': 0.7, 'internet banking': 0.75,
        'share': 0.5, 'provide': 0.45, 'send me': 0.55, 'tell me': 0.5,
        'verify': 0.55, 'confirm': 0.5, 'update': 0.5,
        'kyc': 0.7, 'kyc update': 0.8, 'kyc verification': 0.8,
        're-kyc': 0.85, 'video kyc': 0.75, 'ekyc': 0.75,
        'anydesk': 0.95, 'teamviewer': 0.95, 'quick support': 0.9,
        'screen share': 0.85, 'remote access': 0.9,
    }
    
    # Job/Employment scams
    JOB_SCAM_KEYWORDS: Dict[str, float] = {
        'work from home': 0.7, 'wfh': 0.65, 'part time': 0.6, 'part-time': 0.6,
        'earn money': 0.75, 'earn from home': 0.8, 'online job': 0.75,
        'typing job': 0.85, 'data entry': 0.7, 'copy paste': 0.8,
        'no experience': 0.7, 'no qualification': 0.75, 'anyone can do': 0.75,
        'daily payment': 0.75, 'weekly payment': 0.7, 'instant payment': 0.8,
        'per task': 0.7, 'per click': 0.75, 'per survey': 0.75,
        'registration required': 0.75, 'joining fee': 0.85, 'training fee': 0.85,
        'kit charges': 0.85, 'material fee': 0.85, 'id card fee': 0.85,
        'earn lakhs': 0.85, 'earn thousands': 0.75, 'high income': 0.7,
        'passive income': 0.7, 'residual income': 0.7,
        'amazon job': 0.8, 'flipkart job': 0.8, 'google job': 0.8,
        'youtube job': 0.8, 'instagram job': 0.8, 'telegram job': 0.85,
        'whatsapp job': 0.85, 'review job': 0.8, 'rating job': 0.8,
        'like job': 0.85, 'subscribe job': 0.85, 'follow job': 0.85,
        'ghar baithe': 0.8, 'ghar se kaam': 0.8, 'paisa kamao': 0.8,
    }
    
    # Investment/Trading scams
    INVESTMENT_SCAM_KEYWORDS: Dict[str, float] = {
        'investment': 0.6, 'invest': 0.55, 'trading': 0.6, 'trade': 0.55,
        'stock': 0.5, 'share market': 0.55, 'forex': 0.7, 'crypto': 0.65,
        'bitcoin': 0.65, 'bitcoin trading': 0.75, 'guaranteed returns': 0.9,
        'fixed returns': 0.85, 'daily returns': 0.9, 'weekly returns': 0.85,
        'double money': 0.95, 'triple money': 0.95, '100% returns': 0.95,
        'no risk': 0.85, 'risk free': 0.85, 'zero risk': 0.9,
        'high returns': 0.75, 'best returns': 0.7, 'assured profit': 0.9,
        'mlm': 0.85, 'network marketing': 0.75, 'referral bonus': 0.7,
        'chain marketing': 0.85, 'pyramid': 0.9, 'ponzi': 0.95,
        'binary': 0.75, 'binary trading': 0.85, 'options trading': 0.7,
        'ipo': 0.6, 'pre-ipo': 0.8, 'unlisted shares': 0.8,
        'mutual fund': 0.55, 'sip': 0.5, 'fd scheme': 0.7,
        'chit fund': 0.75, 'committee': 0.6, 'scheme': 0.5,
        'paisa double': 0.95, 'guaranteed profit': 0.9,
    }
    
    # Relationship/Romance scams
    ROMANCE_SCAM_KEYWORDS: Dict[str, float] = {
        'darling': 0.6, 'dear': 0.5, 'honey': 0.55, 'sweetheart': 0.6,
        'love': 0.4, 'relationship': 0.45, 'marry': 0.55, 'marriage': 0.5,
        'from abroad': 0.7, 'from usa': 0.7, 'from uk': 0.7, 'from dubai': 0.7,
        'army officer': 0.8, 'military': 0.7, 'soldier': 0.7, 'deployed': 0.75,
        'stuck': 0.6, 'stranded': 0.7, 'need help': 0.6, 'emergency': 0.65,
        'send gift': 0.75, 'package stuck': 0.8, 'customs clearance': 0.8,
        'meet you': 0.55, 'come to india': 0.7, 'visit you': 0.6,
        'visa fee': 0.85, 'ticket money': 0.85, 'travel expenses': 0.8,
    }
    
    # Delivery/Courier scams
    DELIVERY_SCAM_KEYWORDS: Dict[str, float] = {
        'delivery': 0.55, 'courier': 0.6, 'parcel': 0.6, 'package': 0.55,
        'shipment': 0.6, 'consignment': 0.65, 'customs': 0.6,
        'fedex': 0.65, 'dhl': 0.65, 'ups': 0.6, 'bluedart': 0.6,
        'dtdc': 0.6, 'india post': 0.6, 'speed post': 0.6,
        'held at customs': 0.85, 'customs clearance': 0.8, 'release': 0.6,
        'illegal items': 0.85, 'drugs found': 0.95, 'contraband': 0.9,
        'declared value': 0.75, 'pay duty': 0.8, 'import duty': 0.75,
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
            'investment': cls.INVESTMENT_SCAM_KEYWORDS,
            'romance': cls.ROMANCE_SCAM_KEYWORDS,
            'delivery': cls.DELIVERY_SCAM_KEYWORDS,
        }
    
    @classmethod
    def get_all_keywords(cls) -> Set[str]:
        """Return all keywords as a flat set."""
        all_keywords = set()
        for category in cls.get_all_categories().values():
            all_keywords.update(category.keys())
        return all_keywords
