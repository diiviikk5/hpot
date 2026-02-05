"""
Enhanced multi-layer scam detection engine.
Combines keywords, patterns, heuristics, and behavioral analysis.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
from .patterns import pattern_matcher
from .keywords import ScamKeywords


@dataclass
class DetectionResult:
    """Result of scam detection analysis."""
    is_scam: bool
    confidence: float
    scam_type: Optional[str]
    tactics: List[str]
    extracted_patterns: Dict[str, List]
    keyword_matches: Dict[str, List[str]]
    heuristic_triggers: List[str]
    risk_score: float = 0.0


class ScamDetector:
    """
    Advanced multi-layer scam detection engine optimized for Indian scams.
    
    Detection layers:
    1. Keyword analysis with weighted scoring
    2. Pattern extraction and scoring
    3. Heuristic rule matching
    4. Combination analysis
    5. Scam type classification
    """
    
    # Scam type to keyword category mapping
    SCAM_TYPE_MAPPING = {
        'lottery_fraud': ['reward'],
        'bank_impersonation': ['authority', 'threat', 'info_request'],
        'government_impersonation': ['authority', 'threat'],
        'upi_fraud': ['payment', 'info_request'],
        'job_scam': ['job_scam', 'payment'],
        'investment_scam': ['investment'],
        'romance_scam': ['romance', 'payment'],
        'delivery_scam': ['delivery', 'payment'],
        'tech_support_scam': ['info_request', 'threat'],
        'advance_fee_fraud': ['reward', 'payment'],
        'phishing': ['info_request', 'authority'],
    }
    
    # High-risk keyword combinations
    HIGH_RISK_COMBINATIONS = [
        ({'urgency', 'payment'}, 0.3),  # Urgent payment request
        ({'authority', 'threat'}, 0.35),  # Authority with threats
        ({'reward', 'payment'}, 0.35),  # Prize requiring payment
        ({'threat', 'payment'}, 0.4),  # Threat demanding payment
        ({'info_request', 'urgency'}, 0.3),  # Urgent info request
        ({'authority', 'info_request'}, 0.25),  # Authority asking for info
        ({'job_scam', 'payment'}, 0.35),  # Job requiring payment
        ({'investment', 'urgency'}, 0.3),  # Urgent investment
    ]
    
    def __init__(self, confidence_threshold: float = 0.5):
        self.confidence_threshold = confidence_threshold
        self.keywords = ScamKeywords()
    
    def detect(self, message: str) -> DetectionResult:
        """
        Perform comprehensive scam detection on a message.
        
        Args:
            message: The text message to analyze
            
        Returns:
            DetectionResult with all analysis details
        """
        if not message or len(message.strip()) < 3:
            return DetectionResult(
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                tactics=[],
                extracted_patterns={},
                keyword_matches={},
                heuristic_triggers=[],
            )
        
        text_lower = message.lower()
        
        # Layer 1: Keyword analysis
        keyword_scores, keyword_matches = self._analyze_keywords(text_lower)
        
        # Layer 2: Pattern extraction
        patterns = pattern_matcher.extract_all(message)
        
        # Layer 3: Pattern scoring
        pattern_score = self._calculate_pattern_score(patterns)
        
        # Layer 4: Heuristic analysis
        heuristic_score, heuristics = self._analyze_heuristics(text_lower, patterns, keyword_matches)
        
        # Layer 5: Combination analysis
        combination_score = self._analyze_combinations(keyword_matches)
        
        # Layer 6: Calculate final score
        final_score = self._calculate_final_score(
            keyword_scores, pattern_score, heuristic_score, combination_score
        )
        
        # Determine scam type
        scam_type = self._determine_scam_type(keyword_matches, patterns, heuristics)
        
        # Identify tactics
        tactics = self._identify_tactics(keyword_matches, patterns, heuristics)
        
        # Risk assessment
        risk_score = min(1.0, final_score * 1.2)
        
        return DetectionResult(
            is_scam=final_score >= self.confidence_threshold,
            confidence=min(1.0, final_score),
            scam_type=scam_type,
            tactics=tactics,
            extracted_patterns=patterns,
            keyword_matches=keyword_matches,
            heuristic_triggers=heuristics,
            risk_score=risk_score,
        )
    
    def _analyze_keywords(self, text: str) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        """Analyze text for scam keywords with weighted scoring."""
        scores = {}
        matches = {}
        
        for category, keywords in self.keywords.get_all_categories().items():
            category_score = 0.0
            category_matches = []
            
            for keyword, weight in keywords.items():
                # Check for keyword presence
                if keyword in text:
                    category_score += weight
                    category_matches.append(keyword)
                    
                    # Bonus for exact phrase match (not part of another word)
                    if f' {keyword} ' in f' {text} ':
                        category_score += weight * 0.2
            
            # Normalize category score
            if category_matches:
                scores[category] = min(1.0, category_score / len(category_matches))
            else:
                scores[category] = 0.0
            matches[category] = category_matches
        
        return scores, matches
    
    def _calculate_pattern_score(self, patterns: Dict[str, List]) -> float:
        """Calculate score based on extracted patterns."""
        score = 0.0
        
        # Financial indicators are high-value
        if patterns.get('upi_ids'):
            score += 0.4 * min(1.0, len(patterns['upi_ids']))
        if patterns.get('bank_accounts'):
            score += 0.35 * min(1.0, len(patterns['bank_accounts']))
        if patterns.get('ifsc_codes'):
            score += 0.25
        
        # Contact info
        if patterns.get('phone_numbers'):
            score += 0.2 * min(1.0, len(patterns['phone_numbers']))
        if patterns.get('messaging_numbers'):
            score += 0.25
        
        # Money mentions
        if patterns.get('money_amounts'):
            score += 0.25 * min(1.0, len(patterns['money_amounts']))
        
        # URLs are suspicious
        if patterns.get('urls'):
            score += 0.3
        
        # PII requests
        if patterns.get('aadhaar_numbers') or patterns.get('pan_numbers'):
            score += 0.3
        
        # Reference numbers (fake official-ness)
        if patterns.get('reference_numbers'):
            score += 0.2
        
        return min(1.0, score)
    
    def _analyze_heuristics(
        self, 
        text: str, 
        patterns: Dict[str, List],
        keyword_matches: Dict[str, List[str]]
    ) -> Tuple[float, List[str]]:
        """Apply heuristic rules for scam detection."""
        score = 0.0
        triggers = []
        
        # Rule 1: Urgency + Financial request
        if keyword_matches.get('urgency') and (patterns.get('upi_ids') or patterns.get('bank_accounts')):
            score += 0.4
            triggers.append('urgent_financial_request')
        
        # Rule 2: Authority claim + Threat
        if keyword_matches.get('authority') and keyword_matches.get('threat'):
            score += 0.45
            triggers.append('authority_with_threat')
        
        # Rule 3: Prize/Reward + Fee request
        if keyword_matches.get('reward') and keyword_matches.get('payment'):
            score += 0.5
            triggers.append('prize_requires_payment')
        
        # Rule 4: OTP/CVV request (almost always scam)
        otp_keywords = {'otp', 'cvv', 'pin', 'atm pin', 'password'}
        if any(kw in text for kw in otp_keywords):
            score += 0.6
            triggers.append('sensitive_info_request')
        
        # Rule 5: Remote access tools
        remote_tools = {'anydesk', 'teamviewer', 'quick support', 'screen share'}
        if any(tool in text for tool in remote_tools):
            score += 0.7
            triggers.append('remote_access_request')
        
        # Rule 6: KYC urgency
        if 'kyc' in text and keyword_matches.get('urgency'):
            score += 0.45
            triggers.append('kyc_urgency')
        
        # Rule 7: Account blocked/suspended + action required
        blocked_keywords = {'blocked', 'suspended', 'frozen', 'deactivated', 'closed'}
        if any(kw in text for kw in blocked_keywords) and keyword_matches.get('urgency'):
            score += 0.5
            triggers.append('account_threat_urgency')
        
        # Rule 8: Legal/arrest threat
        legal_keywords = {'arrest', 'warrant', 'fir', 'court', 'jail', 'police'}
        if any(kw in text for kw in legal_keywords):
            score += 0.45
            triggers.append('legal_threat')
        
        # Rule 9: Job with registration fee
        if keyword_matches.get('job_scam') and keyword_matches.get('payment'):
            score += 0.55
            triggers.append('job_fee_scam')
        
        # Rule 10: Investment with guaranteed returns
        guaranteed_keywords = {'guaranteed', 'fixed returns', 'assured', 'no risk', '100%'}
        if keyword_matches.get('investment') and any(kw in text for kw in guaranteed_keywords):
            score += 0.6
            triggers.append('investment_guaranteed_returns')
        
        # Rule 11: Lottery/lucky draw (almost always scam in unsolicited messages)
        lottery_keywords = {'lottery', 'lucky draw', 'jackpot', 'bumper prize'}
        if any(kw in text for kw in lottery_keywords):
            score += 0.55
            triggers.append('lottery_scam')
        
        # Rule 12: WhatsApp/Telegram contact with payment
        if patterns.get('messaging_numbers') and keyword_matches.get('payment'):
            score += 0.35
            triggers.append('messaging_payment_request')
        
        # Rule 13: Impersonation signals
        impersonation_signals = ['i am calling from', 'this is', 'speaking from', 'officer from']
        if any(sig in text for sig in impersonation_signals) and keyword_matches.get('authority'):
            score += 0.25
            triggers.append('impersonation_signals')
        
        # Rule 14: Double/triple money promises
        if 'double' in text or 'triple' in text:
            if 'money' in text or 'investment' in text or patterns.get('money_amounts'):
                score += 0.65
                triggers.append('money_multiplication_promise')
        
        # Rule 15: Excessive urgency
        urgency_count = len(keyword_matches.get('urgency', []))
        if urgency_count >= 3:
            score += 0.3
            triggers.append('excessive_urgency')
        
        return min(1.0, score), triggers
    
    def _analyze_combinations(self, keyword_matches: Dict[str, List[str]]) -> float:
        """Analyze high-risk keyword combinations."""
        score = 0.0
        matched_categories = {cat for cat, matches in keyword_matches.items() if matches}
        
        for combination, bonus in self.HIGH_RISK_COMBINATIONS:
            if combination.issubset(matched_categories):
                score += bonus
        
        return min(0.5, score)  # Cap combination bonus
    
    def _calculate_final_score(
        self,
        keyword_scores: Dict[str, float],
        pattern_score: float,
        heuristic_score: float,
        combination_score: float
    ) -> float:
        """Calculate final confidence score."""
        # Weight the different components
        max_keyword_score = max(keyword_scores.values()) if keyword_scores else 0.0
        avg_keyword_score = sum(keyword_scores.values()) / len(keyword_scores) if keyword_scores else 0.0
        
        # Weighted combination
        final_score = (
            max_keyword_score * 0.25 +
            avg_keyword_score * 0.10 +
            pattern_score * 0.20 +
            heuristic_score * 0.35 +
            combination_score * 0.10
        )
        
        # Boost if multiple strong signals
        strong_signals = sum([
            max_keyword_score > 0.5,
            pattern_score > 0.3,
            heuristic_score > 0.3,
            combination_score > 0.2,
        ])
        
        if strong_signals >= 3:
            final_score = min(1.0, final_score * 1.3)
        elif strong_signals >= 2:
            final_score = min(1.0, final_score * 1.15)
        
        return min(1.0, final_score)
    
    def _determine_scam_type(
        self,
        keyword_matches: Dict[str, List[str]],
        patterns: Dict[str, List],
        heuristics: List[str]
    ) -> Optional[str]:
        """Determine the most likely scam type."""
        type_scores: Dict[str, float] = {}
        
        for scam_type, categories in self.SCAM_TYPE_MAPPING.items():
            score = 0.0
            for category in categories:
                if keyword_matches.get(category):
                    score += len(keyword_matches[category]) * 0.3
            type_scores[scam_type] = score
        
        # Boost based on heuristics
        heuristic_type_map = {
            'lottery_scam': 'lottery_fraud',
            'prize_requires_payment': 'advance_fee_fraud',
            'authority_with_threat': 'government_impersonation',
            'legal_threat': 'government_impersonation',
            'kyc_urgency': 'phishing',
            'sensitive_info_request': 'phishing',
            'remote_access_request': 'tech_support_scam',
            'job_fee_scam': 'job_scam',
            'investment_guaranteed_returns': 'investment_scam',
            'money_multiplication_promise': 'investment_scam',
            'account_threat_urgency': 'bank_impersonation',
            'urgent_financial_request': 'upi_fraud',
        }
        
        for heuristic in heuristics:
            if heuristic in heuristic_type_map:
                scam_type = heuristic_type_map[heuristic]
                type_scores[scam_type] = type_scores.get(scam_type, 0) + 0.5
        
        # Special pattern-based detection
        if patterns.get('upi_ids') and not type_scores.get('upi_fraud', 0):
            type_scores['upi_fraud'] = type_scores.get('upi_fraud', 0) + 0.4
        
        if not type_scores or max(type_scores.values()) == 0:
            return None
        
        # Return highest scoring type
        best_type = max(type_scores, key=type_scores.get)
        if type_scores[best_type] > 0.2:
            return best_type
        return 'unknown'
    
    def _identify_tactics(
        self,
        keyword_matches: Dict[str, List[str]],
        patterns: Dict[str, List],
        heuristics: List[str]
    ) -> List[str]:
        """Identify specific scam tactics used."""
        tactics = []
        
        tactic_map = {
            'urgency': 'time_pressure',
            'authority': 'authority_impersonation',
            'reward': 'lottery_bait',
            'threat': 'fear_tactics',
            'payment': 'fee_demand',
            'info_request': 'data_harvesting',
            'job_scam': 'job_bait',
            'investment': 'investment_bait',
            'romance': 'romance_bait',
            'delivery': 'delivery_bait',
        }
        
        for category, tactic in tactic_map.items():
            if keyword_matches.get(category):
                tactics.append(tactic)
        
        # Add pattern-based tactics
        if patterns.get('upi_ids') or patterns.get('bank_accounts'):
            tactics.append('financial_extraction')
        if patterns.get('urls'):
            tactics.append('phishing_links')
        if patterns.get('phone_numbers') or patterns.get('messaging_numbers'):
            tactics.append('contact_collection')
        
        # Add heuristic-based tactics
        tactics.extend([h for h in heuristics if h not in tactics])
        
        return list(set(tactics))


# Singleton instance
scam_detector = ScamDetector(confidence_threshold=0.45)
