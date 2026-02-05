"""
Multi-layer scam detection engine.
Analyzes messages using keywords, patterns, and heuristics.
"""
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
from .patterns import pattern_matcher
from .keywords import ScamKeywords


@dataclass
class DetectionResult:
    """Result of scam detection analysis."""
    is_scam: bool
    confidence: float
    scam_type: Optional[str]
    indicators: List[str] = field(default_factory=list)
    keyword_matches: Dict[str, List[str]] = field(default_factory=dict)
    extracted_patterns: Dict[str, List[str]] = field(default_factory=dict)
    tactics: List[str] = field(default_factory=list)


class ScamDetector:
    """
    Multi-layer scam detection engine.
    
    Detection layers:
    1. Keyword matching with weighted scoring
    2. Pattern detection for financial identifiers
    3. Heuristic analysis for scam structure
    4. Context-based indicators
    """
    
    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        self.keywords = ScamKeywords()
    
    def detect(self, message: str) -> DetectionResult:
        """
        Analyze a message for scam indicators.
        
        Args:
            message: The message text to analyze
            
        Returns:
            DetectionResult with detection details
        """
        text_lower = message.lower()
        
        # Layer 1: Keyword analysis
        keyword_scores, keyword_matches = self._analyze_keywords(text_lower)
        
        # Layer 2: Pattern extraction
        patterns = pattern_matcher.extract_all(message)
        
        # Layer 3: Calculate pattern score
        pattern_score = self._calculate_pattern_score(patterns)
        
        # Layer 4: Heuristic analysis
        heuristic_score, heuristics = self._analyze_heuristics(text_lower, patterns)
        
        # Combine scores
        combined_score = self._combine_scores(keyword_scores, pattern_score, heuristic_score)
        
        # Determine scam type
        scam_type = self._determine_scam_type(keyword_matches, patterns, text_lower)
        
        # Build indicators list
        indicators = self._build_indicators(keyword_matches, patterns, heuristics)
        
        # Identify tactics
        tactics = self._identify_tactics(keyword_matches, text_lower)
        
        # Determine if it's a scam
        is_scam = combined_score >= self.confidence_threshold
        
        return DetectionResult(
            is_scam=is_scam,
            confidence=min(combined_score, 1.0),
            scam_type=scam_type if is_scam else None,
            indicators=indicators,
            keyword_matches=keyword_matches,
            extracted_patterns={k: v for k, v in patterns.items() if v},
            tactics=tactics
        )
    
    def _analyze_keywords(self, text: str) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        """Analyze text for keyword matches."""
        scores = {}
        matches = {}
        
        for category, keywords in ScamKeywords.get_all_categories().items():
            category_matches = []
            max_score = 0.0
            
            for keyword, weight in keywords.items():
                if keyword in text:
                    category_matches.append(keyword)
                    max_score = max(max_score, weight)
            
            if category_matches:
                matches[category] = category_matches
                # Score based on max weight and number of matches
                scores[category] = min(max_score + (len(category_matches) - 1) * 0.1, 1.0)
        
        return scores, matches
    
    def _calculate_pattern_score(self, patterns: Dict[str, List]) -> float:
        """Calculate score based on extracted patterns."""
        score = 0.0
        
        # UPI IDs are strong indicators
        if patterns.get('upi_ids'):
            score += 0.3 * len(patterns['upi_ids'])
        
        # Bank accounts combined with other indicators
        if patterns.get('bank_accounts'):
            score += 0.2 * len(patterns['bank_accounts'])
        
        # URLs are suspicious
        if patterns.get('urls'):
            score += 0.25 * len(patterns['urls'])
        
        # Money amounts mentioned
        if patterns.get('money_amounts'):
            score += 0.15 * min(len(patterns['money_amounts']), 2)
        
        return min(score, 0.5)  # Cap pattern score contribution
    
    def _analyze_heuristics(self, text: str, patterns: Dict) -> Tuple[float, List[str]]:
        """Apply heuristic rules for scam detection."""
        score = 0.0
        heuristics = []
        
        # Heuristic 1: Urgency + Payment request
        has_urgency = any(kw in text for kw in ['urgent', 'immediately', 'now', 'today'])
        has_payment = any(kw in text for kw in ['pay', 'send', 'transfer', 'deposit'])
        if has_urgency and has_payment:
            score += 0.3
            heuristics.append("urgency_with_payment")
        
        # Heuristic 2: Reward + Fee request
        has_reward = any(kw in text for kw in ['won', 'winner', 'prize', 'lottery', 'congratulations'])
        has_fee = any(kw in text for kw in ['fee', 'charge', 'tax', 'processing'])
        if has_reward and has_fee:
            score += 0.4
            heuristics.append("reward_with_fee")
        
        # Heuristic 3: Authority + Threat
        has_authority = any(kw in text for kw in ['rbi', 'police', 'court', 'government', 'bank'])
        has_threat = any(kw in text for kw in ['arrest', 'legal', 'suspend', 'freeze', 'block'])
        if has_authority and has_threat:
            score += 0.35
            heuristics.append("authority_with_threat")
        
        # Heuristic 4: OTP/CVV request (very high confidence)
        if any(kw in text for kw in ['otp', 'cvv', 'pin', 'password']):
            score += 0.5
            heuristics.append("sensitive_info_request")
        
        # Heuristic 5: Money + UPI mentioned together
        if patterns.get('money_amounts') and patterns.get('upi_ids'):
            score += 0.3
            heuristics.append("money_with_upi")
        
        # Heuristic 6: Suspicious link patterns
        for url in patterns.get('urls', []):
            url_lower = url.lower()
            if any(sus in url_lower for sus in ['bit.ly', 'tinyurl', 'click', 'free', 'prize']):
                score += 0.3
                heuristics.append("suspicious_url")
                break
        
        return min(score, 0.6), heuristics
    
    def _combine_scores(self, keyword_scores: Dict[str, float], 
                       pattern_score: float, heuristic_score: float) -> float:
        """Combine all scores into final confidence."""
        # Average keyword score
        if keyword_scores:
            keyword_avg = sum(keyword_scores.values()) / len(keyword_scores)
            # Bonus for multiple categories
            multi_category_bonus = min(len(keyword_scores) * 0.05, 0.2)
            keyword_contribution = keyword_avg * 0.4 + multi_category_bonus
        else:
            keyword_contribution = 0.0
        
        # Weight contributions
        final_score = (
            keyword_contribution +
            pattern_score * 0.6 +
            heuristic_score * 0.8
        )
        
        return min(final_score, 1.0)
    
    def _determine_scam_type(self, keyword_matches: Dict[str, List[str]], 
                            patterns: Dict, text: str) -> Optional[str]:
        """Determine the type of scam based on indicators."""
        # Priority-based scam type detection
        if 'lottery' in text or 'jackpot' in text or 'prize' in text:
            return "lottery_fraud"
        
        if keyword_matches.get('investment'):
            return "investment_scam"
        
        if keyword_matches.get('job_scam'):
            return "job_scam"
        
        if keyword_matches.get('authority') and keyword_matches.get('threat'):
            if 'bank' in text or 'rbi' in text:
                return "bank_impersonation"
            return "government_impersonation"
        
        if patterns.get('urls'):
            return "phishing"
        
        if keyword_matches.get('payment') and patterns.get('upi_ids'):
            return "upi_fraud"
        
        if keyword_matches.get('reward') and keyword_matches.get('payment'):
            return "advance_fee_fraud"
        
        if keyword_matches.get('info_request'):
            return "phishing"
        
        return "unknown"
    
    def _build_indicators(self, keyword_matches: Dict, patterns: Dict, 
                         heuristics: List[str]) -> List[str]:
        """Build human-readable list of indicators."""
        indicators = []
        
        for category, keywords in keyword_matches.items():
            indicators.append(f"{category}_keywords: {', '.join(keywords[:3])}")
        
        if patterns.get('upi_ids'):
            indicators.append(f"upi_detected: {patterns['upi_ids']}")
        
        if patterns.get('urls'):
            indicators.append(f"urls_detected: {len(patterns['urls'])} URL(s)")
        
        if patterns.get('bank_accounts'):
            indicators.append(f"bank_accounts_detected: {len(patterns['bank_accounts'])}")
        
        for h in heuristics:
            indicators.append(f"heuristic: {h}")
        
        return indicators
    
    def _identify_tactics(self, keyword_matches: Dict, text: str) -> List[str]:
        """Identify specific scam tactics being used."""
        tactics = []
        
        if keyword_matches.get('urgency'):
            tactics.append("urgency_creation")
        
        if keyword_matches.get('authority'):
            tactics.append("authority_impersonation")
        
        if keyword_matches.get('reward'):
            tactics.append("reward_bait")
        
        if keyword_matches.get('threat'):
            tactics.append("fear_tactics")
        
        if keyword_matches.get('payment'):
            tactics.append("payment_request")
        
        if keyword_matches.get('info_request'):
            tactics.append("info_harvesting")
        
        if 'click' in text or 'link' in text:
            tactics.append("link_luring")
        
        if 'otp' in text.lower() or 'cvv' in text.lower():
            tactics.append("credential_theft")
        
        return tactics


# Singleton instance
scam_detector = ScamDetector()
