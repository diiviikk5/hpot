"""
Advanced intelligence extraction and aggregation.
Optimized for comprehensive scam intelligence gathering.
"""
from typing import Dict, List, Any
from ..detection.patterns import pattern_matcher
from ..models import IntelligenceOutput, URLAnalysis


class IntelligenceExtractor:
    """
    Comprehensive intelligence extraction from scam conversations.
    Analyzes URLs, aggregates data, and builds actionable intelligence.
    """
    
    # Suspicious URL indicators
    SUSPICIOUS_DOMAINS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'bc.vc', 'j.mp', 'shorturl.at'
    }
    
    SUSPICIOUS_KEYWORDS = [
        'click', 'free', 'prize', 'winner', 'claim', 'verify', 'update',
        'secure', 'login', 'bank', 'account', 'password', 'otp', 'kyc',
        'lucky', 'offer', 'bonus', 'gift', 'reward', 'urgent', 'blocked'
    ]
    
    SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.link', '.online', '.site', 
                       '.club', '.tk', '.ml', '.ga', '.cf', '.gq']
    
    def extract_from_message(self, message: str) -> Dict[str, Any]:
        """Extract all intelligence from a message."""
        return pattern_matcher.extract_all(message)
    
    def analyze_url(self, url: str) -> URLAnalysis:
        """Perform detailed URL threat analysis."""
        url_lower = url.lower()
        threats = []
        threat_level = "low"
        is_suspicious = False
        
        # Check for URL shorteners
        for shortener in self.SUSPICIOUS_DOMAINS:
            if shortener in url_lower:
                threats.append("url_shortener")
                is_suspicious = True
                threat_level = "medium"
                break
        
        # Check for suspicious keywords in URL
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                threats.append(f"suspicious_keyword:{keyword}")
                is_suspicious = True
                if threat_level == "low":
                    threat_level = "medium"
        
        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if url_lower.endswith(tld) or tld + '/' in url_lower:
                threats.append("suspicious_tld")
                is_suspicious = True
                threat_level = "high"
                break
        
        # Check for IP-based URLs
        import re
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            threats.append("ip_based_url")
            is_suspicious = True
            threat_level = "high"
        
        # Check for typosquatting indicators
        legit_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                         'paypal', 'paytm', 'phonepe', 'sbi', 'hdfc', 'icici']
        for domain in legit_domains:
            # Check for close but not exact matches
            if domain in url_lower:
                if not any(f'{domain}.com' in url_lower or f'{domain}.co' in url_lower 
                          or f'{domain}.in' in url_lower for domain in legit_domains):
                    threats.append("possible_typosquatting")
                    is_suspicious = True
                    threat_level = "critical"
                    break
        
        # Check for excessive path depth (phishing indicator)
        if url.count('/') > 5:
            threats.append("deep_path_structure")
            is_suspicious = True
        
        # Check for encoded characters
        if '%' in url and any(c in url for c in ['%2F', '%3A', '%40']):
            threats.append("encoded_characters")
            is_suspicious = True
        
        return URLAnalysis(
            url=url,
            is_suspicious=is_suspicious,
            threat_indicators=list(set(threats)),
            threat_level=threat_level
        )
    
    def analyze_urls(self, urls: List[str]) -> List[URLAnalysis]:
        """Analyze multiple URLs."""
        return [self.analyze_url(url) for url in urls]
    
    def build_intelligence_output(
        self,
        extracted: Dict[str, List],
        scam_tactics: List[str] = None
    ) -> IntelligenceOutput:
        """Build comprehensive intelligence output."""
        
        # Analyze URLs
        urls = extracted.get('urls', [])
        analyzed_urls = self.analyze_urls(urls)
        
        # Build additional entities
        entities = {}
        
        # Add money amounts
        money = extracted.get('money_amounts', [])
        if money:
            entities['money_amounts'] = money
        
        # Add Aadhaar if found
        aadhaar = extracted.get('aadhaar_numbers', [])
        if aadhaar:
            entities['aadhaar_numbers'] = aadhaar
        
        # Add PAN if found
        pan = extracted.get('pan_numbers', [])
        if pan:
            entities['pan_numbers'] = pan
        
        # Add messaging numbers
        messaging = extracted.get('messaging_numbers', [])
        if messaging:
            entities['messaging_numbers'] = messaging
        
        # Calculate total extracted
        total = sum([
            len(extracted.get('upi_ids', [])),
            len(extracted.get('bank_accounts', [])),
            len(extracted.get('phone_numbers', [])),
            len(urls),
            len(extracted.get('names', [])),
            len(extracted.get('organizations', [])),
            len(extracted.get('reference_numbers', [])),
        ])
        
        return IntelligenceOutput(
            upi_ids=extracted.get('upi_ids', []),
            bank_accounts=extracted.get('bank_accounts', []),
            ifsc_codes=extracted.get('ifsc_codes', []),
            phone_numbers=extracted.get('phone_numbers', []),
            email_addresses=extracted.get('emails', []),
            urls=analyzed_urls,
            scammer_names=extracted.get('names', []),
            organizations=extracted.get('organizations', []),
            reference_numbers=extracted.get('reference_numbers', []),
            scam_tactics=scam_tactics or [],
            extracted_entities=entities,
            total_entities_extracted=total
        )
    
    def aggregate_intelligence(
        self,
        all_messages: List[str],
        tactics: List[str] = None
    ) -> IntelligenceOutput:
        """Aggregate intelligence from all messages in conversation."""
        combined = {
            'upi_ids': [],
            'bank_accounts': [],
            'ifsc_codes': [],
            'phone_numbers': [],
            'emails': [],
            'urls': [],
            'money_amounts': [],
            'names': [],
            'organizations': [],
            'reference_numbers': [],
            'aadhaar_numbers': [],
            'pan_numbers': [],
            'messaging_numbers': [],
        }
        
        for msg in all_messages:
            extracted = self.extract_from_message(msg)
            for key in combined:
                if key in extracted:
                    for item in extracted[key]:
                        if item and item not in combined[key]:
                            combined[key].append(item)
        
        return self.build_intelligence_output(combined, tactics)
    
    def calculate_intelligence_score(self, intelligence: IntelligenceOutput) -> float:
        """Calculate quality score for extracted intelligence."""
        score = 0.0
        
        # High-value items
        score += len(intelligence.upi_ids) * 0.25
        score += len(intelligence.bank_accounts) * 0.25
        score += len(intelligence.phone_numbers) * 0.15
        
        # Medium-value items
        score += len(intelligence.scammer_names) * 0.1
        score += len(intelligence.organizations) * 0.1
        score += len([u for u in intelligence.urls if u.is_suspicious]) * 0.15
        
        # Lower-value but useful
        score += len(intelligence.ifsc_codes) * 0.1
        score += len(intelligence.reference_numbers) * 0.08
        score += len(intelligence.email_addresses) * 0.05
        
        return min(1.0, score)


# Singleton instance
intelligence_extractor = IntelligenceExtractor()
