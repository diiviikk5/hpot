"""
Intelligence extraction and aggregation from conversations.
"""
from typing import Dict, List, Any
from ..detection.patterns import pattern_matcher
from ..models import IntelligenceOutput, URLAnalysis


class IntelligenceExtractor:
    """
    Extracts and structures intelligence from scam conversations.
    """
    
    # Suspicious URL indicators
    SUSPICIOUS_URL_PATTERNS = [
        'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly',
        'click', 'free', 'prize', 'winner', 'claim',
        'verify', 'update', 'secure', 'login', 'bank'
    ]
    
    def extract_from_message(self, message: str) -> Dict[str, Any]:
        """Extract intelligence from a single message."""
        extracted = pattern_matcher.extract_all(message)
        return extracted
    
    def analyze_urls(self, urls: List[str]) -> List[URLAnalysis]:
        """Analyze extracted URLs for threat indicators."""
        analyzed = []
        for url in urls:
            url_lower = url.lower()
            threats = []
            is_suspicious = False
            
            # Check for URL shorteners
            if any(shortener in url_lower for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']):
                threats.append("url_shortener")
                is_suspicious = True
            
            # Check for suspicious keywords
            for pattern in self.SUSPICIOUS_URL_PATTERNS:
                if pattern in url_lower:
                    threats.append(f"suspicious_keyword:{pattern}")
                    is_suspicious = True
            
            # Check for IP-based URLs
            import re
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                threats.append("ip_based_url")
                is_suspicious = True
            
            # Check for typosquatting indicators
            common_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'bank']
            for domain in common_domains:
                if domain in url_lower and not f'{domain}.com' in url_lower and not f'{domain}.co' in url_lower:
                    threats.append("possible_typosquatting")
                    is_suspicious = True
                    break
            
            analyzed.append(URLAnalysis(
                url=url,
                is_suspicious=is_suspicious,
                threat_indicators=list(set(threats))
            ))
        
        return analyzed
    
    def build_intelligence_output(
        self,
        conversation_extracted: Dict[str, List],
        scam_tactics: List[str]
    ) -> IntelligenceOutput:
        """Build structured intelligence output."""
        
        # Analyze URLs
        urls = conversation_extracted.get('urls', [])
        analyzed_urls = self.analyze_urls(urls)
        
        # Build extracted entities from money amounts and other data
        entities = {}
        money = conversation_extracted.get('money_amounts', [])
        if money:
            entities['money_amounts'] = money
        
        return IntelligenceOutput(
            upi_ids=conversation_extracted.get('upi_ids', []),
            bank_accounts=conversation_extracted.get('bank_accounts', []),
            ifsc_codes=conversation_extracted.get('ifsc_codes', []),
            phone_numbers=conversation_extracted.get('phone_numbers', []),
            urls=analyzed_urls,
            email_addresses=conversation_extracted.get('emails', []),
            scam_tactics=scam_tactics,
            extracted_entities=entities
        )
    
    def aggregate_intelligence(
        self,
        all_messages: List[str],
        tactics: List[str]
    ) -> IntelligenceOutput:
        """Aggregate intelligence from all messages in a conversation."""
        combined = {
            'upi_ids': [],
            'bank_accounts': [],
            'ifsc_codes': [],
            'phone_numbers': [],
            'urls': [],
            'emails': [],
            'money_amounts': []
        }
        
        for msg in all_messages:
            extracted = self.extract_from_message(msg)
            for key in combined:
                if key in extracted:
                    for item in extracted[key]:
                        if item not in combined[key]:
                            combined[key].append(item)
        
        return self.build_intelligence_output(combined, tactics)


# Singleton instance
intelligence_extractor = IntelligenceExtractor()
