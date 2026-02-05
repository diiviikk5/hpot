"""
Enhanced pattern matching for extracting financial and contact information.
Optimized for Indian scam patterns with comprehensive regex.
"""
import re
from typing import Dict, List, Set


class PatternMatcher:
    """
    Comprehensive regex-based pattern extraction for Indian scam intelligence.
    """
    
    # UPI ID patterns (comprehensive)
    UPI_PATTERN = re.compile(
        r'(?:upi[:\s]?|pay[:\s]?|@)?'
        r'([a-zA-Z0-9._-]{3,}@[a-zA-Z]{2,})',
        re.IGNORECASE
    )
    
    # Indian bank account numbers (9-18 digits)
    BANK_ACCOUNT_PATTERN = re.compile(
        r'(?:a/?c|account|acc)[:\s#.-]*(\d{9,18})|'
        r'(?<!\d)(\d{9,18})(?!\d)(?=.*(?:ifsc|bank|account))',
        re.IGNORECASE
    )
    
    # IFSC Code pattern
    IFSC_PATTERN = re.compile(
        r'\b([A-Z]{4}0[A-Z0-9]{6})\b',
        re.IGNORECASE
    )
    
    # Indian phone numbers (multiple formats)
    PHONE_PATTERN = re.compile(
        r'(?:\+91[\s.-]?|91[\s.-]?|0)?'
        r'([6-9]\d{9})\b|'
        r'(?:\+91[\s.-]?)?([6-9]\d{4}[\s.-]?\d{5})',
        re.IGNORECASE
    )
    
    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
        re.IGNORECASE
    )
    
    # URL pattern (comprehensive)
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\']+|'
        r'www\.[^\s<>"\']+|'
        r'\b([a-zA-Z0-9-]+\.(?:com|in|org|net|info|biz|xyz|online|site|club|top|tk|ml|ga|cf|gq|link|click)[/\w.-]*)',
        re.IGNORECASE
    )
    
    # Money amounts (Indian formats)
    MONEY_PATTERN = re.compile(
        r'(?:rs\.?|₹|inr|rupees?)[\s]*([0-9,]+(?:\.[0-9]{1,2})?)|'
        r'([0-9,]+(?:\.[0-9]{1,2})?)[\s]*(?:rs\.?|₹|rupees?|inr)|'
        r'([0-9,]+)[\s]*(?:lakh|lac|crore|cr|k|thousand|hundred)|'
        r'(?:lakh|lac|crore|cr)[\s]*([0-9,]+)',
        re.IGNORECASE
    )
    
    # Aadhaar number (12 digits, grouped)
    AADHAAR_PATTERN = re.compile(
        r'\b(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b'
    )
    
    # PAN number
    PAN_PATTERN = re.compile(
        r'\b([A-Z]{5}[0-9]{4}[A-Z])\b',
        re.IGNORECASE
    )
    
    # Reference/Transaction numbers
    REFERENCE_PATTERN = re.compile(
        r'(?:ref|reference|txn|transaction|case|complaint|ticket|id)[:\s#.-]*([A-Z0-9]{6,20})',
        re.IGNORECASE
    )
    
    # Names (after "I am", "my name is", "this is")
    NAME_PATTERN = re.compile(
        r'(?:i am|my name is|this is|speaking|calling)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
        re.IGNORECASE
    )
    
    # Organization names
    ORG_PATTERN = re.compile(
        r'(?:from|calling from|representing|officer from|employee of)[:\s]+([A-Za-z\s]{3,30}?)(?:\s+(?:bank|department|office|cell|branch|division))',
        re.IGNORECASE
    )
    
    # WhatsApp/Telegram numbers
    MESSAGING_PATTERN = re.compile(
        r'(?:whatsapp|telegram|wa|tg)[:\s@]*(?:\+91[\s.-]?)?([6-9]\d{9})',
        re.IGNORECASE
    )
    
    # Common UPI handles for validation
    VALID_UPI_HANDLES: Set[str] = {
        'ybl', 'paytm', 'okaxis', 'okicici', 'okhdfcbank', 'oksbi',
        'upi', 'axl', 'ibl', 'sbi', 'apl', 'pingpay', 'icici',
        'hdfcbank', 'axisbank', 'kotak', 'indus', 'federal', 'rbl',
        'citi', 'hsbc', 'sc', 'dbs', 'jio', 'airtel', 'postbank',
        'boi', 'unionbank', 'pnb', 'bob', 'iob', 'canarabank',
        'bandhan', 'idfc', 'yes', 'equitas', 'fino', 'slice',
        'amazonpay', 'gpay', 'phone', 'phonepe', 'wa', 'fam',
    }
    
    def extract_upi_ids(self, text: str) -> List[str]:
        """Extract valid UPI IDs from text."""
        matches = self.UPI_PATTERN.findall(text)
        valid_upis = []
        for match in matches:
            if '@' in match:
                handle = match.split('@')[1].lower()
                # Validate it's a real UPI handle
                if handle in self.VALID_UPI_HANDLES or len(handle) <= 15:
                    valid_upis.append(match.lower())
        return list(set(valid_upis))
    
    def extract_bank_accounts(self, text: str) -> List[str]:
        """Extract bank account numbers."""
        matches = self.BANK_ACCOUNT_PATTERN.findall(text)
        accounts = []
        for match in matches:
            for group in match:
                if group and len(group) >= 9:
                    accounts.append(group)
        return list(set(accounts))
    
    def extract_ifsc_codes(self, text: str) -> List[str]:
        """Extract IFSC codes."""
        matches = self.IFSC_PATTERN.findall(text)
        return list(set([m.upper() for m in matches]))
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers."""
        matches = self.PHONE_PATTERN.findall(text)
        numbers = []
        for match in matches:
            for group in match:
                if group:
                    # Clean and standardize
                    clean = re.sub(r'[\s.-]', '', group)
                    if len(clean) == 10 and clean[0] in '6789':
                        numbers.append(clean)
        return list(set(numbers))
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses."""
        # Exclude UPI IDs that look like emails
        matches = self.EMAIL_PATTERN.findall(text)
        emails = []
        for email in matches:
            domain = email.split('@')[1].lower()
            # Exclude UPI handles
            if domain not in self.VALID_UPI_HANDLES and '.' in domain:
                emails.append(email.lower())
        return list(set(emails))
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs."""
        matches = self.URL_PATTERN.findall(text)
        urls = []
        for match in matches:
            if match and len(match) > 5:
                urls.append(match)
        
        # Also find full URL matches
        full_urls = re.findall(r'https?://[^\s<>"\']+', text, re.IGNORECASE)
        urls.extend(full_urls)
        
        return list(set(urls))
    
    def extract_money_amounts(self, text: str) -> List[str]:
        """Extract money amounts."""
        matches = self.MONEY_PATTERN.findall(text)
        amounts = []
        for match in matches:
            for group in match:
                if group:
                    amounts.append(group.replace(',', ''))
        return list(set(amounts))
    
    def extract_aadhaar(self, text: str) -> List[str]:
        """Extract Aadhaar numbers."""
        matches = self.AADHAAR_PATTERN.findall(text)
        return list(set([re.sub(r'[\s-]', '', m) for m in matches]))
    
    def extract_pan(self, text: str) -> List[str]:
        """Extract PAN numbers."""
        matches = self.PAN_PATTERN.findall(text)
        return list(set([m.upper() for m in matches]))
    
    def extract_references(self, text: str) -> List[str]:
        """Extract reference/transaction numbers."""
        matches = self.REFERENCE_PATTERN.findall(text)
        return list(set([m.upper() for m in matches]))
    
    def extract_names(self, text: str) -> List[str]:
        """Extract mentioned names."""
        matches = self.NAME_PATTERN.findall(text)
        return list(set([m.strip().title() for m in matches if len(m.strip()) > 2]))
    
    def extract_organizations(self, text: str) -> List[str]:
        """Extract organization names."""
        matches = self.ORG_PATTERN.findall(text)
        return list(set([m.strip().title() for m in matches if len(m.strip()) > 2]))
    
    def extract_messaging_numbers(self, text: str) -> List[str]:
        """Extract WhatsApp/Telegram numbers."""
        matches = self.MESSAGING_PATTERN.findall(text)
        return list(set([m for m in matches if len(m) == 10]))
    
    def extract_all(self, text: str) -> Dict[str, List]:
        """
        Extract all patterns from text.
        Returns a comprehensive dictionary of extracted intelligence.
        """
        return {
            'upi_ids': self.extract_upi_ids(text),
            'bank_accounts': self.extract_bank_accounts(text),
            'ifsc_codes': self.extract_ifsc_codes(text),
            'phone_numbers': self.extract_phone_numbers(text),
            'emails': self.extract_emails(text),
            'urls': self.extract_urls(text),
            'money_amounts': self.extract_money_amounts(text),
            'aadhaar_numbers': self.extract_aadhaar(text),
            'pan_numbers': self.extract_pan(text),
            'reference_numbers': self.extract_references(text),
            'names': self.extract_names(text),
            'organizations': self.extract_organizations(text),
            'messaging_numbers': self.extract_messaging_numbers(text),
        }
    
    def has_financial_indicators(self, text: str) -> bool:
        """Check if text contains any financial indicators."""
        extracted = self.extract_all(text)
        return any([
            extracted['upi_ids'],
            extracted['bank_accounts'],
            extracted['phone_numbers'],
            extracted['money_amounts'],
        ])


# Singleton instance
pattern_matcher = PatternMatcher()
