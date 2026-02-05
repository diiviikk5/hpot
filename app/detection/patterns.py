"""
Regex patterns for detecting financial identifiers and suspicious content.
Optimized for Indian financial ecosystem (UPI, banks, IFSC, etc.)
"""
import re
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class PatternMatch:
    """Represents a pattern match result."""
    pattern_type: str
    value: str
    confidence: float
    metadata: Dict[str, Any] = None


class PatternMatcher:
    """
    Regex-based pattern matching for financial identifiers and suspicious content.
    """
    
    # UPI ID patterns (e.g., name@upi, name@ybl, name@paytm)
    UPI_PATTERN = re.compile(
        r'\b([a-zA-Z0-9._-]+@[a-zA-Z]{2,})\b',
        re.IGNORECASE
    )
    
    # Bank account numbers (9-18 digits)
    BANK_ACCOUNT_PATTERN = re.compile(
        r'\b(\d{9,18})\b'
    )
    
    # IFSC codes (4 letters + 0 + 6 alphanumeric)
    IFSC_PATTERN = re.compile(
        r'\b([A-Z]{4}0[A-Z0-9]{6})\b',
        re.IGNORECASE
    )
    
    # Indian phone numbers
    PHONE_PATTERN = re.compile(
        r'(?:\+91|91|0)?[\s-]?([6-9]\d{9})\b'
    )
    
    # Email addresses
    EMAIL_PATTERN = re.compile(
        r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
        re.IGNORECASE
    )
    
    # URLs (http, https, and without protocol)
    URL_PATTERN = re.compile(
        r'(https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+)',
        re.IGNORECASE
    )
    
    # Money amounts (Indian format)
    MONEY_PATTERN = re.compile(
        r'(?:Rs\.?|₹|INR)\s*(\d{1,3}(?:,\d{2,3})*(?:\.\d{2})?|\d+(?:\.\d{2})?)\s*(?:lakh|lac|crore|cr|k)?',
        re.IGNORECASE
    )
    
    # Common UPI handles
    KNOWN_UPI_HANDLES = {
        'ybl', 'paytm', 'okhdfcbank', 'okicici', 'oksbi', 'axisbank',
        'ibl', 'upi', 'apl', 'yapl', 'airtel', 'jio', 'phonepe',
        'gpay', 'amazonpay', 'freecharge', 'mobikwik'
    }
    
    def extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs from text."""
        matches = self.UPI_PATTERN.findall(text)
        # Filter to likely UPI IDs (exclude common email domains)
        upi_ids = []
        email_domains = {'gmail', 'yahoo', 'hotmail', 'outlook', 'mail', 'email', 'proton'}
        for match in matches:
            handle = match.split('@')[1].lower()
            if handle in self.KNOWN_UPI_HANDLES or handle not in email_domains:
                # Additional check: if it looks like a UPI ID
                if len(handle) <= 15 and not '.' in handle:
                    upi_ids.append(match)
        return list(set(upi_ids))
    
    def extract_bank_accounts(self, text: str) -> List[str]:
        """Extract potential bank account numbers from text."""
        matches = self.BANK_ACCOUNT_PATTERN.findall(text)
        # Filter out obvious non-account numbers (like phone numbers, years, etc.)
        accounts = []
        for match in matches:
            # Skip if it looks like a phone number or year
            if len(match) >= 9 and not (len(match) == 10 and match[0] in '6789'):
                if not (1900 <= int(match) <= 2100):  # Not a year
                    accounts.append(match)
        return list(set(accounts))
    
    def extract_ifsc_codes(self, text: str) -> List[str]:
        """Extract IFSC codes from text."""
        matches = self.IFSC_PATTERN.findall(text)
        return list(set([m.upper() for m in matches]))
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers from text."""
        matches = self.PHONE_PATTERN.findall(text)
        return list(set(matches))
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        matches = self.EMAIL_PATTERN.findall(text)
        return list(set(matches))
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        matches = self.URL_PATTERN.findall(text)
        return list(set(matches))
    
    def extract_money_amounts(self, text: str) -> List[Dict[str, Any]]:
        """Extract money amounts from text."""
        matches = self.MONEY_PATTERN.findall(text)
        amounts = []
        for match in matches:
            # Clean up the amount
            clean = match.replace(',', '')
            amounts.append({
                'raw': match,
                'value': clean
            })
        return amounts
    
    def extract_all(self, text: str) -> Dict[str, List]:
        """Extract all patterns from text."""
        return {
            'upi_ids': self.extract_upi_ids(text),
            'bank_accounts': self.extract_bank_accounts(text),
            'ifsc_codes': self.extract_ifsc_codes(text),
            'phone_numbers': self.extract_phone_numbers(text),
            'emails': self.extract_emails(text),
            'urls': self.extract_urls(text),
            'money_amounts': self.extract_money_amounts(text)
        }


# Singleton instance
pattern_matcher = PatternMatcher()
