#!/usr/bin/env python3
"""
POPIA Privacy-as-Code Toolkit
Core PII Scanner for South African compliance
"""

import re
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class PIIMatch:
    """Represents a found PII match"""
    type: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    context: str
    severity: str
    hash_value: str
    popia_section: str

class POPIAPatterns:
    """South African PII patterns for POPIA compliance"""
    
    # South African ID Number (13 digits with Luhn checksum)
    SA_ID_PATTERN = r'\b\d{13}\b'
    
    # Phone numbers (+27 and local formats)
    PHONE_PATTERNS = [
        r'\+27[1-9]\d{8}',  # +27 format
        r'0[1-9]\d{8}',     # Local format starting with 0
        r'\b[1-9]\d{8}\b'   # 9-digit format
    ]
    
    # Email pattern
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Credit card numbers (basic Luhn validation)
    CREDIT_CARD_PATTERN = r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
    
    # Bank account numbers (simplified - 8-11 digits)
    BANK_ACCOUNT_PATTERN = r'\b\d{8,11}\b'
    
    # Physical addresses (basic pattern)
    ADDRESS_PATTERNS = [
        r'\b\d+\s+[A-Za-z\s]+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln)\b',
        r'\b[A-Za-z\s]+,\s*\d{4}\b'  # City, postal code
    ]

class LuhnValidator:
    """Luhn algorithm for checksum validation"""
    
    @staticmethod
    def validate(number: str) -> bool:
        """Validate using Luhn algorithm"""
        digits = [int(d) for d in number if d.isdigit()]
        if len(digits) < 2:
            return False
            
        # Double every second digit from right
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        
        return sum(digits) % 10 == 0

class SAIDValidator:
    """South African ID number validator"""
    
    @staticmethod
    def validate(id_number: str) -> bool:
        """Validate SA ID number format and checksum"""
        if len(id_number) != 13 or not id_number.isdigit():
            return False
        
        # Extract date part (YYMMDD)
        birth_date = id_number[:6]
        try:
            year = int(birth_date[:2])
            month = int(birth_date[2:4])
            day = int(birth_date[4:6])
            
            # Basic date validation
            if month < 1 or month > 12 or day < 1 or day > 31:
                return False
        except ValueError:
            return False
        
        # Calculate checksum (simplified Luhn for SA ID)
        digits = [int(d) for d in id_number[:12]]
        odd_sum = sum(digits[i] for i in range(0, 12, 2))
        even_digits = ''.join(str(digits[i]) for i in range(1, 12, 2))
        even_sum = sum(int(d) for d in str(int(even_digits) * 2))
        
        total = odd_sum + even_sum
        checksum = (10 - (total % 10)) % 10
        
        return checksum == int(id_number[12])

class POPIAScanner:
    """Main PII scanner for POPIA compliance"""
    
    def __init__(self, ignore_patterns: Optional[List[str]] = None):
        self.ignore_patterns = ignore_patterns or []
        self.patterns = POPIAPatterns()
        self.results: List[PIIMatch] = []
    
    def _hash_value(self, value: str) -> str:
        """Create hash of PII value for logging without exposing actual data"""
        return hashlib.sha256(value.encode()).hexdigest()[:8]
    
    def _should_ignore(self, file_path: str, content: str) -> bool:
        """Check if file should be ignored based on ignore patterns"""
        for pattern in self.ignore_patterns:
            if re.search(pattern, file_path) or re.search(pattern, content):
                return True
        return False
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """Get context around the match for better understanding"""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        context = content[context_start:context_end]
        
        # Redact the actual PII in context
        match_text = content[start:end]
        redacted = '*' * len(match_text)
        context = context.replace(match_text, redacted)
        
        return context.strip()
    
    def _scan_sa_ids(self, content: str, file_path: str) -> List[PIIMatch]:
        """Scan for South African ID numbers"""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for match in re.finditer(self.patterns.SA_ID_PATTERN, line):
                id_number = match.group()
                
                if SAIDValidator.validate(id_number):
                    context = self._get_context(content, match.start(), match.end())
                    
                    matches.append(PIIMatch(
                        type='SA_ID_NUMBER',
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        context=context,
                        severity='HIGH',
                        hash_value=self._hash_value(id_number),
                        popia_section='Section 19 - Processing of Special Personal Information'
                    ))
        
        return matches
    
    def _scan_phones(self, content: str, file_path: str) -> List[PIIMatch]:
        """Scan for phone numbers"""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.patterns.PHONE_PATTERNS:
                for match in re.finditer(pattern, line):
                    phone = match.group()
                    context = self._get_context(content, match.start(), match.end())
                    
                    matches.append(PIIMatch(
                        type='PHONE_NUMBER',
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        context=context,
                        severity='MEDIUM',
                        hash_value=self._hash_value(phone),
                        popia_section='Section 15 - Personal Information Processing'
                    ))
        
        return matches
    
    def _scan_emails(self, content: str, file_path: str) -> List[PIIMatch]:
        """Scan for email addresses"""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for match in re.finditer(self.patterns.EMAIL_PATTERN, line):
                email = match.group()
                context = self._get_context(content, match.start(), match.end())
                
                matches.append(PIIMatch(
                    type='EMAIL',
                    file_path=file_path,
                    line_number=line_num,
                    column_start=match.start(),
                    column_end=match.end(),
                    context=context,
                    severity='MEDIUM',
                    hash_value=self._hash_value(email),
                    popia_section='Section 15 - Personal Information Processing'
                ))
        
        return matches
    
    def _scan_credit_cards(self, content: str, file_path: str) -> List[PIIMatch]:
        """Scan for credit card numbers"""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for match in re.finditer(self.patterns.CREDIT_CARD_PATTERN, line):
                cc_number = re.sub(r'[\s-]', '', match.group())
                
                if len(cc_number) >= 13 and LuhnValidator.validate(cc_number):
                    context = self._get_context(content, match.start(), match.end())
                    
                    matches.append(PIIMatch(
                        type='CREDIT_CARD',
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        context=context,
                        severity='HIGH',
                        hash_value=self._hash_value(cc_number),
                        popia_section='Section 19 - Processing of Special Personal Information'
                    ))
        
        return matches
    
    def scan_file(self, file_path: str) -> List[PIIMatch]:
        """Scan a single file for PII"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if self._should_ignore(file_path, content):
                logger.info(f"Ignoring file: {file_path}")
                return []
            
            matches = []
            matches.extend(self._scan_sa_ids(content, file_path))
            matches.extend(self._scan_phones(content, file_path))
            matches.extend(self._scan_emails(content, file_path))
            matches.extend(self._scan_credit_cards(content, file_path))
            
            logger.info(f"Scanned {file_path}: {len(matches)} PII matches found")
            return matches
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return []
    
    def scan_directory(self, directory_path: str, extensions: List[str] = None) -> List[PIIMatch]:
        """Scan all files in a directory"""
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.txt', '.md', '.json', '.xml', '.csv']
        
        directory = Path(directory_path)
        all_matches = []
        
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                matches = self.scan_file(str(file_path))
                all_matches.extend(matches)
        
        self.results = all_matches
        return all_matches
    
    def generate_report(self, output_format: str = 'json') -> str:
        """Generate scan report in specified format"""
        report_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_matches': len(self.results),
            'severity_breakdown': self._get_severity_breakdown(),
            'popia_sections_affected': self._get_affected_sections(),
            'matches': [asdict(match) for match in self.results]
        }
        
        if output_format == 'json':
            return json.dumps(report_data, indent=2)
        else:
            return str(report_data)
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get breakdown of matches by severity"""
        breakdown = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for match in self.results:
            breakdown[match.severity] += 1
        return breakdown
    
    def _get_affected_sections(self) -> List[str]:
        """Get unique POPIA sections affected"""
        sections = set(match.popia_section for match in self.results)
        return list(sections)

def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description='POPIA Privacy-as-Code Scanner')
    parser.add_argument('--path', required=True, help='Path to scan (file or directory)')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'text'], default='json', help='Output format')
    parser.add_argument('--ignore-rules', nargs='*', help='Regex patterns to ignore')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = POPIAScanner(ignore_patterns=args.ignore_rules or [])
    
    # Scan path
    path = Path(args.path)
    if path.is_file():
        matches = scanner.scan_file(str(path))
        scanner.results = matches
    elif path.is_directory():
        matches = scanner.scan_directory(str(path))
    else:
        logger.error(f"Invalid path: {args.path}")
        return 1
    
    # Generate report
    report = scanner.generate_report(args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {args.output}")
    else:
        print(report)
    
    # Return exit code based on findings
    return 1 if matches else 0

if __name__ == '__main__':
    exit(main())