# Detector for A03:2021 - Injection (XSS, SQLi, Command Injection)
import random
import re
from urllib.parse import unquote_plus, parse_qs, urlparse

def detect(site_data, samples=None):
    """Detects Injection vulnerabilities (XSS, SQLi, Command Injection)."""
    vulnerabilities = []
    # 'samples' here is a dict: {'xss': xss_samples, 'sqli': sqli_samples, 'rce': rce_samples}
    
    xss_samples = samples.get('xss') if samples else []
    sqli_samples = samples.get('sqli') if samples else []
    rce_samples = samples.get('rce') if samples else []
    
    # Проверяем, есть ли у нас ML-модели для инъекций
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на XSS с помощью ML
        xss_result = ml_detector.predict(site_data, "xss")
        if xss_result["prediction"] and xss_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A03_Injection_XSS_ML",
                "details": f"ML-модель обнаружила признаки XSS с уверенностью {xss_result['confidence']:.2f}",
                "severity": "high"
            })
            
        # Проверяем сайт на SQL-инъекции с помощью ML
        sqli_result = ml_detector.predict(site_data, "sqli")
        if sqli_result["prediction"] and sqli_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A03_Injection_SQLi_ML",
                "details": f"ML-модель обнаружила признаки SQL-инъекции с уверенностью {sqli_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для детектора инъекций: {e}")

    site_content_lower = site_data.get("content", "").lower()
    site_url_lower = site_data.get("url", "").lower()
    # Get unquoted URL for easier payload matching
    site_url_unquoted_lower = unquote_plus(site_url_lower)
    
    # Extract form parameters if available
    form_params = {}
    if site_data.get("form_data") and site_data.get("params"):
        form_params = site_data.get("params", {})
    
    # Extract URL parameters
    parsed_url = urlparse(site_data.get("url", ""))
    url_params = parse_qs(parsed_url.query)

    # --- XSS Check ---
    if xss_samples:
        # Advanced XSS pattern detection
        xss_patterns = [
            # Basic XSS vectors
            r"<script\b[^>]*>[^<]*<\/script>",
            r"<img\b[^>]*\bonerror\s*=\s*['\"]",
            r"<svg\b[^>]*\bonload\s*=\s*['\"]",
            r"<[^>]*\b(?:on(?:abort|blur|change|click|dblclick|dragdrop|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|move|readystatechange|reset|resize|select|submit|unload))\s*=\s*['\"]",
            
            # Event handlers
            r"javascript\s*:\s*[^;]*",
            r"vbscript\s*:\s*[^;]*",
            r"data\s*:\s*(?:text\/html|application\/javascript)",
            
            # DOM based XSS
            r"document\.(?:write|writeln|cookie|location|documentElement|getElementById|getElementsByTagName)",
            r"window\.(?:location|navigate|open|location\.hash|location\.href)",
            r"(?:innerHTML|outerHTML|innerText|textContent)\s*=",
            
            # Element properties used for XSS
            r"(?:src|href|data|action)\s*=\s*['\"]?(?:javascript|vbscript|data):",
            
            # Encoding bypasses
            r"&#x[0-9a-f]+;", # Hex encoding
            r"&#\d+;",        # Decimal encoding
            r"\\u[0-9a-f]{4}", # Unicode
            
            # Alert variations often used in XSS payloads
            r"(?:alert|prompt|confirm|eval|expression|Function|setTimeout|setInterval)\s*\("
        ]
        
        # Check URL for XSS patterns
        for pattern in xss_patterns:
            match = re.search(pattern, site_url_unquoted_lower, re.IGNORECASE)
            if match:
                vulnerabilities.append({
                    "type": "A03_Injection_XSS_URL",
                    "details": f"XSS pattern detected in URL: {match.group(0)}",
                    "severity": "high"
                })
                break  # One finding is enough for direct URL pattern detection
        
        # Check URL parameters for XSS vectors
        for param_name, param_values in url_params.items():
            for param_value in param_values:
                for pattern in xss_patterns:
                    match = re.search(pattern, param_value, re.IGNORECASE)
                    if match:
                        vulnerabilities.append({
                            "type": "A03_Injection_XSS_URL_Parameter",
                            "details": f"XSS pattern detected in URL parameter '{param_name}': {param_value[:100]}",
                            "severity": "high"
                        })
                        break
        
        # Check form parameters for XSS vectors
        if form_params:
            for param_name, param_value in form_params.items():
                if isinstance(param_value, str):
                    for pattern in xss_patterns:
                        match = re.search(pattern, param_value, re.IGNORECASE)
                        if match:
                            vulnerabilities.append({
                                "type": "A03_Injection_XSS_Form_Parameter",
                                "details": f"XSS pattern detected in form parameter '{param_name}': {param_value[:100]}",
                                "severity": "high"
                            })
                            break
        
        # Check if parameters are reflected in the content (potential reflection-based XSS)
        page_content = site_data.get("content", "")
        if page_content and url_params:
            for param_name, param_values in url_params.items():
                for param_value in param_values:
                    # Skip very short or common parameter values
                    if len(param_value) < 4 or param_value.lower() in ["true", "false", "yes", "no", "0", "1"]:
                        continue
                    
                    # Check if parameter value is reflected in the content
                    if param_value in page_content:
                        # Check if it's inside a script tag or event handler (higher risk)
                        script_context = False
                        script_tags = re.finditer(r'<script\b[^>]*>(.*?)</script>', page_content, re.IGNORECASE | re.DOTALL)
                        for script in script_tags:
                            if param_value in script.group(1):
                                script_context = True
                                break
                        
                        event_handler_context = False
                        for event_handler in re.finditer(r'\bon\w+\s*=\s*["\'][^"\']*["\']', page_content, re.IGNORECASE):
                            if param_value in event_handler.group(0):
                                event_handler_context = True
                                break
                        
                        severity = "high" if script_context or event_handler_context else "medium"
                        context_type = "script tag" if script_context else "event handler" if event_handler_context else "HTML content"
                        
                        vulnerabilities.append({
                            "type": "A03_Injection_XSS_Parameter_Reflection",
                            "details": f"Parameter '{param_name}' with value '{param_value[:50]}' is reflected in {context_type}. This could potentially lead to reflected XSS.",
                            "severity": severity
                        })

        # Check for raw XSS payloads from vulnerable samples reflected in content or URL
        # Iterate over a sample of vulnerable payloads to keep it efficient
        for sample in random.sample([s for s in xss_samples if s.get("is_vulnerable") and s.get("raw_payload")], 
                                     min(len([s for s in xss_samples if s.get("is_vulnerable") and s.get("raw_payload")]), 20)): # Sample up to 20
            raw_payload = sample.get("raw_payload", "").strip()
            if not raw_payload:
                continue
            
            # Simple check: if raw payload (even partial for common ones) is in content or URL
            # More advanced: check if specific URL parameters are reflected with the payload.
            # For now, direct check of payload presence.
            # Payloads can be complex; sometimes even a part of it is indicative.
            # Common simple XSS payload indicators for faster check
            simplified_payload_indicators = [
                "<script>", "onerror=", "onload=", "javascript:", "<svg", "<img", "<iframe", "alert(",
                "onmouseover=", "onfocus=", "onblur=", "ondblclick=", "formaction=", "autofocus",
                "expression(", "document.cookie", "document.location", "document.write"
            ]
            
            payload_lower = raw_payload.lower()

            found_in_url = False
            if any(indicator in payload_lower for indicator in simplified_payload_indicators):
                 if payload_lower in site_url_unquoted_lower:
                     found_in_url = True
            
            found_in_content = False
            if any(indicator in payload_lower for indicator in simplified_payload_indicators):
                if payload_lower in site_content_lower:
                    found_in_content = True
                    
            # Check for encoded versions of payload in URL and content
            # Common encoding methods used to bypass XSS filters
            encoded_variants = [
                payload_lower.replace('<', '&lt;').replace('>', '&gt;'),
                payload_lower.replace('<', '\\u003c').replace('>', '\\u003e'),
                payload_lower.replace('<', '%3C').replace('>', '%3E')
            ]
            
            for encoded in encoded_variants:
                if encoded in site_url_unquoted_lower:
                    found_in_url = True
                if encoded in site_content_lower:
                    found_in_content = True

            if found_in_url or found_in_content:
                location = "URL" if found_in_url else "HTML content"
                location += " and HTML content" if found_in_url and found_in_content else ""
                
                vulnerabilities.append({
                    "type": "A03_Injection_XSS",
                    "details": f"Potential XSS: Vulnerable sample payload (or part of it) '{raw_payload[:100]}' found in {location}. Sample description: {sample.get('description', 'N/A')}",
                    "severity": "high" if found_in_url and found_in_content else "medium"
                })
                # Report one finding per sample match for XSS to avoid too many similar ones from one payload
    
    # --- SQLi Check ---
    if sqli_samples:
        # Expanded SQL error patterns
        sql_error_patterns = [
            # MySQL/MariaDB
            "sql syntax", "mysql error", "unclosed quotation mark", "you have an error in your sql syntax", 
            "warning: mysql_", "function\\.mysql", "mysql_fetch", "mysql_num_rows", "mysql_result", 
            # MSSQL
            "unclosed quotation mark after the character string", "sql server", "microsoft odbc", 
            "ole db provider for sql server", "microsoft oledb provider for sql server", "jet database engine",
            "ora-[0-9]", "ora-[0-9][0-9][0-9][0-9]", "oracleexception",
            # PostgreSQL
            "pg_query", "pg_exec", "pg::query", "postgresdatasource", "psqldatasource", "postgressql",
            "postgresql.pg.raiseerror", "invalid input syntax for", "unterminated quoted string at or near",
            # SQLite
            "sqlite_error", "sqlite.exception", "sqlite3.operationalerror",
            # Generic errors
            "invalid query", "sql error", "unexpected end of sql command", "unexpected token", 
            "unrecognized token", "unclosed quotation mark", "unterminated string literal",
            "odbc drivers error", "invalid input syntax for type"
        ]
        
        found_sql_error = None
        for pattern in sql_error_patterns:
            if pattern in site_content_lower:
                found_sql_error = pattern
                break

        if found_sql_error:
            # Extract a bit of context around the error
            error_index = site_content_lower.find(found_sql_error)
            start_index = max(0, error_index - 50)
            end_index = min(len(site_content_lower), error_index + len(found_sql_error) + 50)
            error_context = site_content_lower[start_index:end_index].replace("<", "&lt;").replace(">", "&gt;")
            
            vulnerabilities.append({
                 "type": "A03_Injection_SQLi_Error",
                 "details": f"SQL error message detected in page content: '{error_context}'.",
                 "severity": "high" if "syntax" in found_sql_error or "quotation" in found_sql_error else "medium"
             })

        # Advanced SQLi patterns for payload detection
        sql_payload_patterns = [
            # Boolean-based
            r"(?:\s|\'|\"|`|;|\||&)+(?:and|or)\s+\d+\s*=\s*\d+(?:\s|\'|\"|`|;|\||&)+",  # ' or 1=1 --
            r"(?:\s|\'|\"|`|;|\||&)+(?:and|or)\s+\d+\s*>[\s<>=]*\d+(?:\s|\'|\"|`|;|\||&)+",  # ' or 1>0 --
            r"(?:\s|\'|\"|`|;|\||&)+(?:and|or)\s+\d+\s*!=[\s<>=]*\d+(?:\s|\'|\"|`|;|\||&)+",  # ' or 1!=0 --
            
            # Union-based
            r"(?:union\s+all\s+select|union\s+select).+from",
            r"(?:group_concat|concat_ws|concat)\s*\([^\)]+\)",
            
            # Error-based
            r"extractvalue\s*\(\s*[^\,]+\,",
            r"updatexml\s*\(\s*[^\,]+\,",
            r"floor\s*\(\s*rand\s*\(\s*\)\s*\*\s*\d+\s*\)",
            
            # Time-based
            r"benchmark\s*\(\s*\d+\s*\,",
            r"sleep\s*\(\s*\d+\s*\)",
            r"pg_sleep\s*\(\s*\d+\s*\)",
            r"waitfor\s+delay\s+\'[^\']+\'",
            
            # Comments
            r"--\s+",  # SQL comment
            r"\#",     # MySQL comment
            r"\/\*.*?\*\/"  # C-style comment
        ]
        
        # Check URL for SQL injection patterns
        for pattern in sql_payload_patterns:
            if re.search(pattern, site_url_unquoted_lower, re.IGNORECASE):
                vulnerabilities.append({
                    "type": "A03_Injection_SQLi_Payload_In_URL",
                    "details": f"SQL injection pattern detected in URL: {re.search(pattern, site_url_unquoted_lower, re.IGNORECASE).group(0)}",
                    "severity": "high"
                })
                break  # One finding is enough for URL pattern detection
                
        # Check form parameters for SQL injection vectors
        if form_params:
            for param_name, param_value in form_params.items():
                if isinstance(param_value, str):
                    for pattern in sql_payload_patterns:
                        if re.search(pattern, param_value, re.IGNORECASE):
                            vulnerabilities.append({
                                "type": "A03_Injection_SQLi_Form_Parameter",
                                "details": f"SQL injection pattern detected in form parameter '{param_name}': {param_value[:100]}",
                                "severity": "high"
                            })
                            break

        # Check URL parameters for SQL injection vectors
        for param_name, param_values in url_params.items():
            for param_value in param_values:
                for pattern in sql_payload_patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        vulnerabilities.append({
                            "type": "A03_Injection_SQLi_URL_Parameter",
                            "details": f"SQL injection pattern detected in URL parameter '{param_name}': {param_value[:100]}",
                            "severity": "high"
                        })
                        break

        # Check for raw SQLi payloads from vulnerable samples in URL parameters
        for sample in random.sample([s for s in sqli_samples if s.get("is_vulnerable") and s.get("raw_payload")],
                                     min(len([s for s in sqli_samples if s.get("is_vulnerable") and s.get("raw_payload")]), 20)):
            raw_payload = sample.get("raw_payload", "").strip()
            if not raw_payload:
                continue
            
            payload_lower = raw_payload.lower()
            # Focus on keywords often found in URL-based SQLi
            # More specific parts of payload rather than the whole string sometimes
            # E.g. ' or 1=1, union select, waitfor delay
            sql_payload_keywords = [
                "' or ", "'or'", " union ", "select ", " waitfor delay", " benchmark(", " pg_sleep(", "--", "#",
                "or 1=1", "or true", "or 1 like 1", "' and '1'='1", "' and 0=0", "order by"
            ] # Add more common SQLi keywords/patterns
            
            if any(keyword in payload_lower for keyword in sql_payload_keywords) and \
               (payload_lower in site_url_unquoted_lower or \
                any(keyword in site_url_unquoted_lower for keyword in sql_payload_keywords if keyword in payload_lower)): # Check if payload or its keywords are in URL
                details_message = f"Potential SQLi: Part of a known vulnerable SQLi payload ('{raw_payload[:100]}') or its keywords found in URL '{site_url_lower}'. Sample: {sample.get('description', 'N/A')}"
                if found_sql_error:
                    details_message += " Corroborated by SQL errors in page content."
                
                # Avoid duplicate messages if the core payload part is the same
                if not any(d['details'].startswith(f"Potential SQLi: Part of a known vulnerable SQLi payload ('{raw_payload[:100]}')") for d in vulnerabilities):
                    vulnerabilities.append({
                        "type": "A03_Injection_SQLi_Payload_In_URL",
                        "details": details_message,
                        "severity": "high"
                    })

    # --- Command Injection (RCE part of A03) ---
    if rce_samples:
        # Look for direct reflection of RCE payloads or suspicious keywords in URL/content
        for sample in random.sample([s for s in rce_samples if s.get("is_vulnerable") and s.get("raw_payload")],
                                     min(len([s for s in rce_samples if s.get("is_vulnerable") and s.get("raw_payload")]), 20)):
            raw_payload = sample.get("raw_payload", "").strip()
            if not raw_payload:
                continue
            
            payload_lower = raw_payload.lower()
            # Keywords/patterns often found in command injection payloads
            rce_indicators = [
                ";", "|", "&", "`", "$(", "&&", "||", # Shell metacharacters
                "id", "whoami", "uname", "cat /etc/passwd", "ls ", "dir ", # Common commands
                "system(", "exec(", "shell_exec(", "passthru(", "popen(", # Common functions
                "nc ", "netcat ", "wget ", "curl " # Network utilities
            ]

            found_in_url = False
            # Check if payload itself or its significant parts are in the URL
            if payload_lower in site_url_unquoted_lower or \
               any(indicator in site_url_unquoted_lower for indicator in rce_indicators if indicator in payload_lower and len(indicator)>1): # Avoid single char match for generic chars
                found_in_url = True
            
            found_in_content = False
            # Check if payload itself or its significant parts are in the content
            if payload_lower in site_content_lower or \
               any(indicator in site_content_lower for indicator in rce_indicators if indicator in payload_lower and len(indicator)>1):
                found_in_content = True

            if found_in_url or found_in_content:
                location = "URL" if found_in_url else "HTML content"
                location += " and HTML content" if found_in_url and found_in_content else ""
                
                # Add to vulnerabilities if not already reported for this specific payload snippet
                detail_start = f"Potential Command Injection: Part of a known RCE payload ('{raw_payload[:100]}')"
                if not any(d['details'].startswith(detail_start) for d in vulnerabilities):
                    vulnerabilities.append({
                        "type": "A03_Injection_Command",
                        "details": f"{detail_start} or its indicators found in {location}. Sample: {sample.get('description', 'N/A')}",
                        "severity": "high"
                    })
    
    # Deduplicate findings before returning (simple deduplication based on type and first 50 chars of details)
    unique_vulnerabilities = []
    seen_vulns = set()
    for vuln in vulnerabilities:
        vuln_key = (vuln["type"], vuln["details"][:50])
        if vuln_key not in seen_vulns:
            unique_vulnerabilities.append(vuln)
            seen_vulns.add(vuln_key)
            
    return unique_vulnerabilities 