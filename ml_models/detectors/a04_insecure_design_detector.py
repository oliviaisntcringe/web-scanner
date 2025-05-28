# Detector for A04:2021 - Insecure Design
import re

# Enhanced patterns for hardcoded secrets (design-time focus)
# These are illustrative and should be expanded.
DESIGN_HARDCODED_SECRET_PATTERNS = [
    # Generic API Keys / Secrets
    r'(?i)(?:api_key|client_secret|auth_token|access_token|secret_key)\s*[:=]\s*([\'"]?)([a-zA-Z0-9_\-.~!@#$%^&*()+=]{20,})\1',
    # Passwords in comments or clearly assigned
    r'(?i)(?:password|passwd|pwd)\s*[:=]\s*([\'"]?)([a-zA-Z0-9_\-.~!@#$%^&*()+=]{6,})\1',
    r'//\s*TODO:.*remove before production.*credentials',
    r'//\s*FIXME:.*temporary password',
    # AWS Keys (example)
    r'(A3T[A-Z0-9]|AKIA|AGPA|AROA|ASCA|ASIA)[A-Z0-9]{16}'
]

# Debug mode indicators
DEBUG_INDICATORS_URL = [
    "debug=true", "debug=1", "test_mode=on"
]
DEBUG_INDICATORS_CONTENT = [
    "debug_mode: on", "environment: development", "application_env: dev",
    "detailed error report", "stack trace:", "exception encountered",
    "x-debug-token:", "profiler enabled" # Also check headers if available
]

# Sensitive field names for autocomplete checks
SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pwd", "new_password", "confirm_password",
    "credit_card", "card_number", "cc_num", "cvv", "cvc", "card_verification",
    "ssn", "social_security_number", "api_key", "secret"
]

def detect(site_data, samples=None):
    """Detects potential Insecure Design vulnerabilities."""
    vulnerabilities = []
    content_lower = site_data.get("content", "").lower() # Use lower for most content checks
    content_original_case = site_data.get("content", "") # For regex needing case-sensitivity or original value
    url_lower = site_data.get("url", "").lower()
    headers_lower = {k.lower(): v for k, v in site_data.get("headers", {}).items()}
    robots_txt_content = site_data.get("robots_txt_content", "").lower()
    
    # Проверяем, есть ли у нас ML-модель для Insecure Design
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Insecure Design с помощью ML
        ml_result = ml_detector.predict(site_data, "a04_insecure_design")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A04_Insecure_Design_ML",
                "details": f"ML-модель обнаружила признаки небезопасного дизайна с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A04 Insecure Design: {e}")


    # 1. Hardcoded Secrets (Design-Time)
    for pattern_str in DESIGN_HARDCODED_SECRET_PATTERNS:
        try:
            # Use original case content for regex that might be case-sensitive (e.g., AWS keys)
            # or to capture the actual secret. Most patterns here use (?i) anyway.
            matches = re.finditer(pattern_str, content_original_case)
            for match in matches:
                # Avoid matching example keys if possible (simple check)
                matched_text = match.group(0)
                if "example" in matched_text.lower() or "dummy" in matched_text.lower() or "test_key" in matched_text.lower():
                    continue
                
                secret_snippet = match.group(2) if len(match.groups()) >= 2 and match.group(2) else match.group(0)
                
                # Check if this specific finding (by pattern and snippet start) is already added
                detail_start = f"Potential hardcoded secret/credential found (pattern: {pattern_str[:30]}..., value: ...{secret_snippet[:20]}...)"
                if not any(v['details'].startswith(detail_start) for v in vulnerabilities):
                    vulnerabilities.append({
                        "type": "A04_Insecure_Design_Hardcoded_Secret",
                        "details": f"{detail_start} in HTML content. This might be a placeholder, dev remnant, or actual secret."
                    })
        except re.error as e:
            print(f"Regex error in A04 detector (hardcoded secrets) for pattern \'{pattern_str}\': {e}")
            continue

    # 2. Debug Mode Indicators
    for indicator in DEBUG_INDICATORS_URL:
        if indicator in url_lower:
            vulnerabilities.append({
                "type": "A04_Insecure_Design_Debug_Mode_URL",
                "details": f"Application possibly running in debug mode. URL contains \'{indicator}\'."
            })
            break # One URL indicator is enough
            
    for indicator in DEBUG_INDICATORS_CONTENT:
        if indicator in content_lower:
            vulnerabilities.append({
                "type": "A04_Insecure_Design_Debug_Mode_Content",
                "details": f"Application possibly running in debug mode. Content contains \'{indicator}\'."
            })
            break # One content indicator is enough

    # Check for debug headers
    debug_headers = ["x-debug-token", "x-debug-trace", "x-powered-by", "server"] # Server/X-Powered-By can sometimes leak too much dev info
    for h_name, h_value in headers_lower.items():
        if h_name in debug_headers:
            if h_name == "x-powered-by" and ("php/" in h_value or "asp.net" in h_value): # Be more specific
                 vulnerabilities.append({
                    "type": "A04_Insecure_Design_Verbose_Header_PoweredBy",
                    "details": f"Verbose X-Powered-By header found: {h_value}. Can indicate insecure defaults or reveal specific versions."
                 })
            elif h_name == "server" and any(s_ind in h_value.lower() for s_ind in ["apache/", "nginx/", "iis/", "jetty", "gws", "python/", "node.js"]): # Server with version
                 if re.search(r'([0-9]+\\.){1,}[0-9]+', h_value): # If it contains a version number
                    vulnerabilities.append({
                        "type": "A04_Insecure_Design_Verbose_Header_Server",
                        "details": f"Verbose Server header found: {h_value}. Can indicate insecure defaults or reveal specific versions."
                    })
            elif h_name not in ["x-powered-by", "server"]: # General debug headers
                # Sanitize h_name for use in the type string
                safe_h_name_part = h_name.replace('-', '_').upper()
                vulnerabilities.append({
                    "type": f"A04_Insecure_Design_Debug_Header_{safe_h_name_part}",
                    "details": f"Potential debug header '{h_name}' found with value: {h_value[:50]}..."
                })


    # 3. Autocomplete on Sensitive Fields
    # Find all input tags
    input_tags = re.finditer(r'<input([^>]+)>', content_original_case, re.IGNORECASE)
    for tag_match in input_tags:
        attributes_str = tag_match.group(1)
        # Check for autocomplete="on" (or absence of autocomplete="off")
        # Browsers often default to "on", so presence of "on" or absence of "off" on sensitive fields is notable
        autocomplete_attr = re.search(r'autocomplete\s*=\s*([\'"]?)(on|off)\1', attributes_str, re.IGNORECASE)
        
        is_sensitive = False
        for sensitive_name in SENSITIVE_FIELD_NAMES:
            if re.search(r'(?:name|id)\s*=\s*([\'"]?)' + re.escape(sensitive_name) + r'\1', attributes_str, re.IGNORECASE):
                is_sensitive = True
                break
        
        if is_sensitive:
            is_on_or_not_off = True # Default assumption
            if autocomplete_attr:
                if autocomplete_attr.group(2).lower() == "off":
                    is_on_or_not_off = False
            
            if is_on_or_not_off: # If autocomplete is "on" or not explicitly "off" for a sensitive field
                # Check if this specific field (by name) is already reported
                # Ensure sensitive_name is defined; it's from the outer loop.
                detail_start = f"Autocomplete enabled (or not disabled) on sensitive field (name/id likely '{sensitive_name}')"
                if not any(v['details'].startswith(detail_start) for v in vulnerabilities):
                    vulnerabilities.append({
                        "type": "A04_Insecure_Design_Autocomplete_Sensitive",
                        "details": f"{detail_start}. Input tag: <input{attributes_str[:100]}...>"
                    })

    # 4. Lack of Rate Limiting Indicators (Very Heuristic - focus on login/reset forms)
    # This is a weak check. Real detection needs interaction.
    # We're checking if we are on a page that *looks* like a login/reset page AND common rate limit headers are missing.
    is_login_or_reset_page = any(keyword in content_lower for keyword in ["login", "sign in", "authenticate", "forgot password", "reset password", "enter username"])
    if is_login_or_reset_page:
        rate_limit_headers_present = any(h.lower() in headers_lower for h in ["x-ratelimit-limit", "retry-after", "x-ratelimit-remaining"])
        if not rate_limit_headers_present:
            # Avoid reporting this too eagerly if it's not a form POST or specific action
            if any(form_action in content_lower for form_action in ["method=\"post\"", "action=\"/login\"", "action=\"/reset\""] ):
                vulnerabilities.append({
                    "type": "A04_Insecure_Design_Potential_Missing_Rate_Limit_Headers",
                    "details": "Page appears to be a login/reset form, but common rate-limiting headers (e.g., X-RateLimit-Limit, Retry-After) are not detected. This is a weak indicator and requires manual verification of brute-force protections."
                })

    # 5. Exposure of Sensitive Information in robots.txt (if content provided)
    if robots_txt_content:
        sensitive_paths_disallowed = [
            "/admin", "/backup", "/config", "/logs", "/private", "/internal", "/manage", "/_profiler"
        ]
        for path in sensitive_paths_disallowed:
            if f"disallow: {path}" in robots_txt_content:
                vulnerabilities.append({
                    "type": "A04_Insecure_Design_Sensitive_Path_In_RobotsTxt",
                    "details": f"robots.txt disallows access to '{path}', which might indicate a sensitive area. While not a vulnerability itself, it advertises a path that should ideally not be guessable or discoverable."
                })
    
    # Deduplicate findings
    unique_vulnerabilities = []
    seen_vulns = set()
    for vuln in vulnerabilities:
        vuln_key = (vuln["type"], vuln["details"][:70]) # Use slightly longer key for dedupe
        if vuln_key not in seen_vulns:
            unique_vulnerabilities.append(vuln)
            seen_vulns.add(vuln_key)
            
    return unique_vulnerabilities 