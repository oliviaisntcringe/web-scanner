# Detector for A02:2021 - Cryptographic Failures
import re
import random

# Known weak ciphers (examples, a real list would be more extensive)
# These are illustrative and would ideally come from a regularly updated source.
KNOWN_WEAK_CIPHERS = [
    "TLS_RSA_WITH_RC4_128_SHA", "RC4", "3DES_EDE_CBC", "EXPORT", "NULL",
    "MD5" # As part of cipher string, e.g. TLS_RSA_WITH_AES_128_CBC_SHA_MD5
]

# Patterns for hardcoded secrets in HTML
# Note: Order can matter if patterns are very general.
PASSWORD_PATTERN = r'(?i)\b(?:password|passwd|pwd(?:_value)?)\b\s*[:=]\s*(?:(["\'])([^\1]{6,})\1|([^\s"\'&<>]{6,}))'
API_KEY_PATTERN = r'(?i)\b(?:api[-_]?key|secret[-_]?(?:key|token)|auth[-_]?token|access[-_]?token|client[-_]?secret|private[-_]?key)\b\s*[:=]\s*(?:(["\'])([^\1]+?)\1|([^\s"\'&<>]+))'
BEGIN_KEY_PATTERN = r'(?i)-{5}BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}'

HARDCODED_SECRET_PATTERNS = [
    API_KEY_PATTERN, 
    PASSWORD_PATTERN, 
    BEGIN_KEY_PATTERN
]

def detect(site_data, samples=None):
    """Detects Cryptographic Failures."""
    vulnerabilities = []
    site_url = site_data.get("url", "").lower()
    site_content = site_data.get("content", "") # Keep original case for regex on secrets
    site_headers = site_data.get("headers", {})
    site_header_keys_lower = {k.lower(): k for k in site_headers.keys()}
    
    # Проверяем, есть ли у нас ML-модель для Cryptographic Failures
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Cryptographic Failures с помощью ML
        ml_result = ml_detector.predict(site_data, "a02_cryptographic_failures")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A02_Crypto_ML_Detection",
                "details": f"ML-модель обнаружила признаки криптографических уязвимостей с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A02 Cryptographic Failures: {e}")

    # 1. Site served over HTTP (especially if forms are present or cookies set without Secure flag)
    is_http = site_url.startswith("http://")
    if is_http:
        # Check for forms, especially password forms, over HTTP
        post_form_match = re.search(
        r'<form(?=[^>]*method\s*=\s*(["\']?)post\1(?=[\s/>]))[^>]*>',
        site_content,
        re.IGNORECASE
    )
        password_field_match = re.search(
            r'<input(?=[^>]*type\s*=\s*(["\']?)password\1(?=[\s/>]))[^>]*>',
            site_content,
            re.IGNORECASE
        )

        if post_form_match and password_field_match:
            vulnerabilities.append({
                "type": "A02_Crypto_Sensitive_Form_Over_HTTP",
                "details": f"Site '{site_url}' serves a POST form with a password field over HTTP."
            })
        elif not any(v['type'] == "A02_Crypto_Sensitive_Form_Over_HTTP" for v in vulnerabilities):
             vulnerabilities.append({
                "type": "A02_Crypto_Site_Over_HTTP",
                "details": f"Site '{site_url}' is served over HTTP. Sensitive data may be transmitted in cleartext."
            })
    
    # 2. Check for missing Secure flag on cookies (if site is HTTPS or even HTTP)
    # This is more related to A05 but has strong crypto implications
    set_cookie_header_key = site_header_keys_lower.get('set-cookie')
    if set_cookie_header_key:
        cookies_header_val = site_headers.get(set_cookie_header_key)
        if not isinstance(cookies_header_val, list):
            cookies_header_val = [cookies_header_val]
        
        for cookie_str in cookies_header_val:
            if cookie_str: # Ensure cookie_str is not None or empty
                cookie_parts = cookie_str.split(';')
                cookie_name_val = cookie_parts[0]
                # Broader check for session-like cookie names
                is_session_cookie = any(name_part in cookie_name_val.lower() for name_part in 
                                        ["session", "sess", "auth", "token", "jsessionid", "phpsessid", "aspsession", "sid", "cid", "cfid", "cftoken"])
                
                has_secure_flag = any("secure" == part.strip().lower() for part in cookie_parts[1:])
                
                if is_session_cookie and not has_secure_flag:
                    cookie_name = cookie_name_val.split('=')[0] if '=' in cookie_name_val else cookie_name_val
                    # Avoid duplicate reporting for the same cookie name if multiple Set-Cookie headers for it
                    if not any(v['type'] == "A02_Crypto_Session_Cookie_No_Secure_Flag" and cookie_name in v['details'] for v in vulnerabilities):
                        vulnerabilities.append({
                            "type": "A02_Crypto_Session_Cookie_No_Secure_Flag",
                            "details": f"A session-like cookie ('{cookie_name}') was set without the 'Secure' flag: {cookie_name_val}"
                        })
                    # Do not break here, report all such cookies

    # 3. Check for weak ciphers (using X-Simulated-SSL-Cipher or real applicable headers if available)
    # This is a simplified check based on a custom header from our generator or common real headers
    simulated_cipher_key = site_header_keys_lower.get('x-simulated-ssl-cipher')
    if simulated_cipher_key:
        actual_cipher = site_headers.get(simulated_cipher_key, "")
        for weak_cipher_pattern in KNOWN_WEAK_CIPHERS:
            if weak_cipher_pattern.lower() in actual_cipher.lower():
                if not any(v['type'] == "A02_Crypto_Weak_Cipher_Detected" for v in vulnerabilities): # Report once
                    vulnerabilities.append({
                        "type": "A02_Crypto_Weak_Cipher_Detected",
                        "details": f"Site may be using a weak cipher suite: '{actual_cipher}' (matched: {weak_cipher_pattern}). (Simulated or from actual header)."
                    })
                    break
    # Add checks for real headers if scanner can get them, e.g. from SSL Labs API or similar tool output

    # 4. Check for hardcoded secrets in HTML content
    for pattern_str in HARDCODED_SECRET_PATTERNS:
        matches = []
        try:
            regex_flags = re.IGNORECASE if pattern_str != BEGIN_KEY_PATTERN else 0 # BEGIN_KEY_PATTERN is case sensitive
            matches = re.finditer(pattern_str, site_content, regex_flags)
        except re.error as e:
            print(f"Regex error in A02 detector for pattern '{pattern_str}': {e}")
            continue
            
        for match in matches:
            snippet = match.group(0)
            secret_part = ""

            if pattern_str == API_KEY_PATTERN:
                secret_part = match.group(3) 
            elif pattern_str == PASSWORD_PATTERN:
                secret_part = match.group(2) if match.group(2) else match.group(3) # group 2 for quoted, 3 for unquoted
            else: # Fallback for BEGIN_KEY_PATTERN
                secret_part = snippet 

            details_text = f"Potential hardcoded secret found in HTML (matches pattern for '{("API/Secret Key" if pattern_str == API_KEY_PATTERN else ("Password" if pattern_str == PASSWORD_PATTERN else "Private Key"))}'): ...{secret_part[:min(len(secret_part),30)]}..."
            if pattern_str == BEGIN_KEY_PATTERN:
                 details_text = f"Potential hardcoded private key found in HTML: {snippet.splitlines()[0]}..."
            
            # Avoid too many similar generic secret findings
            current_finding_type = f"A02_Crypto_Hardcoded_{"APIKey" if pattern_str == API_KEY_PATTERN else ("Password" if pattern_str == PASSWORD_PATTERN else "PrivateKey")}"
            if not any(v['type'] == current_finding_type and secret_part[:10] in v['details'] for v in vulnerabilities):
                vulnerabilities.append({
                    "type": current_finding_type,
                    "details": details_text
                })

    # 5. Use samples for correlation or to confirm findings
    if samples:
        for sample in random.sample(samples, min(len(samples), 5)):
            if sample.get('is_vulnerable'):
                sample_raw_payload = sample.get('raw_payload', '').lower()
                sample_features = sample.get('features', [])
                
                # Example: Sample indicates HTTP form, and we found one
                if ("http for sensitive form" in sample_raw_payload or (len(sample_features) > 0 and sample_features[0] == 1.0)) and \
                   any(v['type'] == "A02_Crypto_Sensitive_Form_Over_HTTP" for v in vulnerabilities):
                    # Could add confidence or a note, for now, it confirms existing finding.
                    pass
                
                # Example: Sample indicates weak cipher, and we found one
                if ("weak cipher" in sample_raw_payload or (len(sample_features) > 1 and sample_features[1] == 1.0)) and \
                   any(v['type'] == "A02_Crypto_Weak_Cipher_Detected" for v in vulnerabilities):
                    pass

                # Example: Sample indicates hardcoded secret, and we found one
                if ("hardcoded secret" in sample_raw_payload or (len(sample_features) > 2 and sample_features[2] == 1.0)) and \
                   any(v['type'] == "A02_Crypto_Hardcoded_Secret_In_HTML" for v in vulnerabilities):
                    pass

    return vulnerabilities 