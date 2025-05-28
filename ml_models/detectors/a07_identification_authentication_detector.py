# Detector for A07:2021 - Identification and Authentication Failures
import re

# Session ID patterns in URL
SESSION_ID_URL_PATTERNS = ["phpsessid=", "jsessionid=", "sessionid=", "sid=", "aspsessionid", "sessid=", "user_session=", "zenid="]

# Default credential hints in input fields (value attribute)
DEFAULT_CRED_VALUES = {
    "admin": ["admin", "root", "administrator"],
    "password": ["password", "123456", "admin", "root", "changeme", "secret"]
}

# Keywords indicating a login, registration, or password reset page
AUTH_PAGE_KEYWORDS = [
    "login", "log in", "sign in", "signin", "authenticate", "authentication",
    "register", "registration", "sign up", "signup", "create account",
    "forgot password", "reset password", "password recovery"
]

# Keywords indicating user-specific content (suggesting a session might be active)
USER_CONTENT_KEYWORDS = [
    "my account", "user profile", "dashboard", "welcome,", "logged in as", "member area"
]

def detect(site_data, samples=None):
    """Detects potential Identification and Authentication Failures."""
    vulnerabilities = []
    url_lower = site_data.get("url", "").lower()
    content_lower = site_data.get("content", "").lower()
    content_original_case = site_data.get("content", "") # For regex needing original case or specific values
    headers_lower = {k.lower(): v for k, v in site_data.get("headers", {}).items()}
    
    # Проверяем, есть ли у нас ML-модель для Identification and Authentication Failures
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Identification and Authentication Failures с помощью ML
        ml_result = ml_detector.predict(site_data, "a07_identification_authentication")
        
        # Проверяем, что результат не None и предсказание доступно
        if ml_result and ml_result.get("prediction") is not None and ml_result.get("confidence", 0) > 0.7:
            vulnerabilities.append({
                "type": "A07_Ident_Auth_ML",
                "details": f"ML-модель обнаружила признаки проблем идентификации/аутентификации с уверенностью {ml_result.get('confidence', 0):.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A07 Identification and Authentication Failures: {e}")
        # Продолжаем выполнение других проверок даже при ошибке ML

    is_auth_page = any(keyword in content_lower for keyword in AUTH_PAGE_KEYWORDS) or \
                   any(keyword in url_lower for keyword in AUTH_PAGE_KEYWORDS)
    is_user_specific_page = any(keyword in content_lower for keyword in USER_CONTENT_KEYWORDS)

    # 1. Session ID or Sensitive Token in URL
    for pattern in SESSION_ID_URL_PATTERNS:
        if pattern in url_lower:
            vulnerabilities.append({
                "type": "A07_Ident_Auth_Session_In_URL",
                "details": f"Potential session ID or sensitive token exposure in URL (matched: '{pattern}'). Session identifiers should not be transmitted in URLs."
            })
            break
    # Check for password reset tokens in URL (common pattern)
    if ("token=" in url_lower or "reset_token=" in url_lower or "verification_code=" in url_lower) and \
       ("reset" in url_lower or "forgot" in url_lower or "verify" in url_lower or "activate" in url_lower):
        if not any(v["details"].startswith("Potential password reset token") for v in vulnerabilities):
             vulnerabilities.append({
                "type": "A07_Ident_Auth_Reset_Token_In_URL",
                "details": "Potential password reset token or verification code found in URL. These should be short-lived and handled securely."
            })

    # 2. Autocomplete on Password Fields
    # Regex to find input fields, then check type and autocomplete
    input_tags = re.finditer(r'<input([^>]+)>', content_original_case, re.IGNORECASE)
    for tag_match in input_tags:
        attributes_str = tag_match.group(1)
        type_match = re.search(r'type\s*=\s*([\'"]?)password\1', attributes_str, re.IGNORECASE)
        if type_match:
            # Check if autocomplete is NOT explicitly "off"
            autocomplete_attr = re.search(r'autocomplete\s*=\s*([\'"]?)off\1', attributes_str, re.IGNORECASE)
            if not autocomplete_attr:
                # Check if this specific finding is already added (e.g. from another password field on the same page)
                if not any(v["type"] == "A07_Ident_Auth_Autocomplete_Password" for v in vulnerabilities):
                    vulnerabilities.append({
                        "type": "A07_Ident_Auth_Autocomplete_Password",
                        "details": "Password field found that does not explicitly set autocomplete='off'. Browsers may autofill, which can be a risk on shared devices."
                    })
                    break # Report once per page for this general finding

    # 3. Weak Logout Heuristic (Presence of user content without obvious logout links)
    if is_user_specific_page:
        logout_link_present = any(re.search(r'<a[^>]+href\s*=\s*([\'"]?)([^\'"\s>]*logout|[^\'"\s>]*signout)[^>]*>', content_lower) for link_pattern in ["logout", "signout"])
        if not logout_link_present and not any(kw in content_lower for kw in ["log out", "sign out"]):
            if not any(v["type"] == "A07_Ident_Auth_Weak_Logout_Heuristic" for v in vulnerabilities):
                vulnerabilities.append({
                    "type": "A07_Ident_Auth_Weak_Logout_Heuristic",
                    "details": "Page contains user-specific keywords (e.g., 'my account', 'dashboard') but no clear 'logout' or 'signout' link was detected. Ensure robust session termination."
                })

    # 4. Default Credential Hints in Form Input Fields
    # More targeted: find username/email and password fields close to each other
    forms = re.finditer(r'<form([^>]*)>(.*?)</form>', content_original_case, re.DOTALL | re.IGNORECASE)
    for form_match in forms:
        form_content = form_match.group(2)
        username_input = re.search(r'<input[^>]+(?:name|id)\s*=\s*([\'"]?)(?:user(?:name)?|email|login|usr|log)\1[^>]*>', form_content, re.IGNORECASE)
        password_input = re.search(r'<input[^>]+type\s*=\s*([\'"]?)password\1[^>]*>', form_content, re.IGNORECASE)

        if username_input and password_input:
            user_field_html = username_input.group(0)
            pass_field_html = password_input.group(0)
            
            for val_pattern_key, val_patterns in DEFAULT_CRED_VALUES.items():
                for val_pattern in val_patterns:
                    # Check in username field
                    if val_pattern_key == "admin" and re.search(r'value\s*=\s*([\'"]?)' + re.escape(val_pattern) + r'\1', user_field_html, re.IGNORECASE):
                        if not any(d["details"].startswith(f"Potential default username hint ('{val_pattern}')") for d in vulnerabilities):
                            vulnerabilities.append({
                                "type": "A07_Ident_Auth_Default_Username_Hint",
                                "details": f"Potential default username hint ('{val_pattern}') found in a form input field. Default credentials should be changed."
                            })
                    # Check in password field (less common to be pre-filled, but check anyway)
                    if val_pattern_key == "password" and re.search(r'value\s*=\s*([\'"]?)' + re.escape(val_pattern) + r'\1', pass_field_html, re.IGNORECASE):
                         if not any(d["details"].startswith(f"Potential default password hint ('{val_pattern}')") for d in vulnerabilities):
                            vulnerabilities.append({
                                "type": "A07_Ident_Auth_Default_Password_Hint",
                                "details": f"Potential default password hint ('{val_pattern}') found pre-filled in a password input field. This is highly insecure if true."
                            })
    
    # 5. User Enumeration Hints (via verbose messages on auth pages)
    if is_auth_page:
        user_enum_errors = [
            "username does not exist", "user not found", "no such user", "invalid username",
            "this email is not registered", "account with this email does not exist"
        ]
        # Avoid matching these if they are clearly *successful* registration messages
        if not any(ok_msg in content_lower for ok_msg in ["registration successful", "account created"]):
            for error_msg in user_enum_errors:
                if error_msg in content_lower:
                    if not any(v["type"] == "A07_Ident_Auth_User_Enumeration_Hint" for v in vulnerabilities):
                        vulnerabilities.append({
                            "type": "A07_Ident_Auth_User_Enumeration_Hint",
                            "details": f"Potential user enumeration: Page contains message '{error_msg}', which may reveal whether a username/email exists."
                        })
                        break
    
    # 6. Missing Brute-Force Protection Hints (CAPTCHA) on Auth Pages
    if is_auth_page:
        # Common CAPTCHA indicators (simplified)
        captcha_indicators = ["captcha", "recaptcha", "hcaptcha", "turnstile", "am i human", "security check", "are you a robot"]
        has_captcha = any(indicator in content_lower for indicator in captcha_indicators) or \
                      any(re.search(r'class\s*=\s*([\'"]?).*(?:captcha|recaptcha)[^\'">]*\1', content_lower)) or \
                      any(re.search(r'id\s*=\s*([\'"]?).*(?:captcha|recaptcha)[^\'">]*\1', content_lower))
        
        if not has_captcha:
            # Only report if it looks like a form that would need protection
            if re.search(r'<form[^>]+method\s*=\s*([\'"]?)post\1', content_lower, re.IGNORECASE) and \
               any(input_type in content_lower for input_type in ['type="password"', 'type=\"password\'']):
                if not any(v["type"] == "A07_Ident_Auth_Missing_Captcha_Hint" for v in vulnerabilities):
                    vulnerabilities.append({
                        "type": "A07_Ident_Auth_Missing_Captcha_Hint",
                        "details": "Authentication page (login, registration, or password reset) does not appear to have CAPTCHA or similar brute-force protection. This is a heuristic check."
                    })

    # Deduplicate findings
    unique_vulnerabilities = []
    seen_vulns = set()
    for vuln in vulnerabilities:
        vuln_key = (vuln["type"], vuln["details"][:70]) 
        if vuln_key not in seen_vulns:
            unique_vulnerabilities.append(vuln)
            seen_vulns.add(vuln_key)
            
    return unique_vulnerabilities 