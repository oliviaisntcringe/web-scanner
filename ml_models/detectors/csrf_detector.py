# Detector for Cross-Site Request Forgery (CSRF)
import random
import re
from urllib.parse import urlparse

def detect(site_data, samples=None):
    """Detects potential CSRF vulnerabilities."""
    vulnerabilities = []
    content = site_data.get("content", "")
    content_lower = content.lower()
    url = site_data.get("url", "")
    headers = site_data.get("headers", {})
    
    # Проверяем, есть ли у нас ML-модель для CSRF
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на CSRF с помощью ML
        ml_result = ml_detector.predict(site_data, "csrf")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "CSRF_ML_Detection",
                "details": f"ML-модель обнаружила признаки CSRF с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для CSRF: {e}")
    
    # Simplified but robust form pattern for POST forms with actions
    try:
        form_pattern = re.compile(
            r'(?si)<form(?=[^>]*method=([\'"]?)post\1)(?=[^>]*action=([\'"]?)(?P<action>[^\'">]*)\2)[^>]*>(?P<form_content>.*?)</form>'
        )
        
        # More general pattern to catch forms that might not specify an action explicitly
        simple_form_pattern = re.compile(
            r'(?si)<form(?=[^>]*method=([\'"]?)post\1)[^>]*>(?P<form_content>.*?)</form>'
        )
    except re.error as e:
        print(f"Regex compilation error in CSRF detector: {e}")
        form_pattern = None
        simple_form_pattern = None
    
    # CSRF token patterns within form content
    csrf_token_patterns = [
        # Common framework specific CSRF token field names
        r"input[^>]+(?:name|id)=(?P<q>['\"]?)(?:csrf[-_]?token|csrf|_csrf|authenticity_token|xsrf[-_]?token|anti[-_]?csrf|__RequestVerificationToken)(?P=q)",
        # CSRF meta tags
        r"meta[^>]+name=(?P<q>['\"]?)(?:csrf-token|csrf-param)(?P=q)",
        # Common hidden field patterns for CSRF tokens 
        r"input[^>]+type=(?P<q>['\"]?)hidden(?P=q)[^>]+name=(?P<q2>['\"]?)(?:token|_token|csrf|_csrf|auth_token)(?P=q2)",
        # Hidden input with value that looks like a token (random string/hash)
        r"input[^>]+type=(?P<q>['\"]?)hidden(?P=q)[^>]+value=(?P<q2>['\"]?)[a-zA-Z0-9_\-+=\/]{16,}(?P=q2)"
    ]
    
    # Check all forms
    forms_found = []
    if form_pattern is not None:
        try:
            forms_found = list(form_pattern.finditer(content))
            if not forms_found and simple_form_pattern is not None:
                # Fall back to simpler form pattern if no matches with the first pattern
                forms_found = list(simple_form_pattern.finditer(content))
        except Exception as e:
            print(f"Error searching for forms in CSRF detector: {e}")
    
    potential_csrf_forms = []
    
    for form_match in forms_found:
        form_content = form_match.group("form_content")
        action = form_match.group("action") if "action" in form_match.groupdict() else ""
        
                # Check if the form has a CSRF token
        has_token_in_form = False
        for token_pattern_str in csrf_token_patterns:
            try:
                token_pattern = re.compile(token_pattern_str, re.IGNORECASE)
                if token_pattern.search(form_content):
                    has_token_in_form = True
                    break
            except re.error as e:
                print(f"Regex error in CSRF detector for token pattern '{token_pattern_str}': {e}")
                continue
        
        if not has_token_in_form:
            # Heuristic: if action looks like a state-changing operation
            state_changing_keywords = [
                "delete", "update", "create", "add", "remove", "change", "set", "submit", 
                "post", "buy", "transfer", "upload", "modify", "edit", "register", "save",
                "checkout", "purchase", "pay", "confirm", "send", "approve", "reject"
            ]
            
            # Check if action contains state-changing keywords
            is_state_changing_action = False
            if action:
                is_state_changing_action = any(keyword in action.lower() for keyword in state_changing_keywords)
            
            # Check form content for fields that suggest state-changing operations
            sensitive_input_types = [
                "password", "email", "tel", "number", "file", "date", "time", "datetime-local",
                "month", "week", "credit-card", "money", "currency"
            ]
            
            has_sensitive_inputs = False
            input_pattern = re.compile(r'<input[^>]+type=([\'"]?)(?P<type>[^\'"]+)\1[^>]*>', re.IGNORECASE)
            for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                input_type = input_match.group("type").lower()
                if input_type in sensitive_inputs:
                    has_sensitive_inputs = True
                    break
            
            # Check if form contains buttons that suggest state changes
            button_pattern = re.compile(r'<button[^>]*>(?P<button_text>.*?)</button>', re.IGNORECASE | re.DOTALL)
            has_state_changing_button = False
            for button_match in re.finditer(button_pattern, form_content, re.IGNORECASE | re.DOTALL):
                button_text = button_match.group("button_text").lower()
                if any(keyword in button_text for keyword in state_changing_keywords):
                    has_state_changing_button = True
                    break
            
            # Decide if the form is vulnerable based on our heuristics
            if is_state_changing_action or has_sensitive_inputs or has_state_changing_button:
                form_excerpt = form_content[:200].replace("<", "&lt;").replace(">", "&gt;")
                potential_csrf_forms.append({
                    "action": action,
                    "excerpt": form_excerpt,
                    "has_sensitive_inputs": has_sensitive_inputs,
                    "is_state_changing_action": is_state_changing_action,
                    "has_state_changing_button": has_state_changing_button
                })
    
    # Report findings for forms without CSRF protection
    if potential_csrf_forms:
        for i, form in enumerate(potential_csrf_forms):
            form_details = f"Form {i+1} with action '{form['action']}'"
            reasons = []
            
            if form["is_state_changing_action"]:
                reasons.append("action URL contains state-changing keywords")
            if form["has_sensitive_inputs"]:
                reasons.append("contains sensitive input fields")
            if form["has_state_changing_button"]:
                reasons.append("contains buttons with state-changing text")
                
            reasons_text = ", ".join(reasons)
            severity = "high" if len(reasons) > 1 else "medium"
            
            vulnerabilities.append({
                "type": "CSRF_Unprotected_Form",
                "details": f"{form_details} lacks CSRF protection and {reasons_text}. Form excerpt: {form['excerpt']}",
                "severity": severity
            })
    
    # Check for SameSite cookie attributes (relevant for CSRF defense)
    cookie_headers = []
    for header_name, header_value in headers.items():
        if header_name.lower() == "set-cookie":
            if isinstance(header_value, list):
                cookie_headers.extend(header_value)
            else:
                cookie_headers.append(header_value)
    
    if cookie_headers:
        # Check for cookies without SameSite attribute
        cookies_without_samesite = 0
        session_cookie_without_samesite = False
        
        for cookie in cookie_headers:
            # Check if it's a session or authentication cookie
            is_sensitive_cookie = any(name in cookie.lower() for name in ["session", "auth", "token", "id", "user", "logged", "jsessionid", "phpsessid", "aspsessionid"])
            
            # Check for SameSite attribute
            if "samesite=none" in cookie.lower() or (not "samesite=lax" in cookie.lower() and not "samesite=strict" in cookie.lower()):
                cookies_without_samesite += 1
                if is_sensitive_cookie:
                    session_cookie_without_samesite = True
        
        if cookies_without_samesite > 0:
            severity = "high" if session_cookie_without_samesite else "medium"
            vulnerabilities.append({
                "type": "CSRF_Cookie_SameSite_Missing",
                "details": f"Found {cookies_without_samesite} cookie(s) without secure SameSite attribute. " +
                           ("Session/authentication cookies are affected, increasing CSRF risk." if session_cookie_without_samesite else ""),
                "severity": severity
            })
    
    # Check for absence of custom headers that can help prevent CSRF
    csrf_protection_headers = ["X-CSRF-Token", "X-Frame-Options", "Content-Security-Policy"]
    missing_headers = [header for header in csrf_protection_headers 
                      if not any(h.lower() == header.lower() for h in headers.keys())]
    
    if missing_headers and potential_csrf_forms:
        vulnerabilities.append({
            "type": "CSRF_Missing_Protection_Headers",
            "details": f"Forms present but missing recommended security headers for CSRF mitigation: {', '.join(missing_headers)}",
            "severity": "medium"
        })
    
    # Check if origin/referer checking might be in place
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    origin_checking_indicator = False
    
    # Look for code that might check origin/referer
    origin_checking_patterns = [
        r"(?:origin|referer|referrer)(?:\s*==\s*|\s*===\s*|\s*!=\s*|\s*!==\s*|\s*\.indexOf\s*\(\s*)",
        r"check(?:Origin|Referer|Referrer)",
        r"validate(?:Origin|Referer|Referrer)",
        r"(?:origin|referer|referrer)(?:\s*\.\s*match\s*\(\s*)"
    ]
    
    for pattern in origin_checking_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            origin_checking_indicator = True
            break
    
    # If forms are present, but no CSRF tokens and no origin checking is detected
    if potential_csrf_forms and not origin_checking_indicator and not any("CSRF" in vuln["type"] for vuln in vulnerabilities):
        vulnerabilities.append({
            "type": "CSRF_No_Protection_Mechanism",
            "details": "Forms with state-changing actions present, but no CSRF tokens or origin verification mechanisms detected.",
            "severity": "high"
        })
    
    # If samples are provided, correlate with known vulnerable patterns
    if samples and potential_csrf_forms:
        # Find vulnerable samples to compare with
        vulnerable_samples = [s for s in samples if s.get("is_vulnerable")]
        
        if vulnerable_samples:
            # Get a sample of vulnerable cases
            for sample in random.sample(vulnerable_samples, min(len(vulnerable_samples), 5)):
                sample_html = sample.get("html", "")
                sample_features = sample.get("features", [])
                
                # Check if our site has similar characteristics to vulnerable samples
                if len(sample_features) > 10:
                    # Assuming feature[10] is csrf_token_in_html count (0 means none found)
                    if sample_features[10] == 0 and potential_csrf_forms:
                        sample_description = sample.get("description", "")
                        vulnerabilities.append({
                            "type": "CSRF_Correlation_With_Sample",
                            "details": f"Site has similar characteristics to known vulnerable CSRF samples (absence of tokens in forms). Sample reference: {sample_description}",
                            "severity": "medium"
                        })
                        break
    
    # Deduplicate findings
    unique_vulnerabilities = []
    seen_types = set()
    
    for vuln in vulnerabilities:
        vuln_type = vuln["type"]
        if vuln_type not in seen_types:
            unique_vulnerabilities.append(vuln)
            seen_types.add(vuln_type)
    
    return unique_vulnerabilities 