# Detector for A01:2021 - Broken Access Control
import random
import re
from urllib.parse import urlparse, parse_qs, unquote_plus

def detect(site_data, samples=None):
    """Detects Broken Access Control vulnerabilities."""
    vulnerabilities = []
    site_url = site_data.get("url", "")
    site_content = site_data.get("content", "")
    site_content_lower = site_content.lower()
    site_headers = site_data.get("headers", {})
    
    # Проверяем, есть ли у нас ML-модель для A01 Broken Access Control
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на проблемы с контролем доступа с помощью ML
        ml_result = ml_detector.predict(site_data, "a01_broken_access_control")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A01_ML_Detection",
                "details": f"ML-модель обнаружила признаки нарушения контроля доступа с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A01: {e}")
    
    # Parse URL components for analysis
    parsed_url = urlparse(site_url)
    path = parsed_url.path
    path_segments = [segment for segment in path.split('/') if segment]
    query_params = parse_qs(parsed_url.query)
    
    # 1. Check for administrative/sensitive URLs without authentication indicators
    admin_keywords = [
        "admin", "administrator", "adm", "sysadmin", "moderator", "manage", "dashboard", 
        "control", "superuser", "root", "supervisor", "manager", "backend", "cpanel"
    ]
    
    restricted_section_keywords = [
        "profile", "account", "user", "settings", "config", "private", "personal",
        "secure", "protected", "internal", "secret", "premium", "vip", "billing"
    ]
    
    auth_indicators = [
        "login", "signin", "sign-in", "auth", "authenticate", "session", 
        "password", "token", "jwt", "oauth", "credential", "logged in", 
        "welcome back", "my account"
    ]
    
    # Check URL path for admin or restricted sections
    for segment in path_segments:
        segment_lower = segment.lower()
        is_admin_segment = any(keyword == segment_lower or keyword in segment_lower for keyword in admin_keywords)
        
        if is_admin_segment:
            # Check if there are authentication indicators in the page content
            has_auth_indicator = any(indicator in site_content_lower for indicator in auth_indicators)
            
            if not has_auth_indicator:
                vulnerabilities.append({
                    "type": "A01_Admin_Access_Without_Auth",
                    "details": f"Admin section '{segment}' in URL path without apparent authentication checks.",
                    "severity": "high"
                })
    
    # 2. Check for potential Insecure Direct Object References (IDOR)
    idor_param_patterns = [
        r'id=\d+', r'user_?id=\d+', r'account_?id=\d+', r'profile_?id=\d+',
        r'order_?id=\d+', r'item_?id=\d+', r'file_?id=\d+', r'doc_?id=\d+',
        r'record_?id=\d+', r'customer_?id=\d+', r'patient_?id=\d+', r'number=\d+'
    ]
    
    # Check URL for IDOR patterns
    for pattern in idor_param_patterns:
        if re.search(pattern, site_url, re.IGNORECASE):
            # Check for evidence of access control in content
            has_acl_indicators = any(indicator in site_content_lower for indicator in 
                                     ["permission", "access denied", "forbidden", "authorized", "not allowed"])
            
            # If no access control indicators, report potential IDOR
            if not has_acl_indicators:
                match = re.search(pattern, site_url, re.IGNORECASE)
                vulnerabilities.append({
                    "type": "A01_Potential_IDOR",
                    "details": f"Possible IDOR via parameter '{match.group(0)}' without apparent access control.",
                    "severity": "medium"
                })
    
    # 3. Check for numeric IDs in URL path segments (potential IDOR)
    for i, segment in enumerate(path_segments):
        # Look for numeric segments (potential resource IDs)
        if segment.isdigit() and len(segment) > 0 and i > 0:
            # Resource path often has a name before the ID, e.g., /users/123
            resource_name = path_segments[i-1] if i > 0 else "resource"
            vulnerabilities.append({
                "type": "A01_Path_Based_IDOR",
                "details": f"Numeric ID '{segment}' in URL path for resource '{resource_name}'. Verify access controls.",
                "severity": "medium"
            })
    
    # 4. Check for sensitive file extensions or paths that may bypass access controls
    sensitive_url_patterns = [
        r'\.(bak|old|backup|sql|zip|tar\.gz|config|conf|ini|log|env|git|svn)$\b',
        r'(?:\.git|\.svn|\.hg|\.env|\.DS_Store)/.*?',
        r'(?:phpmyadmin|adminer|wp-admin|wp-config|server-status|jenkins|jmx-console)',
        r'(?:phpinfo\.php|test\.php|info\.php|debug\.php|install\.php)',
        r'(?:/etc/|/var/|/bin/|/home/|/proc/|/sys/)',
        r'(?:/config/|/settings/|/backup/|/dump/|/logs/)'
    ]
    
    for pattern in sensitive_url_patterns:
        if re.search(pattern, site_url, re.IGNORECASE):
            match = re.search(pattern, site_url, re.IGNORECASE)
            vulnerabilities.append({
                "type": "A01_Sensitive_Path_Exposure",
                "details": f"URL contains sensitive path or file '{match.group(0)}' that may bypass access controls.",
                "severity": "high"
            })
    
    # 5. Check for missing/misconfigured CORS headers
    origin_header_value = None
    for header_name, header_value in site_headers.items():
        if header_name.lower() == "access-control-allow-origin":
            origin_header_value = header_value
            if origin_header_value == "*":
                vulnerabilities.append({
                    "type": "A01_Insecure_CORS",
                    "details": "Access-Control-Allow-Origin header is set to wildcard (*), potentially allowing unauthorized cross-origin access.",
                    "severity": "medium"
                })
            break
    
    # 6. Check for forced browsing opportunities
    if any(segment in path_segments for segment in ["hidden", "backup", "secret", "private", "internal"]):
        vulnerabilities.append({
            "type": "A01_Forced_Browsing",
            "details": f"URL path contains directories that suggest possible forced browsing exposure: {path}",
            "severity": "medium"
        })
    
    # 7. Look for horizontal privilege escalation hints
    for param_name, param_values in query_params.items():
        param_name_lower = param_name.lower()
        if param_name_lower in ["user", "username", "user_id", "account", "email", "profile"]:
            vulnerabilities.append({
                "type": "A01_Horizontal_Privilege_Escalation",
                "details": f"Parameter '{param_name}' allows specifying user identity. Verify proper access controls.",
                "severity": "medium"
            })
            break
    
    # 8. Check for vertical privilege escalation indicators
    for param_name, param_values in query_params.items():
        param_name_lower = param_name.lower()
        if param_name_lower in ["role", "type", "level", "admin", "access", "privilege", "group"]:
            for param_value in param_values:
                if param_value.lower() in ["admin", "administrator", "manager", "root", "superuser"]:
                    vulnerabilities.append({
                        "type": "A01_Vertical_Privilege_Escalation",
                        "details": f"Parameter '{param_name}={param_value}' may allow privilege escalation.",
                        "severity": "high"
                    })
                    break
    
    # 9. Leverage samples for more sophisticated pattern matching
    if samples:
        for sample in random.sample(samples, min(len(samples), 10)):
            if not sample.get("is_vulnerable"): 
                continue

            sample_url = sample.get("url", "")
            sample_html = sample.get("html", "")
            sample_raw_payload = sample.get("raw_payload", "")
            
            # Extract HTML indicators of BAC vulnerabilities
            sample_html_keywords = []
            bac_indicators = [
                "Admin Profile", "deleted successfully", "Full controls available", 
                "sensitive admin data", "all permissions", "administrative access", 
                "manage users", "user list", "all accounts", "full access"
            ]
            
            for indicator in bac_indicators:
                if indicator in sample_html:
                    sample_html_keywords.append(indicator.lower())
            
            # Check for URL pattern matches between sample and current URL
            try:
                # Replace numbers with (\d+) and try to match parts of the path
                sample_path = urlparse(sample_url).path
                url_pattern_str = re.sub(r'\d+', r"(\\d+)", sample_path)
                
                if len(url_pattern_str) > 5 and url_pattern_str != '/' and re.search(url_pattern_str, path):
                    # Check for content keywords that indicate BAC issues
                    for keyword in sample_html_keywords:
                        if keyword in site_content_lower:
                            vulnerabilities.append({
                                "type": "A01_BAC_Pattern_Match",
                                "details": f"URL matches vulnerable pattern '{url_pattern_str}' and content contains '{keyword}', suggesting BAC vulnerability. Sample: {sample_raw_payload}",
                                "severity": "high"
                            })
                            break
                    
                    # If no content keywords but URL pattern matches, still report with lower confidence
                    if not sample_html_keywords and re.search(url_pattern_str, path):
                        vulnerabilities.append({
                            "type": "A01_BAC_URL_Pattern_Only",
                            "details": f"URL matches vulnerable pattern '{url_pattern_str}' from sample {sample_url}. Verify access controls.",
                            "severity": "medium"
                        })
            except Exception as e:
                if ML_DEBUG:
                    print(f"Error processing BAC sample URL for regex: {sample_url} - {e}")
                continue
    
    # Deduplicate vulnerabilities
    unique_vulns = []
    seen_vuln_types = set()
    
    for vuln in vulnerabilities:
        vuln_key = vuln["type"]
        if vuln_key not in seen_vuln_types:
            unique_vulns.append(vuln)
            seen_vuln_types.add(vuln_key)
    
    return unique_vulns

# Assuming ML_DEBUG might be set globally or passed if this was part of a larger class
ML_DEBUG = True # Define locally for standalone use / testing 