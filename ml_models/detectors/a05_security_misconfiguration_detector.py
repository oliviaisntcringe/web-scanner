import re
import random
from urllib.parse import urlparse

# Detector for A05:2021 - Security Misconfiguration

# Expanded security header checklist with expected values and severity levels
SECURITY_HEADERS_CHECKLIST = {
    "Content-Security-Policy": {
        "severity": "medium",
        "recommendation": "Implement CSP to prevent XSS and data injection attacks"
    },
    "Strict-Transport-Security": {
        "expected": "max-age=31536000; includeSubDomains",
        "severity": "medium",
        "recommendation": "Set HSTS with at least 1 year max-age and includeSubDomains"
    },
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "severity": "medium",
        "recommendation": "Set X-Content-Type-Options to nosniff to prevent MIME-type sniffing"
    },
    "X-Frame-Options": {
        "expected": ["DENY", "SAMEORIGIN"],
        "severity": "medium",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking"
    },
    "Referrer-Policy": {
        "expected": ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"],
        "severity": "low",
        "recommendation": "Set appropriate Referrer-Policy to control information in the Referer header"
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": "Use Permissions-Policy to control browser features"
    },
    "X-XSS-Protection": {
        "expected": "1; mode=block",
        "severity": "low",
        "recommendation": "Set X-XSS-Protection for older browsers that don't support CSP"
    },
    "Cache-Control": {
        "expected": ["no-store", "no-cache, no-store", "private, no-cache, no-store"],
        "severity": "low",
        "recommendation": "Set Cache-Control headers for sensitive pages to prevent caching"
    }
}

# Expanded patterns for verbose error messages
VERBOSE_ERROR_PATTERNS = [
    # Database errors
    r"sql syntax", r"mysql error", r"ora-[0-9]{5}", r"postgresql query failed",
    r"db2 sql error", r"sqlite3?\.[a-z]+error", r"sqlserver\.data\.[a-z]+exception",
    
    # Stack traces
    r"stack trace:", r"stacktrace:", r"exception in thread", r"uncaught exception",
    r"Traceback \(most recent call last\):", r"at [a-zA-Z0-9$_.]+\([a-zA-Z0-9$_.:]+\)",
    r"at [a-zA-Z0-9$_.]+\.[a-zA-Z0-9$_]+\([a-zA-Z0-9$_.]+\.java:\d+\)",
    r"([a-zA-Z0-9./-]+\.(?:java|php|py|rb|js|cs|go)):(\d+)",
    
    # PHP errors
    r"Warning: [a-zA-Z0-9_()]+", r"Notice: [a-zA-Z0-9_()]+", r"Fatal error:",
    r"Call to undefined function", r"failed to open stream", r"include\(\): Failed opening",
    
    # Python errors
    r"File \"[^\"]+\", line \d+", r"Traceback \(most recent call last\):",
    r"IndexError:", r"KeyError:", r"ImportError:", r"ModuleNotFoundError:",
    
    # Node.js/JavaScript errors
    r"ReferenceError:", r"TypeError:", r"SyntaxError:", r"RangeError:",
    r"Error: Cannot find module", r"UnhandledPromiseRejectionWarning:",
    
    # Common web frameworks
    r"Django (?:Version: )?\d+\.\d+\.\d+", r"Ruby on Rails (?:Version: )?\d+\.\d+\.\d+",
    r"Laravel (?:Version: )?\d+\.\d+\.\d+", r"Express (?:Version: )?\d+\.\d+\.\d+",
    r"ActionController::(?:Routing)?Error",
]

# Software version disclosure patterns
SOFTWARE_VERSION_PATTERNS = [
    r"Apache/(\d+\.\d+\.\d+)", r"nginx/(\d+\.\d+\.\d+)", r"PHP/(\d+\.\d+\.\d+)",
    r"MySQL/(\d+\.\d+\.\d+)", r"MariaDB/(\d+\.\d+\.\d+)", r"PostgreSQL (\d+\.\d+)",
    r"Python/(\d+\.\d+\.\d+)", r"Ruby/(\d+\.\d+\.\d+)", r"Node\.js/(\d+\.\d+\.\d+)",
    r"ASP\.NET (\d+\.\d+\.\d+)", r"IIS/(\d+\.\d+)", r"OpenSSL/(\d+\.\d+\.\d+)",
    r"jQuery v?(\d+\.\d+\.\d+)", r"Bootstrap v?(\d+\.\d+\.\d+)", r"React v?(\d+\.\d+\.\d+)",
    r"Drupal (\d+\.\d+)", r"WordPress (\d+\.\d+\.\d+)", r"Joomla! (\d+\.\d+\.\d+)",
    r"Tomcat/(\d+\.\d+\.\d+)", r"JBoss(?:-EAP)?/(\d+\.\d+\.\d+)", r"WebLogic (\d+\.\d+\.\d+)"
]

# Default credentials patterns
DEFAULT_CREDENTIAL_PATTERNS = [
    r"admin:admin", r"admin:password", r"root:root", r"admin:123456", r"user:user",
    r"guest:guest", r"demo:demo", r"test:test", r"default:default", r"admin:pass",
    r"admin:123", r"username:password", r"administrator:administrator"
]

# Development/debug features patterns
DEBUG_FEATURE_PATTERNS = [
    r"debug=[tT]rue", r"debug_mode=[tT]rue", r"[dD]ebug [mM]ode [eE]nabled",
    r"[aA]pp [iI]n [dD]ebug [mM]ode", r"[dD]evelopment [mM]ode",
    r"ENVIRONMENT=(?:dev|development|test|testing)",
    r"APP_ENV=(?:dev|development|test|testing)"
]

def detect(site_data, samples=None):
    """Detects Security Misconfiguration vulnerabilities."""
    vulnerabilities = []
    content = site_data.get("content", "")
    content_lower = content.lower()
    headers = site_data.get("headers", {})
    url = site_data.get("url", "")
    
    # Проверяем, есть ли у нас ML-модель для Security Misconfiguration
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Security Misconfiguration с помощью ML
        ml_result = ml_detector.predict(site_data, "a05_security_misconfiguration")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A05_Security_Misconfiguration_ML",
                "details": f"ML-модель обнаружила признаки неправильной конфигурации безопасности с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A05 Security Misconfiguration: {e}")
    
    # Ensure header keys are checked case-insensitively
    site_header_keys_lower = {k.lower(): k for k in headers.keys()}
    
    # 1. Enhanced check for missing or misconfigured security headers
    for header_name, header_info in SECURITY_HEADERS_CHECKLIST.items():
        header_lower = header_name.lower()
        
        # Check if header exists
        if header_lower not in site_header_keys_lower:
            vulnerabilities.append({
                "type": "A05_Missing_Security_Header",
                "details": f"Security header '{header_name}' is missing. {header_info.get('recommendation')}",
                "severity": header_info.get("severity", "medium")
            })
        else:
            # If header exists, check its value when an expected value is defined
            if "expected" in header_info:
                header_value = headers.get(site_header_keys_lower.get(header_lower), "").lower()
                expected_values = header_info["expected"] if isinstance(header_info["expected"], list) else [header_info["expected"].lower()]
                
                # Check if the header value matches any of the expected values
                if not any(expected.lower() in header_value for expected in expected_values):
                    vulnerabilities.append({
                        "type": "A05_Misconfigured_Security_Header",
                        "details": f"Security header '{header_name}' has value '{headers.get(site_header_keys_lower.get(header_lower))}' but expected one of: {', '.join(expected_values)}. {header_info.get('recommendation')}",
                        "severity": header_info.get("severity", "medium")
                    })
    
    # 2. Enhanced check for verbose error messages in content
    for pattern_str in VERBOSE_ERROR_PATTERNS:
        match = re.search(pattern_str, content, re.IGNORECASE)
        if match:
            error_text = match.group(0)
            start_pos = max(0, match.start() - 30)
            end_pos = min(len(content), match.end() + 30)
            context = content[start_pos:end_pos].replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
            
            vulnerabilities.append({
                "type": "A05_Verbose_Error_Message",
                "details": f"Verbose error message found in content: '{context}'",
                "severity": "medium"
            })
            break  # Report only the first verbose error found to reduce noise
    
    # 3. Enhanced check for software version disclosure
    disclosed_versions = []
    
    # Check headers for version disclosure
    server_header_key = site_header_keys_lower.get("server")
    if server_header_key:
        server_header = headers.get(server_header_key, "")
        for pattern in SOFTWARE_VERSION_PATTERNS:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                disclosed_versions.append({
                    "software": match.group(0).split("/")[0],
                    "version": match.group(1),
                    "location": "Server header"
                })
    
    x_powered_by_key = site_header_keys_lower.get("x-powered-by")
    if x_powered_by_key:
        x_powered_by = headers.get(x_powered_by_key, "")
        for pattern in SOFTWARE_VERSION_PATTERNS:
            match = re.search(pattern, x_powered_by, re.IGNORECASE)
            if match:
                disclosed_versions.append({
                    "software": match.group(0).split("/")[0],
                    "version": match.group(1),
                    "location": "X-Powered-By header"
                })
    
    # Check content for version disclosure
    for pattern in SOFTWARE_VERSION_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            disclosed_versions.append({
                "software": match.group(0).split("/")[0],
                "version": match.group(1),
                "location": "HTML content"
            })
    
    # Report disclosed versions
    if disclosed_versions:
        for version_info in disclosed_versions[:3]:  # Limit to first 3 findings
            vulnerabilities.append({
                "type": "A05_Version_Disclosure",
                "details": f"Software version disclosed: {version_info['software']} version {version_info['version']} in {version_info['location']}",
                "severity": "medium"
            })
    
    # 4. Check for directory listing
    directory_listing_patterns = [
        r"<title>Index of /", r"<h1>Index of /", r"<h1>Directory Listing For /",
        r"Directory Listing for /", r"Parent Directory</a>.*Last modified</a>.*Size</a>"
    ]
    
    for pattern in directory_listing_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            vulnerabilities.append({
                "type": "A05_Directory_Listing_Enabled",
                "details": "Directory listing is enabled on this server, exposing file and directory names.",
                "severity": "high"
            })
            break
    
    # 5. Check for default credentials or mentions in content
    for pattern in DEFAULT_CREDENTIAL_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            match = re.search(pattern, content, re.IGNORECASE)
            vulnerabilities.append({
                "type": "A05_Default_Credentials",
                "details": f"Potential default credentials found in content: '{match.group(0)}'",
                "severity": "high"
            })
            break
    
    # 6. Check for development/debug features
    for pattern in DEBUG_FEATURE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, url, re.IGNORECASE):
            match_location = "URL" if re.search(pattern, url, re.IGNORECASE) else "content"
            match = re.search(pattern, url if match_location == "URL" else content, re.IGNORECASE)
            vulnerabilities.append({
                "type": "A05_Debug_Mode_Enabled",
                "details": f"Application appears to be running in debug/development mode. Found '{match.group(0)}' in {match_location}.",
                "severity": "high"
            })
            break
    
    # 7. Check for backup or temporary files in URL
    backup_file_patterns = [
        r"\.bak$", r"\.backup$", r"\.old$", r"\.orig$", r"\.tmp$", r"\.temp$",
        r"\.swp$", r"~$", r"\.save$", r"\.copy$", r"\.bk$", r"\.BAK$"
    ]
    
    parsed_url = urlparse(url)
    path = parsed_url.path
    
    for pattern in backup_file_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            vulnerabilities.append({
                "type": "A05_Backup_File_Exposure",
                "details": f"URL points to a potential backup or temporary file: '{path}'",
                "severity": "high"
            })
            break
    
    # 8. Check for improper CORS configuration
    cors_header_key = site_header_keys_lower.get("access-control-allow-origin")
    if cors_header_key:
        cors_value = headers.get(cors_header_key, "")
        if cors_value == "*":
            vulnerabilities.append({
                "type": "A05_Insecure_CORS_Configuration",
                "details": "Access-Control-Allow-Origin header is set to wildcard (*), allowing any domain to access resources.",
                "severity": "medium"
            })
    
    # 9. Check for XML External Entity (XXE) potential
    xxe_patterns = [
        r"<!DOCTYPE[^>]*SYSTEM", r"<!ENTITY\s+\w+\s+SYSTEM", r"<!ENTITY\s+%\s+\w+\s+SYSTEM"
    ]
    
    content_type_key = site_header_keys_lower.get("content-type")
    if content_type_key:
        content_type = headers.get(content_type_key, "").lower()
        if "xml" in content_type:
            for pattern in xxe_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "A05_XXE_Potential",
                        "details": "XML content with DTD that may be vulnerable to XXE attacks.",
                        "severity": "high"
                    })
                    break
    
    # 10. Correlation with samples if available
    if samples:
        vulnerable_samples = [s for s in samples if s.get("is_vulnerable")]
        
        if vulnerable_samples:
            for sample in random.sample(vulnerable_samples, min(len(vulnerable_samples), 3)):
                sample_headers = sample.get("headers", {})
                sample_content = sample.get("html", "")
                sample_features = sample.get("features", [])
                
                # Compare headers with sample
                for header_name in SECURITY_HEADERS_CHECKLIST.keys():
                    header_lower = header_name.lower()
                    # If sample is vulnerable and missing this header, and our site is also missing it
                    if header_lower not in {h.lower() for h in sample_headers.keys()} and header_lower not in site_header_keys_lower:
                        # This adds confidence to our finding, but we've already reported it
                        pass
                
                # Check for similar error patterns in content
                if any(re.search(pattern, sample_content, re.IGNORECASE) for pattern in VERBOSE_ERROR_PATTERNS):
                    # If we find similar error patterns in both, it increases confidence
                    for pattern in VERBOSE_ERROR_PATTERNS:
                        if re.search(pattern, sample_content, re.IGNORECASE) and re.search(pattern, content, re.IGNORECASE):
                            vulnerabilities.append({
                                "type": "A05_Sample_Error_Pattern_Match",
                                "details": f"Error pattern found in content matches pattern in vulnerable sample. Sample description: {sample.get('description', 'N/A')}",
                                "severity": "medium"
                            })
                            break
    
    # Deduplicate vulnerabilities by type to reduce noise
    unique_vulnerabilities = []
    seen_types = set()
    
    for vuln in vulnerabilities:
        vuln_type = vuln["type"]
        if vuln_type not in seen_types:
            unique_vulnerabilities.append(vuln)
            seen_types.add(vuln_type)
        elif vuln_type == "A05_Version_Disclosure":  # Special case: allow multiple version disclosures but limit them
            if len([v for v in unique_vulnerabilities if v["type"] == "A05_Version_Disclosure"]) < 3:
                unique_vulnerabilities.append(vuln)
    
    return unique_vulnerabilities 