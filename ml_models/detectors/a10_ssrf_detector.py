# Detector for A10:2021 - Server-Side Request Forgery (SSRF)
import random
import re
from urllib.parse import urlparse, parse_qs, unquote_plus

def detect(site_data, samples=None):
    """Detects Server-Side Request Forgery vulnerabilities."""
    vulnerabilities = []
    url = site_data.get("url", "")
    url_lower = url.lower()
    unquoted_url = unquote_plus(url_lower)
    content = site_data.get("content", "")
    content_lower = content.lower()
    headers = site_data.get("headers", {})
    
    # Проверяем, есть ли у нас ML-модель для SSRF
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на SSRF с помощью ML
        ml_result = ml_detector.predict(site_data, "ssrf")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A10_SSRF_ML_Detection",
                "details": f"ML-модель обнаружила признаки SSRF с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для SSRF: {e}")
    
    # Parse URL for analysis
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # 1. SSRF via URL Parameters - Check for parameters that typically accept URLs/paths
    ssrf_param_keywords = [
        "url", "uri", "link", "src", "href", "path", "file", "document", 
        "location", "redirect", "redirecturl", "return", "returnurl", 
        "next", "target", "dest", "destination", "domain", "callback", 
        "resource", "load", "page", "feed", "host", "site", "server", 
        "address", "ip", "fetch", "proxy", "navigate", "jump", "data",
        "reference", "img", "image", "imageurl", "doc", "filename"
    ]
    
    # Patterns for internal/private network resources (commonly targeted in SSRF)
    private_network_patterns = [
        # IPv4 private ranges
        r"127\.0\.0\.\d+", r"10\.\d+\.\d+\.\d+", 
        r"172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+", 
        r"192\.168\.\d+\.\d+", r"169\.254\.\d+\.\d+",
        # Common internal hostnames
        r"localhost", r"internal", r"intranet", r"private", r"corp", 
        r"local", r"lan", r"net", r"srv", r"dmz", r"stage", r"dev",
        # Cloud metadata endpoints
        r"169\.254\.169\.254", r"metadata\.google", r"metadata\.azure", 
        r"169\.254\.170\.2", r"fd00:ec2::254",
        # File schemes and unusual protocols
        r"file:///", r"gopher://", r"dict://", r"ldap://", r"tftp://", 
        r"jar://", r"ftp://localhost"
    ]
    
    # 2. Check all query parameters for SSRF indicators
    for param_name, param_values in query_params.items():
        param_name_lower = param_name.lower()
        
        # Check if parameter name is SSRF-related
        is_ssrf_param = any(keyword in param_name_lower for keyword in ssrf_param_keywords)
        
        for param_value in param_values:
            param_value_lower = param_value.lower()
            
            # Check if the parameter value looks like a URL
            is_url_value = re.match(r'^(https?://|file://|ftp://|gopher://|dict://|ldap://|tftp://|jar://)', param_value_lower)
            
            # Check if the parameter value targets private/internal resources
            targets_private_network = any(re.search(pattern, param_value_lower) for pattern in private_network_patterns)
            
            # Determine severity based on parameter type and value
            if is_ssrf_param and (is_url_value or targets_private_network):
                severity = "high" if targets_private_network else "medium"
                vulnerability_type = "A10_SSRF_URL_Parameter"
                
                details = f"Potential SSRF in parameter '{param_name}' with value '{param_value[:75]}...'"
                if targets_private_network:
                    details += " targeting private network/internal resources."
                
                vulnerabilities.append({
                    "type": vulnerability_type,
                    "details": details,
                    "severity": severity
                })
    
    # 3. Check for URL path-based SSRF
    # Sometimes SSRF is in the path component rather than parameters
    path = parsed_url.path.lower()
    
    # Check if path contains URL-like components
    encoded_url_in_path = re.search(r'(?:%3A%2F%2F|https?:|file:|ftp:)[^&]*', path)
    if encoded_url_in_path:
        match_value = encoded_url_in_path.group(0)
        vulnerabilities.append({
            "type": "A10_SSRF_Path_Based",
            "details": f"Potential SSRF with URL encoded in path: '{match_value}'",
            "severity": "medium"
        })
    
    # 4. Check for common SSRF error messages in response content
    ssrf_error_patterns = [
        # Connection errors
        r"failed to connect to \S+", r"connection refused", r"connection timed out",
        r"could not resolve host", r"no route to host", r"timeout was reached",
        r"network is unreachable", r"DNS resolution failed", 
        
        # Common SSRF-related errors
        r"failed to open stream", r"can't connect to local", r"error fetching URL",
        r"URL using bad/illegal format", r"malformed URL", r"unable to connect",
        
        # Security-related messages
        r"ssrf detected", r"illegal URL", r"URL access denied", r"blocked by security policy",
        r"URL blocked", r"URL not allowed", r"invalid hostname", r"invalid URL scheme",
        
        # Framework-specific
        r"java\.net\.ConnectException", r"java\.net\.UnknownHostException",
        r"System\.Net\.WebException", r"curl error", r"Request failed with status code",
        r"urllib.error"
    ]
    
    for pattern in ssrf_error_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            error_context = content[max(0, match.start() - 40):min(len(content), match.end() + 40)].replace("\n", " ")
            vulnerabilities.append({
                "type": "A10_SSRF_Error_Message",
                "details": f"Response contains error message indicative of SSRF: '{error_context}'",
                "severity": "medium"
            })
            break
    
    # 5. Check response headers for SSRF indicators
    server_header = next((headers[h] for h in headers if h.lower() == 'server'), None)
    
    if server_header and any(indicator in server_header.lower() for indicator in ["internal", "localhost", "127.0.0.1"]):
        vulnerabilities.append({
            "type": "A10_SSRF_Server_Header",
            "details": f"Server header contains internal hostname/IP: '{server_header}'",
            "severity": "medium"
        })
    
    # 6. Look for HTTP responses in the HTML content (sign of proxied content)
    http_response_in_content = re.search(r'HTTP/[12]\.[01] [2-5]\d\d [A-Za-z ]+', content)
    if http_response_in_content:
        vulnerabilities.append({
            "type": "A10_SSRF_HTTP_Response_In_Content",
            "details": f"HTTP response line found in page content: '{http_response_in_content.group(0)}', possibly indicating proxied content via SSRF",
            "severity": "medium"
        })
    
    # 7. Analyze available samples if present
    if samples:
        # Find relevant vulnerable samples
        vulnerable_samples = [s for s in samples if s.get("is_vulnerable")]
        
        if vulnerable_samples:
            # Sample some of the vulnerable cases to check for patterns
            for sample in random.sample(vulnerable_samples, min(len(vulnerable_samples), 5)):
                sample_url = sample.get("url", "").lower()
                sample_payload = sample.get("raw_payload", "").lower()
                
                # Check if our URL contains similar patterns to known SSRF payloads
                if sample_payload:
                    # Extract key components from the sample payload that indicate SSRF
                    ssrf_indicators_from_sample = []
                    
                    # Look for private IP patterns in the sample payload
                    for pattern in private_network_patterns:
                        if re.search(pattern, sample_payload):
                            ssrf_indicators_from_sample.append(pattern)
                    
                    # Check if our URL contains any of these indicators
                    for indicator in ssrf_indicators_from_sample:
                        if re.search(indicator, unquoted_url):
                            vulnerabilities.append({
                                "type": "A10_SSRF_Sample_Pattern_Match",
                                "details": f"URL contains pattern '{indicator}' matching known SSRF payload. Reference sample: {sample.get('description', 'N/A')}",
                                "severity": "high"
                            })
                            break
    
    # 8. Check for common SSRF bypasses
    ssrf_bypass_patterns = [
        # DNS Rebinding patterns
        r"[a-z0-9\-\.]+\.127\.0\.0\.1\.xip\.io",
        r"[a-z0-9\-\.]+\.localtest\.me",
        r"[a-z0-9\-\.]+\.nip\.io",
        r"127\.0\.0\.1\.\w+\.\w+",
        
        # URL encoding bypasses
        r"%2f127\.0\.0\.1", r"%2flocalhost",
        r"127%2e0%2e0%2e1", r"%68%74%74%70%3a%2f%2f",
        
        # Protocol bypasses
        r"http:///127\.0\.0\.1", r"http:\\/\\/127\.0\.0\.1",
        r"0://", r"http+unix://", r"\\\\localhost",
        
        # IPv6 bypasses
        r"\[::1\]", r"\[0:0:0:0:0:0:0:1\]",
        
        # Decimal/octal/hex IP representation
        r"2130706433", r"0177\.0000\.0000\.0001", r"0x7f\.0x0\.0x0\.0x1"
    ]
    
    for pattern in ssrf_bypass_patterns:
        if re.search(pattern, unquoted_url, re.IGNORECASE):
            match = re.search(pattern, unquoted_url, re.IGNORECASE).group(0)
            vulnerabilities.append({
                "type": "A10_SSRF_Bypass_Technique",
                "details": f"URL contains SSRF bypass technique: '{match}'",
                "severity": "high"
            })
            break
    
    # Deduplicate vulnerabilities by type to avoid noise
    unique_vulnerabilities = []
    seen_types = set()
    
    for vuln in vulnerabilities:
        vuln_type = vuln["type"]
        if vuln_type not in seen_types:
            unique_vulnerabilities.append(vuln)
            seen_types.add(vuln_type)
    
    return unique_vulnerabilities 