# Detector for A09:2021 - Security Logging and Monitoring Failures
import re

def detect(site_data, samples=None):
    """Detects Security Logging and Monitoring Failures."""
    # samples is None for this detector
    vulnerabilities = []
    content_lower = site_data.get("content", "").lower()
    # headers = site_data.get("headers", {}) # Not directly used yet, but could be for checking error headers
    
    # Проверяем, есть ли у нас ML-модель для Security Logging and Monitoring Failures
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Security Logging and Monitoring Failures с помощью ML
        ml_result = ml_detector.predict(site_data, "a09_logging_monitoring")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A09_Logging_Monitoring_ML",
                "details": f"ML-модель обнаружила признаки проблем безопасности логирования/мониторинга с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A09 Security Logging and Monitoring Failures: {e}")

    # Check for verbose error messages that might indicate poor error handling and logging
    verbose_error_patterns = [
        r"stack trace:", r"exception in thread", r"uncaught exception", 
        r"ORA-[0-9]{5}", # Oracle errors
        r"mysql_fetch_array\(\) expects parameter", r"mysql_connect\(\)[:\s]", r"pg_query\(\) expects parameter", r"Warning: pg_connect\(\)[:\s]", # PHP DB errors
        r"Call to undefined function", r"Notice: Undefined variable", r"Warning: include\([\w\.\-/]+\)",
        r"Microsoft OLE DB Provider for SQL Server error", r"\[ODBC SQL Server Driver\]",
        r"java\.lang\.NullPointerException", r"javax\.servlet\.ServletException",
        r"Traceback \(most recent call last\):", # Python traceback
        # r"An error has occurred.", # Too generic, might cause too many FPs
        # r"DEBUG", # Too generic, might be part of normal text
        r"failed to open stream", r"No such file or directory"
    ]
    for pattern_str in verbose_error_patterns:
        try:
            if re.search(pattern_str, content_lower, re.IGNORECASE):
                # Try to get a small snippet around the found pattern
                match = re.search(pattern_str, content_lower, re.IGNORECASE)
                if match:
                    start, end = match.span()
                    snippet_start = max(0, start - 30)
                    snippet_end = min(len(content_lower), end + 30)
                    snippet = content_lower[snippet_start:snippet_end].replace("\n", " ")
                    vulnerabilities.append({
                        "type": "A09_Logging_Monitoring_Verbose_Error", 
                        "details": f"Verbose error message found in content (matches '{pattern_str}'): ...{snippet}..."
                    })
                    # Consider breaking after the first type of verbose error to avoid too many similar findings,
                    # or collect all and deduplicate/summarize later.
                    # For now, let it find all distinct patterns.
        except re.error as e:
            print(f"Regex error in A09 detector for pattern '{pattern_str}': {e}")
            continue

    # Check for missing common security headers (can be an indicator of lack of security visibility/monitoring)
    # This overlaps a bit with Misconfig, but focusing on headers that aid in incident response/analysis
    # common_security_headers_to_check = {
    #     "Content-Security-Policy": False,
    #     "Strict-Transport-Security": False, # If site is HTTPS
    #     "X-Content-Type-Options": False,
    #     "X-Frame-Options": False,
    # }
    # if site_data.get("url","").startswith("https://"):
    #     for header_name, found in common_security_headers_to_check.items():
    #         if header_name.lower() not in (h.lower() for h in headers.keys()):
    #             vulnerabilities.append({"type": "A09_Logging_Monitoring_Missing_Security_Header", "details": f"Security header '{header_name}' is missing."})
    # This part is commented out as it strongly overlaps A05 and might be better there or handled separately.

    return vulnerabilities 