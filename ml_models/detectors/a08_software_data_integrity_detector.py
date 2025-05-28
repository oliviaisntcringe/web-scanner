# Detector for A08:2021 - Software and Data Integrity Failures
import re
import random

def detect(site_data, samples=None):
    """Detects Software and Data Integrity Failures."""
    # 'samples' here are RCE samples as per DETECTOR_CONFIG, used as a proxy for deserialization
    vulnerabilities = []
    content = site_data.get("content", "")
    url = site_data.get("url", "")
    # headers = site_data.get("headers", {}) # Not used currently, can be added if needed
    
    # Проверяем, есть ли у нас ML-модель для Software and Data Integrity Failures
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Software and Data Integrity Failures с помощью ML
        ml_result = ml_detector.predict(site_data, "a08_software_data_integrity")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A08_Software_Data_Integrity_ML",
                "details": f"ML-модель обнаружила признаки проблем целостности ПО и данных с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A08 Software and Data Integrity Failures: {e}")

    # Check for Subresource Integrity (SRI) missing on external scripts/styles
    # Regex for <script src="..."> or <link href="...">
    # It captures the quote type and ensures it matches, then captures the URL.
    external_resource_pattern = r'<(?:script|link)[^>]+(?:src|href)\s*=\s*(?P<quote>[\'"])?(?P<url>https?://[^\s>]+)(?P=quote)?[^>]*>'
    for match in re.finditer(external_resource_pattern, content, re.IGNORECASE):
        resource_tag = match.group(0)
        resource_url = match.group("url")
        
        parsed_site_url = re.match(r'(https?://[^/]+)', url)
        site_domain = parsed_site_url.group(1) if parsed_site_url else None
        
        is_external = True
        if site_domain and resource_url.startswith(site_domain):
            is_external = False
        elif not resource_url.startswith("http"):
            is_external = False
        
        if is_external and 'integrity=' not in resource_tag.lower():
            vulnerabilities.append({
                "type": "A08_Software_Data_Integrity_Missing_SRI",
                "details": f"External resource {resource_url} loaded without Subresource Integrity (SRI)."
            })

    # Insecure Deserialization (very speculative, using RCE samples as a proxy)
    if samples: # samples are RCE data
        # Keywords that might appear in error messages or debug output related to deserialization libraries
        # or in payloads that might lead to RCE via deserialization.
        insecure_deserial_keywords = ["gadgetchain", "phpggc", "ysoserial", "java.io.ObjectInputStream", "pickle.loads"]
        content_lower = content.lower()
        found_deserial_hint = False
        for keyword in insecure_deserial_keywords:
            if keyword.lower() in content_lower:
                for sample in random.sample(samples, min(len(samples), 3)):
                    # If the keyword is found in a known vulnerable RCE sample (very loose connection)
                    if sample.get("is_vulnerable") and keyword.lower() in sample.get("html", "").lower():
                        found_deserial_hint = True
                        break
                if found_deserial_hint: break
        if found_deserial_hint:
             vulnerabilities.append({
                 "type": "A08_Software_Data_Integrity_Deserialization_Hint", 
                 "details": "Found keywords/patterns potentially related to insecure deserialization (highly speculative, based on RCE data and content)."
             })
    
    # Check for software updates mentioned with unverified sources (highly contextual and hard to automate)
    # Example: "Download our update from http://untrusted-mirror.com/update.zip"
    # Corrected update_pattern regex and ensured it's properly quoted
    update_pattern = r"(?:download|update|install|get)[^<]+(?:from|at)[^<]+http://[^\s'\"<>]+$"
    # Added $ to anchor the pattern, assuming the URL is the last part of such a string pattern.
    # This might need adjustment based on actual content where such patterns are found.
    # Using double quotes for the raw string to avoid issues with internal single quotes.
    search_results = re.findall(update_pattern, content, re.IGNORECASE)
    if search_results:
        for found_text in search_results: # Iterate if multiple matches, though one is enough for a finding
            vulnerabilities.append({
                "type": "A08_Software_Data_Integrity_Untrusted_Update_Source",
                "details": f"Potential mention of software update from an HTTP source: ...{found_text[-50:]}..."
            })
            break # Report first finding

    return vulnerabilities 