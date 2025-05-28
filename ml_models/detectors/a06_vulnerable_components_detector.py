# Detector for A06:2021 - Vulnerable and Outdated Components
import re

# Pre-compiled regex for common library version extraction from script tags
# e.g. jquery-1.2.3.min.js, angular.1.5.0.js, bootstrap.bundle.3.0.0.js
LIB_VERSION_REGEX = r'([a-zA-Z0-9._-]+?)[.-](\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9._-]+)?)(?:\.min|\.bundle)?\.(?:js|css)'

# Define known vulnerable versions (simplified, a real system would use a DB)
# Format: lib_name_lower: [(major, minor, patch_if_specific_else_-1), ...]
# -1 means any version below the next entry or if it's the only one, any below a known good one.
KNOWN_VULNERABLE_VERSIONS = {
    "jquery": [(3,5,0)], # Versions < 3.5.0
    "bootstrap": [(4,0,0)], # Versions < 4.0.0
    "angular": [(1,7,0)], # AngularJS versions < 1.7.0 (AngularJS is EOL, so most are bad)
    "react": [(16,8,0)], # Example: React versions < 16.8 (hooks) might indicate older practices
}

KNOWN_SERVER_VULNS = {
    "apache": [(2,4,53)], # Apache < 2.4.53
    "nginx": [(1,21,0)], # Nginx < 1.21.0
}

def parse_version(version_str):
    """Parses a version string (e.g., '1.2.3', '1.2') into a tuple of integers."""
    try:
        return tuple(map(int, re.findall(r'\d+', version_str)))
    except:
        return None

def is_version_less_than(parsed_v1, parsed_v2_target):
    """Compares two parsed version tuples. True if v1 < v2_target."""
    if not parsed_v1 or not parsed_v2_target: return False
    for i in range(min(len(parsed_v1), len(parsed_v2_target))):
        if parsed_v1[i] < parsed_v2_target[i]:
            return True
        if parsed_v1[i] > parsed_v2_target[i]:
            return False
    # If one is a prefix of other, e.g., 1.2 vs 1.2.3. Treat 1.2 as less than 1.2.3.
    return len(parsed_v1) < len(parsed_v2_target)

def detect(site_data, samples=None):
    """Detects Vulnerable and Outdated Components."""
    vulnerabilities = []
    content = site_data.get("content", "")
    headers = site_data.get("headers", {})
    
    # Проверяем, есть ли у нас ML-модель для Vulnerable Components
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на Vulnerable Components с помощью ML
        ml_result = ml_detector.predict(site_data, "a06_vulnerable_components")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "A06_Vulnerable_Components_ML",
                "details": f"ML-модель обнаружила признаки уязвимых компонентов с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для A06 Vulnerable Components: {e}")

    # 1. Direct detection of component versions from content (scripts, links)
    # Consolidate jQuery, Bootstrap, and other JS/CSS lib detection
    found_scripts_and_links = re.finditer(LIB_VERSION_REGEX, content, re.IGNORECASE)
    for match in found_scripts_and_links:
        lib_name_guess = match.group(1).lower().replace('-', '').replace('.', '') # Normalize e.g. jquery-ui to jqueryui
        version_str = match.group(2)
        parsed_version = parse_version(version_str)
        if not parsed_version: continue

        for known_lib_name, target_versions_list in KNOWN_VULNERABLE_VERSIONS.items():
            if known_lib_name in lib_name_guess: # Simple substring match for lib name
                for target_v_tuple in target_versions_list:
                    if is_version_less_than(parsed_version, target_v_tuple):
                        vulnerabilities.append({
                            "type": f"A06_Vulnerable_Component_{known_lib_name.capitalize()}",
                            "details": f"Potentially outdated/vulnerable {known_lib_name} version {version_str} found (heuristic: < {'.'.join(map(str,target_v_tuple))})."
                        })
                        break # Found a rule for this lib, no need to check other target versions for same lib
                break # Matched lib_name_guess
    
    # 2. Detect specific server versions from headers
    server_header = headers.get("Server", "") # Case-sensitive lookup as per RFC, but value compared case-insensitively
    if server_header:
        server_header_lower = server_header.lower()
        for server_name, target_versions_list in KNOWN_SERVER_VULNS.items():
            match = re.search(rf'{server_name}/(\d+\.\d+(?:\.\d+)?)', server_header_lower)
            if match:
                version_str = match.group(1)
                parsed_version = parse_version(version_str)
                if not parsed_version: continue
                for target_v_tuple in target_versions_list:
                    if is_version_less_than(parsed_version, target_v_tuple):
                        vulnerabilities.append({
                            "type": f"A06_Vulnerable_Component_{server_name.capitalize()}_Server",
                            "details": f"Potentially outdated/vulnerable {server_name.capitalize()} version {version_str} found in Server header: '{server_header}' (heuristic: < {'.'.join(map(str,target_v_tuple))})."
                        })
                        break
                break

    # 3. Leverage training samples if provided
    # The samples for A06 have 'raw_payload' like "Uses vulnerable jquery version 1.2.3"
    if samples:
        for sample in samples:
            if sample.get('is_vulnerable') and 'raw_payload' in sample:
                raw_desc = sample['raw_payload'] # e.g., "Uses vulnerable jquery version 1.2.3"
                # Try to parse library and version from this description
                m = re.search(r'(?:uses|using)\s+(?:vulnerable|outdated)?\s*([a-zA-Z0-9._-]+)\s+version\s*(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9._-]+)?)', raw_desc, re.IGNORECASE)
                if m:
                    lib_name_from_sample = m.group(1).lower()
                    version_from_sample = m.group(2)
                    
                    # Check if this specific vulnerable lib/version is in site_data content
                    # This is a more targeted check based on the training data pattern
                    # We need to be careful with regex construction if version_from_sample contains special chars
                    escaped_lib_name = re.escape(lib_name_from_sample)
                    escaped_version = re.escape(version_from_sample)
                    
                    # Search for patterns like: jquery-1.2.3.js, jquery.1.2.3.min.js, etc.
                    # This regex is a bit broad to catch variations.
                    pattern_to_find = rf'{escaped_lib_name}[.-]{escaped_version}(?:\.min|\.bundle)?\.(?:js|css)'
                    if re.search(pattern_to_find, content, re.IGNORECASE):
                        # Avoid duplicate reporting if already found by general checks above
                        # This is a simple way to check for duplicates:
                        already_reported = False
                        for v in vulnerabilities:
                            if lib_name_from_sample in v['details'].lower() and version_from_sample in v['details']:
                                already_reported = True
                                break
                        if not already_reported:
                            vulnerabilities.append({
                                "type": f"A06_Vulnerable_Component_{lib_name_from_sample.capitalize()}_Sample_Match",
                                "details": f"Vulnerable component {lib_name_from_sample} version {version_from_sample} (identified from training sample pattern) found in content."
                            })
    return vulnerabilities 