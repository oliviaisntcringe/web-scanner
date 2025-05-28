import json
import os
import importlib

# Path to the directory where generator_data.py saves its output
TRAINING_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'training_data')
DETECTORS_DIR = os.path.join(os.path.dirname(__file__), 'detectors')

def load_training_data(vulnerability_type):
    """Loads training data for a specific vulnerability type."""
    file_path = os.path.join(TRAINING_DATA_DIR, f"{vulnerability_type}_training_data.json")
    if not os.path.exists(file_path):
        print(f"Warning: Training data file not found: {file_path}")
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        print(f"Successfully loaded {len(data.get('samples', []))} samples for {vulnerability_type} from {file_path}")
        return data.get('samples', [])
    except Exception as e:
        print(f"Error loading training data for {vulnerability_type} from {file_path}: {e}")
        return None

# List of detector modules and their corresponding data files (if any)
# Format: (module_name, function_name, data_key_or_None, owasp_category_or_None)
# data_key is used to load from *_training_data.json
DETECTOR_CONFIG = [
    ("a01_broken_access_control_detector", "detect", "a01_broken_access_control", "A01_Broken_Access_Control"),
    ("a02_cryptographic_failures_detector", "detect", "a02_cryptographic_failures", "A02_Cryptographic_Failures"),
    ("a03_injection_detector", "detect", ["xss", "sqli", "rce"], "A03_Injection"), # Takes multiple data types
    ("a04_insecure_design_detector", "detect", None, "A04_Insecure_Design"),
    ("a05_security_misconfiguration_detector", "detect", "a05_security_misconfiguration", "A05_Security_Misconfiguration"),
    ("a06_vulnerable_components_detector", "detect", "a06_vulnerable_components", "A06_Vulnerable_Components"),
    ("a07_identification_authentication_detector", "detect", None, "A07_Identification_Authentication_Failures"),
    ("a08_software_data_integrity_detector", "detect", "rce", "A08_Software_Data_Integrity_Failures"), # RCE data for Deserialization
    ("a09_logging_monitoring_detector", "detect", None, "A09_Security_Logging_Monitoring_Failures"),
    ("a10_ssrf_detector", "detect", "ssrf", "A10_Server_Side_Request_Forgery"),
    ("lfi_detector", "detect", "lfi", "LFI"), # Standalone LFI
    ("rce_detector", "detect", "rce", "RCE"), # Standalone RCE (Command Injection)
    ("csrf_detector", "detect", "csrf", "CSRF"), # CSRF
]

def predict_vulnerabilities(site_data):
    """Analyzes site data by calling various vulnerability detectors."""
    print(f"Analyzing {site_data.get('url', 'unknown site')} for vulnerabilities...")
    all_vulnerabilities = []
    
    loaded_samples_cache = {}

    # Инициализируем ML-детектор для использования обученных моделей
    try:
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        print("ML-детектор инициализирован")
    except Exception as e:
        print(f"Ошибка при инициализации ML-детектора: {e}")
        ml_detector = None

    for module_name, func_name, data_keys, category_name in DETECTOR_CONFIG:
        try:
            # Dynamically import the detector module
            detector_module = importlib.import_module(f".detectors.{module_name}", package="ml_models")
            detect_function = getattr(detector_module, func_name)
            
            # Prepare samples for the detector
            current_samples = {}
            if data_keys:
                if isinstance(data_keys, list): # Multiple data types for one detector
                    for key in data_keys:
                        if key not in loaded_samples_cache:
                            loaded_samples_cache[key] = load_training_data(key)
                        current_samples[key] = loaded_samples_cache[key]
                else: # Single data type
                    if data_keys not in loaded_samples_cache:
                        loaded_samples_cache[data_keys] = load_training_data(data_keys)
                    current_samples = loaded_samples_cache[data_keys] # Pass the list of samples directly

            # Call the detector function
            # The detector function should handle if samples is a dict or a list
            if current_samples or not data_keys: # Proceed if samples are loaded or not needed
                print(f"Running detector: {module_name}...")
                findings = detect_function(site_data, current_samples if data_keys else None)
                if findings:
                    for finding in findings:
                        # Ensure each finding has a 'type' and 'details'
                        if 'type' not in finding or 'details' not in finding:
                            print(f"Warning: Malformed finding from {module_name}: {finding}")
                            continue
                        # Optionally, prepend the main category if not already specific
                        # if category_name and not finding['type'].startswith(category_name):
                        #    finding['type'] = f"{category_name}_{finding['type']}"
                        all_vulnerabilities.append(finding)
            else:
                print(f"Skipping detector {module_name} due to missing training data: {data_keys}")
                
            # Если ML-детектор доступен, проверяем с его помощью
            if ml_detector and data_keys and not isinstance(data_keys, list):
                try:
                    ml_result = ml_detector.predict(site_data, data_keys)
                    if ml_result["prediction"] and ml_result["confidence"] > 0.7:
                        ml_finding = {
                            "type": f"{data_keys.upper()}_ML_Detection",
                            "details": f"ML-модель обнаружила признаки {data_keys} с уверенностью {ml_result['confidence']:.2f}",
                            "severity": "high",
                            "ml_confidence": ml_result["confidence"]
                        }
                        all_vulnerabilities.append(ml_finding)
                        print(f"ML-детектор обнаружил {data_keys} с уверенностью {ml_result['confidence']:.2f}")
                except Exception as e:
                    print(f"Ошибка при ML-анализе для {data_keys}: {e}")

        except ImportError as e:
            print(f"Error importing detector {module_name}: {e}")
        except AttributeError as e:
            print(f"Error: Function {func_name} not found in {module_name}: {e}")
        except Exception as e:
            print(f"Error running detector {module_name}: {e}")

    if not all_vulnerabilities:
        print("No specific vulnerabilities identified by any detector.")
        return []
    else:
        # Deduplicate findings
        unique_vulnerabilities = []
        seen = set()
        for vuln in all_vulnerabilities:
            vuln_tuple = (vuln['type'], vuln['details'])
            if vuln_tuple not in seen:
                unique_vulnerabilities.append(vuln)
                seen.add(vuln_tuple)
        
        print(f"Found {len(unique_vulnerabilities)} unique potential vulnerabilities.")
        return unique_vulnerabilities

if __name__ == '__main__':
    # Example usage:
    # Create dummy training data files for testing if generator_data.py hasn't run
    if not os.path.exists(TRAINING_DATA_DIR):
        os.makedirs(TRAINING_DATA_DIR)
    
    dummy_site_data = {
        "url": "http://example.com/page?id=1' OR '1'='1&param=<script>alert(1)</script>",
        "content": "<html><title>Test</title><body><p>Some SQL error: unclosed quotation mark. User input: <script>alert('XSS')</script>. Loading script from http://vulnerable.com/script.js on an https page. Admin panel access without login here. jQuery-1.2.3.min.js used. CSRF token missing.</p></html>",
        "headers": {"Server": "Apache/2.2.15 (Debian)", "X-Powered-By": "PHP/5.3.3"}
    }
    
    # Create dummy training files if they don't exist for the test to run
    for _, _, data_keys, _ in DETECTOR_CONFIG:
        if data_keys:
            keys_to_check = data_keys if isinstance(data_keys, list) else [data_keys]
            for key in keys_to_check:
                if key:
                    p = os.path.join(TRAINING_DATA_DIR, f"{key}_training_data.json")
                    if not os.path.exists(p):
                        with open(p, 'w') as f:
                            json.dump({"samples": [{"html": "<script>alert(1)</script>", "is_vulnerable": True, "url": "http://example.com"}]}, f) # Minimal sample
                            
    results = predict_vulnerabilities(dummy_site_data)
    print("\n--- Analysis Complete ---")
    if results:
        for res in results:
            print(f"- Type: {res['type']}, Details: {res['details']}")
    else:
        print("No vulnerabilities found by new predictor structure.")
 