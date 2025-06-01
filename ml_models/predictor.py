import json
import os
import importlib

# Тут хранятся данные для обучения моделей
TRAINING_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'training_data')
DETECTORS_DIR = os.path.join(os.path.dirname(__file__), 'detectors')

def load_training_data(vulnerability_type):
    """Загружает примеры для конкретного типа уязвимости."""
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

# Список всех детекторов и нужных им данных
# Формат: (название_файла, название_функции, источник_данных, категория_уязвимости)
# Мы загружаем данные из файлов *_training_data.json
DETECTOR_CONFIG = [
    ("a01_broken_access_control_detector", "detect", "a01_broken_access_control", "A01_Broken_Access_Control"),
    ("a02_cryptographic_failures_detector", "detect", "a02_cryptographic_failures", "A02_Cryptographic_Failures"),
    ("a03_injection_detector", "detect", ["xss", "sqli", "rce"], "A03_Injection"), # Этот детектор использует разные наборы данных
    ("a04_insecure_design_detector", "detect", None, "A04_Insecure_Design"),
    ("a05_security_misconfiguration_detector", "detect", "a05_security_misconfiguration", "A05_Security_Misconfiguration"),
    ("a06_vulnerable_components_detector", "detect", "a06_vulnerable_components", "A06_Vulnerable_Components"),
    ("a07_identification_authentication_detector", "detect", None, "A07_Identification_Authentication_Failures"),
    ("a08_software_data_integrity_detector", "detect", "rce", "A08_Software_Data_Integrity_Failures"), # Используем данные по RCE для проверки десериализации
    ("a09_logging_monitoring_detector", "detect", None, "A09_Security_Logging_Monitoring_Failures"),
    ("a10_ssrf_detector", "detect", "ssrf", "A10_Server_Side_Request_Forgery"),
    ("lfi_detector", "detect", "lfi", "LFI"), # Проверка на локальное включение файлов
    ("rce_detector", "detect", "rce", "RCE"), # Проверка на исполнение команд
    ("csrf_detector", "detect", "csrf", "CSRF"), # Проверка на CSRF
]

def predict_vulnerabilities(site_data):
    """Проверяет сайт на наличие разных уязвимостей."""
    print(f"Analyzing {site_data.get('url', 'unknown site')} for vulnerabilities...")
    all_vulnerabilities = []
    
    loaded_samples_cache = {}

    # Запускаем наш основной детектор
    try:
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        print("ML-детектор инициализирован")
    except Exception as e:
        print(f"Ошибка при инициализации ML-детектора: {e}")
        ml_detector = None

    for module_name, func_name, data_keys, category_name in DETECTOR_CONFIG:
        try:
            # Загружаем нужный детектор
            detector_module = importlib.import_module(f".detectors.{module_name}", package="ml_models")
            detect_function = getattr(detector_module, func_name)
            
            # Подготавливаем данные для анализа
            current_samples = {}
            if data_keys:
                if isinstance(data_keys, list): # Если детектору нужны разные типы данных
                    for key in data_keys:
                        if key not in loaded_samples_cache:
                            loaded_samples_cache[key] = load_training_data(key)
                        current_samples[key] = loaded_samples_cache[key]
                else: # Если один тип данных
                    if data_keys not in loaded_samples_cache:
                        loaded_samples_cache[data_keys] = load_training_data(data_keys)
                    current_samples = loaded_samples_cache[data_keys] # Передаем список примеров

            # Запускаем детектор на проверку сайта
            # Детектор сам разберется что ему дали - словарь или список
            if current_samples or not data_keys: # Запускаем если есть данные или они не нужны
                print(f"Running detector: {module_name}...")
                findings = detect_function(site_data, current_samples if data_keys else None)
                if findings:
                    for finding in findings:
                        # Проверяем что результат правильный
                        if 'type' not in finding or 'details' not in finding:
                            print(f"Warning: Malformed finding from {module_name}: {finding}")
                            continue
                        # Можно добавить категорию в начало, если нужно
                        # if category_name and not finding['type'].startswith(category_name):
                        #    finding['type'] = f"{category_name}_{finding['type']}"
                        all_vulnerabilities.append(finding)
            else:
                print(f"Skipping detector {module_name} due to missing training data: {data_keys}")
                
            # Теперь пробуем найти уязвимости с помощью умного детектора
            if ml_detector and data_keys and not isinstance(data_keys, list):
                try:
                    ml_result = ml_detector.predict(site_data, data_keys)
                    if ml_result["prediction"] and ml_result["confidence"] > 0.7:
                        ml_finding = {
                            "type": f"{data_keys.upper()}_Detection",
                            "details": f"Обнаружены признаки {data_keys} с точностью {ml_result['confidence']:.2f}",
                            "severity": "high",
                            "ml_confidence": ml_result["confidence"]
                        }
                        all_vulnerabilities.append(ml_finding)
                        print(f"Детектор обнаружил {data_keys} с точностью {ml_result['confidence']:.2f}")
                except Exception as e:
                    print(f"Ошибка при анализе для {data_keys}: {e}")

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
        # Убираем повторы в результатах
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
    # Тестовый запуск:
    # Если нет данных - создаем тестовые
    if not os.path.exists(TRAINING_DATA_DIR):
        os.makedirs(TRAINING_DATA_DIR)
    
    dummy_site_data = {
        "url": "http://example.com/page?id=1' OR '1'='1&param=<script>alert(1)</script>",
        "content": "<html><title>Test</title><body><p>Some SQL error: unclosed quotation mark. User input: <script>alert('XSS')</script>. Loading script from http://vulnerable.com/script.js on an https page. Admin panel access without login here. jQuery-1.2.3.min.js used. CSRF token missing.</p></html>",
        "headers": {"Server": "Apache/2.2.15 (Debian)", "X-Powered-By": "PHP/5.3.3"}
    }
    
    # Создаем пустые файлы с данными для тестирования
    for _, _, data_keys, _ in DETECTOR_CONFIG:
        if data_keys:
            keys_to_check = data_keys if isinstance(data_keys, list) else [data_keys]
            for key in keys_to_check:
                if key:
                    p = os.path.join(TRAINING_DATA_DIR, f"{key}_training_data.json")
                    if not os.path.exists(p):
                        with open(p, 'w') as f:
                            json.dump({"samples": [{"html": "<script>alert(1)</script>", "is_vulnerable": True, "url": "http://example.com"}]}, f) # Простейший пример
                            
    results = predict_vulnerabilities(dummy_site_data)
    print("\n--- Analysis Complete ---")
    if results:
        for res in results:
            print(f"- Type: {res['type']}, Details: {res['details']}")
    else:
        print("No vulnerabilities found by new predictor structure.")
 