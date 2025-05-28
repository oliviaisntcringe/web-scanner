#!/usr/bin/env python3
import json
from ml_models.ml_detector import MLDetector
from ml_models.predictor import predict_vulnerabilities

def test_ml_detector():
    """Тестирует ML-детектор на примерах для разных типов уязвимостей"""
    detector = MLDetector()
    
    print("\n=== Тестирование ML-детектора ===")
    print(f"Загружено {len(detector.models)} моделей")
    
    # Список тестовых примеров для разных типов уязвимостей
    test_cases = {
        # XSS уязвимость
        "xss": {
            "url": "http://example.com/search?q=<script>alert(1)</script>",
            "content": "<html><body>Результаты поиска для: <script>alert(1)</script></body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # SQL инъекция
        "sqli": {
            "url": "http://example.com/user?id=1' OR '1'='1",
            "content": "<html><body>Ошибка базы данных: Unclosed quotation mark after the character string</body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # RCE уязвимость
        "rce": {
            "url": "http://example.com/ping?host=127.0.0.1; cat /etc/passwd",
            "content": "<html><body>Результаты пинга: PING 127.0.0.1 (127.0.0.1): 56 data bytes...</body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # CSRF уязвимость
        "csrf": {
            "url": "http://example.com/transfer",
            "content": "<html><body><form action='/transfer' method='POST'><input name='amount' value='1000'><input name='to' value='attacker'><button>Transfer</button></form></body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # LFI уязвимость
        "lfi": {
            "url": "http://example.com/page.php?file=../../../etc/passwd",
            "content": "<html><body>root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n...</body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # SSRF уязвимость
        "ssrf": {
            "url": "http://example.com/proxy?url=http://169.254.169.254/latest/meta-data/",
            "content": "<html><body>ami-id\nami-launch-index\nami-manifest-path\n...</body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # A01 Broken Access Control
        "a01_broken_access_control": {
            "url": "http://example.com/admin/users",
            "content": "<html><body><h1>Admin Panel</h1><table><tr><th>User</th><th>Password Hash</th></tr>...</table></body></html>",
            "headers": {"Content-Type": "text/html", "Authorization": "Basic dXNlcjpwYXNz"}
        },
        
        # A02 Cryptographic Failures
        "a02_cryptographic_failures": {
            "url": "http://example.com/login",
            "content": "<html><body><form action='/login' method='POST'><input type='text' name='username'><input type='password' name='password'></form></body></html>",
            "headers": {"Content-Type": "text/html", "X-Simulated-SSL-Cipher": "TLS_RSA_WITH_RC4_128_SHA"}
        },
        
        # A04 Insecure Design
        "a04_insecure_design": {
            "url": "http://example.com/debug?mode=true",
            "content": "<html><body><!-- TODO: remove before production - credentials: admin/admin123 -->\nDebug Mode: ON</body></html>",
            "headers": {"Content-Type": "text/html", "X-Debug-Token": "f8d7s9f87dsf"}
        },
        
        # A05 Security Misconfiguration
        "a05_security_misconfiguration": {
            "url": "http://example.com/",
            "content": "<html><body><!-- DEBUG MODE ENABLED -->\nTraceback (most recent call last):\nFile \"app.py\", line 42</body></html>",
            "headers": {"Content-Type": "text/html", "Server": "Apache/2.4.29 (Ubuntu)"}
        },
        
        # A06 Vulnerable Components
        "a06_vulnerable_components": {
            "url": "http://example.com/",
            "content": "<html><head><script src='jquery-1.8.2.min.js'></script></head><body>Hello</body></html>",
            "headers": {"Content-Type": "text/html", "Server": "Apache/2.2.31 (Unix)"}
        },
        
        # A07 Identification and Authentication Failures
        "a07_identification_authentication": {
            "url": "http://example.com/login?sessionid=123456",
            "content": "<html><body><form action='/login' method='POST'><input type='text' name='username' value='admin'><input type='password' name='password'></form></body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # A08 Software and Data Integrity Failures
        "a08_software_data_integrity": {
            "url": "http://example.com/",
            "content": "<html><head><script src='https://cdn.example.com/jquery.min.js'></script></head><body>Download our update from http://untrusted-mirror.com/update.zip</body></html>",
            "headers": {"Content-Type": "text/html"}
        },
        
        # A09 Security Logging and Monitoring Failures
        "a09_logging_monitoring": {
            "url": "http://example.com/",
            "content": "<html><body>Error: Failed to connect to database: uncaught exception at line 42</body></html>",
            "headers": {"Content-Type": "text/html"}
        }
    }
    
    # Тестируем каждую модель
    for vuln_type, test_data in test_cases.items():
        print(f"\n--- Тестирование модели {vuln_type} ---")
        try:
            result = detector.predict(test_data, vuln_type)
            print(f"Предсказание: {'Уязвимо' if result['prediction'] else 'Не уязвимо'}")
            print(f"Уверенность: {result['confidence']:.2f}")
        except Exception as e:
            print(f"Ошибка при тестировании модели {vuln_type}: {e}")

    # Также тестируем интегрированную функцию predictor
    print("\n=== Тестирование интегрированного предиктора ===")
    # Выбираем один пример для полного сканирования всеми детекторами
    full_scan_example = test_cases["xss"]
    
    print("Полное сканирование на все уязвимости...")
    vulnerabilities = predict_vulnerabilities(full_scan_example)
    
    print(f"Обнаружено {len(vulnerabilities)} уязвимостей:")
    for i, vuln in enumerate(vulnerabilities, 1):
        severity = vuln.get("severity", "medium")
        print(f"{i}. [{severity.upper()}] {vuln['type']}: {vuln['details']}")

if __name__ == "__main__":
    test_ml_detector() 