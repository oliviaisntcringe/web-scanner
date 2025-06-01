#!/usr/bin/env python3
import os
import joblib
import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
import re

# Путь к папке с сохраненными моделями
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'trained_models')

class MLDetector:
    """
    Детектор уязвимостей, использующий разные подходы для разных типов уязвимостей.
    """
    
    def __init__(self):
        """
        Инициализирует детектор и загружает обученные модели.
        """
        self.models = {}
        self.vectorizers = {}
        self.load_models()
        
    def load_models(self):
        """
        Загружает предварительно обученные модели и векторизаторы.
        """
        # Названия уязвимостей, для которых у нас есть модели
        vulnerability_types = [
            'xss', 'sqli', 'lfi', 'rce', 'csrf', 'ssrf',
            'a01_broken_access_control', 'a02_cryptographic_failures', 
            'a05_security_misconfiguration', 'a06_vulnerable_components'
        ]
        
        for vuln_type in vulnerability_types:
            # Пути к сохраненным файлам
            model_path = os.path.join(MODELS_DIR, f"{vuln_type}_model.pkl")
            vectorizer_path = os.path.join(MODELS_DIR, f"{vuln_type}_vectorizer.pkl")
            
            # Загружаем модель и векторизатор, если файлы существуют
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                try:
                    with open(model_path, 'rb') as f:
                        self.models[vuln_type] = pickle.load(f)
                    with open(vectorizer_path, 'rb') as f:
                        self.vectorizers[vuln_type] = pickle.load(f)
                    print(f"Модель и векторизатор для {vuln_type} успешно загружены")
                except Exception as e:
                    print(f"Ошибка при загрузке модели для {vuln_type}: {e}")
            else:
                print(f"Модель для {vuln_type} не найдена в {MODELS_DIR}")
    
    def extract_features(self, site_data, vuln_type):
        """
        Извлекает признаки из данных сайта для определенного типа уязвимости.
        
        Разные типы уязвимостей требуют разных признаков.
        """
        # Базовые признаки, которые мы можем использовать для любого типа уязвимости
        features = {
            'has_input_forms': False,
            'has_json_response': False,
            'has_js_code': False,
            'has_file_uploads': False,
            'has_includes': False,
            'has_redirects': False,
            'has_serialized_data': False,
            'uses_cookies': False,
            'content_length': 0,
        }
        
        # Получаем содержимое страницы и заголовки
        content = site_data.get('content', '')
        url = site_data.get('url', '')
        headers = site_data.get('headers', {})
        
        # Заполняем базовые признаки на основе содержимого и заголовков
        features['content_length'] = len(content)
        features['has_input_forms'] = '<form' in content.lower() or '<input' in content.lower()
        features['has_json_response'] = 'application/json' in headers.get('Content-Type', '').lower() if headers else False
        features['has_js_code'] = '<script' in content.lower() or '.js' in content.lower()
        features['has_file_uploads'] = 'type="file"' in content.lower() or 'multipart/form-data' in content.lower()
        features['uses_cookies'] = 'cookie' in str(headers).lower() if headers else False
        
        # Более специфичные признаки для разных типов уязвимостей
        if vuln_type == 'xss':
            # Для XSS важны места, где пользовательский ввод может отображаться
            features['has_echoed_params'] = bool(re.search(r'value=["\']\s*\w+\s*["\']', content))
            features['has_dom_manipulation'] = 'document.write' in content or 'innerHTML' in content
        
        elif vuln_type == 'sqli':
            # Для SQL-инъекций ищем признаки работы с базой данных
            features['has_sql_errors'] = bool(re.search(r'sql|mysql|sqlite|oracle|db|database', content.lower()))
            features['has_query_params'] = '?' in url and ('=' in url.split('?')[1] if '?' in url else False)
        
        elif vuln_type == 'lfi':
            # Для LFI ищем признаки включения файлов
            features['has_includes'] = bool(re.search(r'include|require|include_once|require_once', content.lower()))
            features['has_file_params'] = bool(re.search(r'file=|path=|dir=', url.lower()))
        
        elif vuln_type == 'rce':
            # Для RCE ищем признаки выполнения команд
            features['has_shell_functions'] = bool(re.search(r'exec|system|passthru|shell_exec|popen', content.lower()))
            features['has_eval'] = 'eval(' in content
        
        # Текстовое представление для векторизатора
        text_features = f"{url} {content}"
        
        return features, text_features
    
    def predict(self, site_data, vuln_type):
        """
        Предсказывает наличие уязвимости определенного типа.
        
        Args:
            site_data: Словарь с данными о сайте (URL, контент, заголовки)
            vuln_type: Тип уязвимости для проверки
            
        Returns:
            Словарь с результатами предсказания и уверенностью
        """
        # Проверяем, есть ли у нас модель для этого типа уязвимости
        if vuln_type not in self.models or vuln_type not in self.vectorizers:
            print(f"Нет обученной модели для {vuln_type}")
            return {"prediction": False, "confidence": 0.0}
        
        try:
            # Извлекаем признаки из данных сайта
            features, text_features = self.extract_features(site_data, vuln_type)
            
            # Преобразуем текстовые признаки в числовые с помощью TF-IDF
            text_features_vector = self.vectorizers[vuln_type].transform([text_features])
            
            # Получаем предсказание от модели
            prediction_prob = self.models[vuln_type].predict_proba(text_features_vector)
            
            # Вероятность того, что сайт уязвим
            confidence = prediction_prob[0][1] if prediction_prob.shape[1] > 1 else prediction_prob[0][0]
            
            # Класс уязвимости (True/False)
            prediction = confidence > 0.5
            
            return {
                "prediction": bool(prediction),
                "confidence": float(confidence)
            }
            
        except Exception as e:
            print(f"Ошибка при предсказании для {vuln_type}: {e}")
            return {"prediction": False, "confidence": 0.0}

# Пример использования
if __name__ == "__main__":
    detector = MLDetector()
    
    test_site = {
        "url": "http://example.com/admin?id=1",
        "content": "<html><body><form method='post'><input type='text' name='username'><input type='password' name='password'><input type='submit'></form></body></html>",
        "headers": {"Server": "Apache/2.2.15", "X-Powered-By": "PHP/5.3.3"}
    }
    
    results = detector.predict_all(test_site)
    
    print("\n=== Результаты ML-анализа ===")
    for vuln_type, result in results.items():
        if result["prediction"]:
            print(f"✗ {vuln_type}: {result['message']} (Уверенность: {result['confidence']:.2f})")
        else:
            print(f"✓ {vuln_type}: {result['message']}") 