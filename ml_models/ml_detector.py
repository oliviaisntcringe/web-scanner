#!/usr/bin/env python3
import os
import joblib
import numpy as np

class MLDetector:
    """Класс для работы с ML-моделями для обнаружения уязвимостей."""
    
    def __init__(self):
        # Директория, где хранятся обученные модели
        self.models_dir = os.path.join(os.path.dirname(__file__), '..', 'ml_models', 'trained_models')
        
        # Словарь для хранения загруженных моделей
        self.models = {}
        
        # Пытаемся загрузить все доступные модели
        self._load_all_models()
    
    def _load_all_models(self):
        """Загружает все обученные модели."""
        if not os.path.exists(self.models_dir):
            print(f"Директория с моделями не существует: {self.models_dir}")
            return
        
        # Ищем все .pkl файлы в директории
        for filename in os.listdir(self.models_dir):
            if filename.endswith('_model.pkl'):
                vulnerability_type = filename.replace('_model.pkl', '')
                try:
                    model_path = os.path.join(self.models_dir, filename)
                    self.models[vulnerability_type] = joblib.load(model_path)
                    print(f"Загружена модель для {vulnerability_type}")
                except Exception as e:
                    print(f"Ошибка загрузки модели {filename}: {e}")
    
    def extract_features(self, site_data):
        """Извлекает признаки из данных сайта для ML-предсказания."""
        url = site_data.get("url", "")
        content = site_data.get("content", "")
        headers = site_data.get("headers", {})
        
        # Извлекаем базовые признаки
        features = [
            len(content) / 1000,  # Нормализованная длина контента
            len(url) / 100,       # Нормализованная длина URL
            1 if 'script' in content.lower() else 0,  # Наличие тегов script
            1 if 'admin' in url.lower() else 0,       # URL содержит admin
            len(headers),         # Количество заголовков
            len(url.split('/'))   # Глубина URL
        ]
        
        # Дополнительные признаки для конкретных типов уязвимостей
        # Инъекции (XSS, SQLi, RCE)
        injection_features = [
            1 if any(char in url for char in ["'", "\"", "<", ">", ";", "="]) else 0,  # Спец. символы в URL
            1 if any(char in content for char in ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]) else 0,  # SQL-ключевые слова
            1 if "alert(" in content else 0,  # XSS-паттерн
            1 if any(cmd in content.lower() for cmd in ["exec", "system", "shell_exec", "eval", "os."]) else 0  # RCE-паттерны
        ]
        
        # CSRF признаки
        csrf_features = [
            1 if "form" in content.lower() else 0,  # Наличие форм
            1 if "csrf" in content.lower() else 0,  # CSRF-токены
            1 if "method=\"post\"" in content.lower() or "method='post'" in content.lower() else 0  # POST-методы
        ]
        
        # A01 Broken Access Control признаки
        bac_features = [
            1 if any(segment in url.lower() for segment in ["admin", "config", "settings", "profile"]) else 0,  # Админ-пути
            1 if "id=" in url else 0,  # Параметры ID
            1 if "auth" in content.lower() or "login" in content.lower() else 0  # Авторизация
        ]
        
        # Объединяем все признаки
        all_features = features + injection_features + csrf_features + bac_features
        
        return np.array(all_features)
    
    def predict(self, site_data, vulnerability_type):
        """Предсказывает, содержит ли сайт указанную уязвимость."""
        if vulnerability_type not in self.models:
            return {
                "prediction": False,
                "confidence": 0.0,
                "message": f"Модель для {vulnerability_type} не найдена"
            }
        
        # Извлекаем признаки
        features = self.extract_features(site_data)
        
        # Получаем модель
        model = self.models[vulnerability_type]
        
        try:
            # Предсказываем класс (0 - безопасно, 1 - уязвимо)
            prediction = model.predict([features])[0]
            
            # Получаем вероятность для положительного класса
            confidence = 0.0
            if hasattr(model, "predict_proba"):
                probas = model.predict_proba([features])[0]
                confidence = probas[1] if len(probas) > 1 else 0.0
            
            return {
                "prediction": bool(prediction),
                "confidence": float(confidence),
                "message": f"Уязвимость {vulnerability_type} {'обнаружена' if prediction else 'не обнаружена'} с уверенностью {confidence:.2f}"
            }
        except Exception as e:
            return {
                "prediction": False,
                "confidence": 0.0,
                "message": f"Ошибка при предсказании: {e}"
            }
    
    def predict_all(self, site_data):
        """Проверяет сайт на все доступные типы уязвимостей."""
        results = {}
        
        for vulnerability_type in self.models:
            results[vulnerability_type] = self.predict(site_data, vulnerability_type)
        
        return results

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