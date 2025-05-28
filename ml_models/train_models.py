#!/usr/bin/env python3
import os
import json
import pickle
import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

# Директории для данных и моделей
TRAINING_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'training_data')
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'ml_models', 'trained_models')

# Создаем директорию для моделей, если она не существует
if not os.path.exists(MODELS_DIR):
    os.makedirs(MODELS_DIR)

def load_training_data(vulnerability_type):
    """Загружает тренировочные данные для определенного типа уязвимости."""
    file_path = os.path.join(TRAINING_DATA_DIR, f"{vulnerability_type}_training_data.json")
    if not os.path.exists(file_path):
        print(f"Предупреждение: Файл с тренировочными данными не найден: {file_path}")
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        samples = data.get('samples', [])
        print(f"Успешно загружено {len(samples)} примеров для {vulnerability_type}")
        return samples
    except Exception as e:
        print(f"Ошибка загрузки тренировочных данных для {vulnerability_type}: {e}")
        return None

def extract_features_and_labels(samples, vulnerability_type):
    """Извлекает признаки и метки из тренировочных данных."""
    if not samples:
        return None, None
    
    features = []
    labels = []
    
    for sample in samples:
        # Проверяем, что образец имеет правильную структуру
        if 'is_vulnerable' not in sample:
            continue
        
        # Если features уже есть в образце, используем их
        if 'features' in sample and isinstance(sample['features'], list) and len(sample['features']) >= 6:
            feature_vector = sample['features']
        else:
            # Иначе создаем векторы признаков из html и url
            html = sample.get('html', '')
            url = sample.get('url', '')
            headers = sample.get('headers', {})
            raw_payload = sample.get('raw_payload', '')
            
            # Базовые признаки для всех типов уязвимостей
            base_features = [
                len(html) / 1000,  # Нормализованная длина HTML
                len(url) / 100,    # Нормализованная длина URL
                1 if 'script' in html.lower() else 0,  # Наличие тегов script
                1 if 'admin' in url.lower() else 0,    # URL содержит admin
                len(headers),      # Количество заголовков
                len(url.split('/')) # Глубина URL
            ]
            
            # Специализированные признаки по типу уязвимости
            specialized_features = []
            
            if vulnerability_type in ['xss', 'sqli', 'rce']:
                # Признаки для инъекций
                specialized_features = [
                    1 if any(char in url for char in ["'", "\"", "<", ">", ";", "="]) else 0,  # Спец. символы в URL
                    1 if any(char in html for char in ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]) else 0,  # SQL-ключевые слова
                    1 if "alert(" in html else 0,  # XSS-паттерн
                    1 if any(cmd in html.lower() for cmd in ["exec", "system", "shell_exec", "eval", "os."]) else 0,  # RCE-паттерны
                    sum(1 for c in url if c in ['&', '|', ';', '$', '`', '(', ')']),  # Количество специальных символов в URL
                    1 if raw_payload and len(raw_payload) > 10 else 0  # Есть ли сложный payload
                ]
            elif vulnerability_type == 'csrf':
                # Признаки для CSRF
                specialized_features = [
                    1 if "form" in html.lower() else 0,  # Наличие форм
                    1 if "csrf" in html.lower() else 0,  # CSRF-токены
                    1 if "method=\"post\"" in html.lower() or "method='post'" in html.lower() else 0,  # POST-методы
                    1 if "token" in html.lower() else 0,  # Токены
                    html.lower().count("<input"),  # Количество полей ввода
                    1 if "cookie" in str(headers).lower() else 0  # Cookies в заголовках
                ]
            elif vulnerability_type == 'a01_broken_access_control':
                # Признаки для A01 Broken Access Control
                specialized_features = [
                    1 if any(segment in url.lower() for segment in ["admin", "config", "settings", "profile"]) else 0,  # Админ-пути
                    1 if "id=" in url else 0,  # Параметры ID
                    1 if "auth" in html.lower() or "login" in html.lower() else 0,  # Авторизация
                    1 if "access" in raw_payload.lower() else 0,  # Access в описании
                    1 if re.search(r'id=\d+', url) else 0,  # ID как число
                    1 if "forbidden" in html.lower() or "permission" in html.lower() else 0  # Текст о разрешениях
                ]
            elif vulnerability_type in ['a05_security_misconfiguration', 'ssrf', 'lfi']:
                # Признаки для других типов
                specialized_features = [
                    1 if any(ext in url for ext in ['.php', '.asp', '.jsp', '.cgi']) else 0,  # Расширения файлов
                    1 if "file=" in url or "path=" in url or "dir=" in url else 0,  # Параметры файлов
                    1 if "http" in url and "=" in url else 0,  # URL-инъекция
                    1 if "localhost" in url or "127.0.0.1" in url else 0,  # Локальные адреса
                    1 if "/etc/" in url or "C:\\" in url else 0,  # Системные пути
                    1 if raw_payload and ("vulnerability" in raw_payload.lower() or "exploit" in raw_payload.lower()) else 0  # Exploit в описании
                ]
            else:
                # Общие дополнительные признаки для остальных типов
                specialized_features = [
                    1 if "error" in html.lower() else 0,  # Ошибки
                    1 if "warning" in html.lower() else 0,  # Предупреждения
                    1 if "version" in html.lower() else 0,  # Версии
                    1 if len(url) > 100 else 0,  # Длинные URL
                    1 if raw_payload and len(raw_payload) > 50 else 0,  # Сложные payload
                    html.lower().count("<form")  # Количество форм
                ]
            
            # Объединяем базовые и специализированные признаки
            feature_vector = base_features + specialized_features
        
        # Если слишком мало признаков, добавляем нули
        while len(feature_vector) < 12:
            feature_vector.append(0)
        
        features.append(feature_vector)
        labels.append(1 if sample['is_vulnerable'] else 0)
    
    return np.array(features), np.array(labels)

def train_and_evaluate_model(features, labels, vulnerability_type):
    """Обучает и оценивает модель на данных."""
    if len(features) == 0 or len(labels) == 0:
        print(f"Ошибка: нет данных для обучения модели {vulnerability_type}")
        return None
    
    # Разделяем данные на тренировочную и тестовую выборки
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42
    )
    
    # Создаем и обучаем модель
    print(f"Обучение модели для {vulnerability_type}...")
    
    # Используем RandomForest для обучения
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Оцениваем модель
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    print(f"Метрики для {vulnerability_type}:")
    print(f"  Точность (Accuracy): {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-score: {f1:.4f}")
    
    # Матрица ошибок
    cm = confusion_matrix(y_test, y_pred)
    print(f"  Матрица ошибок:\n{cm}")
    
    # Пробуем альтернативную модель (GradientBoosting) и выбираем лучшую
    gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    gb_model.fit(X_train, y_train)
    gb_y_pred = gb_model.predict(X_test)
    gb_f1 = f1_score(y_test, gb_y_pred, zero_division=0)
    
    print(f"  F1-score для GradientBoosting: {gb_f1:.4f}")
    
    # Выбираем лучшую модель на основе F1
    if gb_f1 > f1:
        print(f"  Используем GradientBoosting для {vulnerability_type}")
        model = gb_model
        f1 = gb_f1
    else:
        print(f"  Используем RandomForest для {vulnerability_type}")
    
    # Сохраняем модель
    model_path = os.path.join(MODELS_DIR, f"{vulnerability_type}_model.pkl")
    joblib.dump(model, model_path)
    print(f"Модель сохранена в {model_path}")
    
    # Сохраняем метрики
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist()
    }
    metrics_path = os.path.join(MODELS_DIR, f"{vulnerability_type}_metrics.json")
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=4)
    
    return model

def train_all_models():
    """Обучает модели для всех типов уязвимостей."""
    # Список типов уязвимостей, для которых у нас есть тренировочные данные
    vulnerability_types = [
        "xss", "sqli", "csrf", "ssrf", "lfi", "rce",
        "a01_broken_access_control", "a02_cryptographic_failures",
        "a05_security_misconfiguration", "a06_vulnerable_components"
    ]
    
    trained_models = {}
    
    for vuln_type in vulnerability_types:
        print(f"\n=== Обучение модели для {vuln_type} ===")
        samples = load_training_data(vuln_type)
        
        if not samples:
            print(f"Пропуск {vuln_type}: нет данных")
            continue
        
        features, labels = extract_features_and_labels(samples, vuln_type)
        if features is None or labels is None or len(features) == 0:
            print(f"Пропуск {vuln_type}: ошибка при извлечении признаков")
            continue
        
        # Проверка размерности признаков
        print(f"Количество примеров для {vuln_type}: {len(features)}")
        print(f"Размерность векторов признаков: {features.shape}")
        
        model = train_and_evaluate_model(features, labels, vuln_type)
        if model:
            trained_models[vuln_type] = model
    
    print("\n=== Обучение моделей завершено ===")
    print(f"Обучено {len(trained_models)} моделей из {len(vulnerability_types)} типов уязвимостей")
    
    # Сохраняем список обученных моделей
    with open(os.path.join(MODELS_DIR, "trained_models_list.json"), 'w') as f:
        json.dump(list(trained_models.keys()), f, indent=4)
    
    return trained_models

if __name__ == "__main__":
    train_all_models() 