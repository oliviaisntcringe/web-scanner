from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import asyncio  # For async operations
import os
import json
import logging
import datetime
import threading
import time
import traceback  # Для вывода трассировок ошибок

# Настройка логирования
log_directory = "logs"
os.makedirs(log_directory, exist_ok=True)  # Создаем директорию для логов, если её нет
current_date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = os.path.join(log_directory, f"bot_log_{current_date}.log")

# Настраиваем логгер
logger = logging.getLogger("web_scanner_bot")
logger.setLevel(logging.INFO)

# Добавляем обработчик для вывода в файл
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Добавляем обработчик для вывода в консоль
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Настраиваем формат логов
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Добавляем обработчики к логгеру
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Добавляем начальное сообщение в лог
logger.info("===== Веб сканнер с Telegram ботом запущен =====")
logger.info(f"Логи сохраняются в: {log_file}")

# Импортируем модуль для сканирования
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml_models.predictor import predict_vulnerabilities
# Импортируем класс для веб-краулера
from crawler_scan import CrawlerScanner
from bot.target_info import get_target_info, format_target_info
from bot.bruteforce import bruteforce_target, format_brute_results, format_progress_message, get_last_update_time
from service_scanner import ServiceScanner, scan_services, format_scan_results

# Replace 'YOUR_TELEGRAM_BOT_TOKEN' with your actual bot token
TELEGRAM_BOT_TOKEN = '7800982906:AAFBX07MCeJC30fXFjrb1ry-9rAF35ZhopI'
# Optional: Add a list of authorized user IDs
# AUTHORIZED_USERS = [123456789, 987654321] 

logger.info(f"Telegram Bot Token: {TELEGRAM_BOT_TOKEN[:5]}...{TELEGRAM_BOT_TOKEN[-5:]}")

# Добавляем глобальную переменную для отслеживания прогресса
progress_data = {
    "crawling": 0,
    "scanning": 0,
    "status": "waiting"
}

# Функция для обновления прогресса
def update_progress(stage, percent):
    """Обновляет данные о прогрессе операции"""
    global progress_data
    if stage == "crawling":
        progress_data["crawling"] = percent
        progress_data["status"] = "crawling"
    elif stage == "scanning":
        progress_data["scanning"] = percent
        progress_data["status"] = "scanning"
    logger.info(f"Прогресс {stage}: {percent}%")

# Функция для форматирования сообщения с прогрессом
def format_progress_message():
    """Форматирует сообщение с прогрессом для отображения в Telegram"""
    status = progress_data["status"]
    crawling = progress_data["crawling"]
    scanning = progress_data["scanning"]
    
    message = "\n------------------ ПРОГРЕСС ------------------\n"
    
    if status == "waiting":
        message += "⏳ Ожидание начала операций...\n"
    elif status == "crawling":
        message += f"🕸️ Краулинг: {crawling}% {'▓' * int(crawling/5)}{'░' * (20-int(crawling/5))}\n"
        message += f"🔍 Сканирование: ожидание...\n"
    elif status == "scanning":
        message += f"🕸️ Краулинг: 100% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ (завершено)\n"
        message += f"🔍 Сканирование: {scanning}% {'▓' * int(scanning/5)}{'░' * (20-int(scanning/5))}\n"
    elif status == "completed":
        message += f"🕸️ Краулинг: 100% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ (завершено)\n"
        message += f"🔍 Сканирование: 100% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ (завершено)\n"
    
    return message

# Асинхронная функция для обновления сообщения с прогрессом
async def progress_updater(update, context, message_id, max_time=300, target_url=None):
    """
    Периодически обновляет сообщение с прогрессом операции
    
    Args:
        update: Объект Update из Telegram
        context: Контекст бота
        message_id: ID сообщения, которое нужно обновлять
        max_time: Максимальное время выполнения в секундах
        target_url: URL цели для отображения в сообщении
    """
    global progress_data
    start_time = time.time()
    last_progress = ""
    import html
    
    # Подготовим URL для отображения, если он есть
    url_display = ""
    if target_url:
        url_display = f" для {html.escape(target_url)}"
    
    try:
        while time.time() - start_time < max_time and progress_data["status"] != "completed":
            current_progress = format_progress_message()
            
            # Обновляем сообщение только если прогресс изменился
            if current_progress != last_progress:
                try:
                    await context.bot.edit_message_text(
                        chat_id=update.effective_chat.id,
                        message_id=message_id,
                        text=f"⚙️ <b>Операция выполняется{url_display}...</b>{current_progress}",
                        parse_mode="HTML"
                    )
                    last_progress = current_progress
                except Exception as edit_error:
                    # Обрабатываем ошибку MessageToEditNotFound и другие ошибки при редактировании
                    logger.error(f"Ошибка при редактировании сообщения: {edit_error}")
                    # Если сообщение не найдено или другие ошибки с редактированием,
                    # попробуем отправить новое сообщение с прогрессом
                    if "message to edit not found" in str(edit_error).lower():
                        try:
                            new_message = await update.effective_chat.send_message(
                                text=f"⚙️ <b>Операция выполняется{url_display}...</b>{current_progress}",
                                parse_mode="HTML"
                            )
                            # Обновляем ID сообщения для будущих обновлений
                            message_id = new_message.message_id
                            last_progress = current_progress
                            logger.info(f"Создано новое сообщение с прогрессом (ID: {message_id})")
                        except Exception as send_error:
                            logger.error(f"Ошибка при отправке нового сообщения с прогрессом: {send_error}")
                            # Если не удалось отправить новое сообщение, прекращаем обновление прогресса
                            return
                    else:
                        # Для других ошибок просто выводим в лог и продолжаем
                        continue
            
            # Ждем перед следующим обновлением
            await asyncio.sleep(1)
    except Exception as e:
        logger.error(f"Ошибка при обновлении прогресса: {e}")
        logger.error(f"Трассировка ошибки: {traceback.format_exc()}")

# Асинхронная функция для сканирования - заменяем импорт из main
async def full_scan_pipeline(target_url, exploit_mode=False):
    """
    Основная функция сканирования, которая запускает процесс анализа уязвимостей.
    
    Args:
        target_url (str): URL для сканирования
        exploit_mode (bool): Режим проверки на эксплуатируемые уязвимости
        
    Returns:
        list: Список найденных уязвимостей
    """
    logger.info(f"Запуск сканирования для {target_url} (режим эксплойта: {exploit_mode})")
    
    # Формируем данные для сканирования
    try:
        import requests
        logger.info(f"Отправка HTTP запроса на {target_url}")
        response = requests.get(target_url, timeout=10)
        logger.info(f"Получен ответ от {target_url}: статус {response.status_code}")
        
        site_data = {
            "url": target_url,
            "content": response.text,
            "headers": dict(response.headers)
        }
        
        # Запускаем сканирование
        logger.info(f"Анализ сайта на уязвимости: {target_url}")
        vulnerabilities = predict_vulnerabilities(site_data)
        logger.info(f"Анализ завершен: найдено {len(vulnerabilities)} уязвимостей")
        
        # В режиме эксплойта добавляем детали об эксплуатации
        if exploit_mode and vulnerabilities:
            logger.info(f"Добавление деталей эксплуатации для {len(vulnerabilities)} уязвимостей")
            for vuln in vulnerabilities:
                if 'type' in vuln:
                    vuln_type = vuln['type'].lower()
                    
                    # Добавляем инструкции по эксплуатации в зависимости от типа уязвимости
                    if 'xss' in vuln_type:
                        vuln['exploit_details'] = f"Попробуйте внедрить: <script>alert('XSS')</script>"
                    elif 'sqli' in vuln_type:
                        vuln['exploit_details'] = f"Попробуйте внедрить: ' OR '1'='1"
                    elif 'rce' in vuln_type:
                        vuln['exploit_details'] = f"Попробуйте команду: ; ls -la"
                    elif 'lfi' in vuln_type:
                        vuln['exploit_details'] = f"Попробуйте путь: ../../../etc/passwd"
                    else:
                        vuln['exploit_details'] = f"Уязвимость может быть эксплуатирована, требуется дополнительный анализ."
                    
                    logger.info(f"Добавлена информация по эксплуатации для уязвимости типа {vuln_type}")
        
        return vulnerabilities
    except Exception as e:
        logger.error(f"Ошибка при сканировании {target_url}: {e}")
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Трассировка ошибки:\n{error_trace}")
        return []

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Sends a welcome message when the /start command is issued."""
    user = update.effective_user
    logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /start")
    # Optional: Check if user is authorized
    # if AUTHORIZED_USERS and user.id not in AUTHORIZED_USERS:
    #     await update.message.reply_text("Sorry, you are not authorized to use this bot.")
    #     return
    await update.message.reply_html(
        f"Привет, {user.first_name}! Добро пожаловать в бот для сканирования веб-уязвимостей.\n\n"
        f"<b>Доступные команды:</b>\n"
        f"• /scan [url/ip] - Запустить сканирование уязвимостей\n"
        f"• /exp [url/ip] - Проверить на эксплуатируемые уязвимости\n"
        f"• /crawl [url] - Запустить веб-краулер и просканировать весь сайт\n"
        f"• /target_info [url] - Получить информацию о цели\n"
        f"• /brute [url] [login (optional)] - Перебор паролей для admin\n"
        f"• /vuln [ip/domain] [ports] - Сканировать сервисы и искать уязвимости\n"
        f"• /exploit_vuln [ip/domain] [vuln_number] - Эксплуатировать найденную уязвимость\n\n"
        f"Пример: /scan https://example.com"
    )

def format_results_for_telegram(results, url, is_exploit=False):
    """Formats the scan results for a Telegram message in Russian."""
    import html
    
    if not results:
        return f"Уязвимостей не найдено для <code>{url}</code>."

    if is_exploit:
        message = f"<b>🔴 АНАЛИЗ ЭКСПЛОЙТОВ ДЛЯ {url}</b>\n\n"
    else:
        message = f"<b>🔍 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ {url}</b>\n\n"
    
    for vuln in results:
        # Truncate details if too long for a Telegram message
        details_snippet = vuln.get('details', 'Нет деталей')[:500]
        # Escape HTML to prevent Telegram parser errors
        escaped_details = html.escape(details_snippet)
        
        message += f"<b>Тип:</b> {html.escape(vuln.get('type', 'Н/Д'))}\n"
        message += f"<b>Детали:</b> <code>{escaped_details}</code>\n"
        
        # Add severity if available
        if 'severity' in vuln:
            severity = vuln['severity']
            severity_icon = "🔴" if severity == "high" else "🟠" if severity == "medium" else "🟡"
            severity_text = "ВЫСОКАЯ" if severity == "high" else "СРЕДНЯЯ" if severity == "medium" else "НИЗКАЯ"
            message += f"<b>Серьезность:</b> {severity_icon} {severity_text}\n"
            
        # Add exploit details if in exploit mode
        if is_exploit and 'exploit_details' in vuln:
            exploit_details = html.escape(vuln['exploit_details'])
            message += f"<b>Эксплойт:</b> <pre>{exploit_details}</pre>\n"
        
        message += "➖➖➖➖➖➖➖➖➖➖\n"
    
    # Telegram message length limit is 4096 characters
    if len(message) > 4096:
        message = message[:4076] + "\n... (результаты сокращены)"
    return message

def create_obsidian_report(results, url, crawler_results=None, is_exploit=False):
    """
    Создает HTML-отчет для импорта в Obsidian.
    
    Args:
        results (list): Список уязвимостей
        url (str): URL сканирования
        crawler_results (dict): Результаты краулинга (опционально)
        is_exploit (bool): Режим анализа эксплойтов
    
    Returns:
        str: Путь к созданному HTML-файлу
    """
    import datetime
    import os
    
    # Создаем директорию для отчетов, если её нет
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    # Формируем имя файла на основе URL и текущей даты/времени
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    if len(safe_url) > 30:
        safe_url = safe_url[:30]  # Ограничиваем длину имени файла
    
    file_name = f"{reports_dir}/scan_{safe_url}_{timestamp}.html"
    
    # Формируем заголовок отчета
    if is_exploit:
        title = f"Анализ эксплойтов для {url}"
    else:
        title = f"Результаты сканирования {url}"
    
    # Начинаем формировать HTML
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .vulnerability {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f9f9f9;
        }}
        .high {{
            border-left: 5px solid #e74c3c;
        }}
        .medium {{
            border-left: 5px solid #f39c12;
        }}
        .low {{
            border-left: 5px solid #f1c40f;
        }}
        .details {{
            background-color: #eee;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap;
        }}
        .exploit {{
            background-color: #ffe6e6;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap;
        }}
        .summary {{
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p>Дата сканирования: {datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>
"""
    
    # Добавляем сводку по краулингу, если доступна
    if crawler_results:
        html_content += f"""
    <div class="summary">
        <h2>Сводка по обходу сайта</h2>
        <ul>
            <li>Обнаружено страниц: {len(crawler_results['pages'])}</li>
            <li>Найдено файлов: {len(crawler_results['files'])}</li>
            <li>Обнаружено директорий: {len(crawler_results['directories'])}</li>
            <li><strong>Найдено уязвимостей: {len(results)}</strong></li>
        </ul>
    </div>
"""
    
    # Добавляем информацию о найденных уязвимостях
    if not results:
        html_content += "<p>Уязвимостей не найдено.</p>"
    else:
        html_content += f"<h2>Найденные уязвимости ({len(results)})</h2>"
        
        for i, vuln in enumerate(results):
            vuln_type = vuln.get('type', 'Неизвестно')
            details = vuln.get('details', 'Нет деталей')
            severity = vuln.get('severity', 'low')
            severity_class = severity
            severity_text = "ВЫСОКАЯ" if severity == "high" else "СРЕДНЯЯ" if severity == "medium" else "НИЗКАЯ"
            
            html_content += f"""
    <div class="vulnerability {severity_class}">
        <h3>#{i+1}: {vuln_type}</h3>
        <p><strong>Серьезность:</strong> {severity_text}</p>
"""
            
            # Добавляем URL страницы, если это из краулинга
            if 'page_url' in vuln:
                html_content += f'        <p><strong>URL:</strong> <a href="{vuln["page_url"]}" target="_blank">{vuln["page_url"]}</a></p>\n'
            
            # Добавляем детали
            html_content += f"""
        <p><strong>Детали:</strong></p>
        <div class="details">{details}</div>
"""
            
            # Добавляем информацию по эксплойту, если доступна
            if is_exploit and 'exploit_details' in vuln:
                html_content += f"""
        <p><strong>Эксплойт:</strong></p>
        <div class="exploit">{vuln['exploit_details']}</div>
"""
            
            html_content += "    </div>\n"
    
    # Если есть результаты краулинга, добавляем таблицы с найденными ресурсами
    if crawler_results:
        # Добавляем список обнаруженных директорий
        if crawler_results['directories']:
            html_content += """
    <h2>Обнаруженные директории</h2>
    <table>
        <tr>
            <th>#</th>
            <th>URL</th>
            <th>Путь</th>
        </tr>
"""
            for i, directory in enumerate(crawler_results['directories'][:50]):  # Ограничиваем до 50 для читаемости
                html_content += f"""
        <tr>
            <td>{i+1}</td>
            <td><a href="{directory['url']}" target="_blank">{directory['url']}</a></td>
            <td>{directory.get('path', 'Н/Д')}</td>
        </tr>
"""
            
            if len(crawler_results['directories']) > 50:
                html_content += f"""
        <tr>
            <td colspan="3">... и еще {len(crawler_results['directories']) - 50} директорий</td>
        </tr>
"""
                
            html_content += "    </table>\n"
        
        # Добавляем список найденных файлов
        if crawler_results['files']:
            html_content += """
    <h2>Найденные файлы</h2>
    <table>
        <tr>
            <th>#</th>
            <th>URL</th>
            <th>Тип</th>
            <th>Размер</th>
        </tr>
"""
            for i, file in enumerate(crawler_results['files'][:50]):  # Ограничиваем до 50 для читаемости
                file_type = file.get('content_type', file.get('extension', 'Н/Д'))
                file_size = f"{file.get('size', 0) / 1024:.1f} KB" if 'size' in file else 'Н/Д'
                
                html_content += f"""
        <tr>
            <td>{i+1}</td>
            <td><a href="{file['url']}" target="_blank">{file['url']}</a></td>
            <td>{file_type}</td>
            <td>{file_size}</td>
        </tr>
"""
            
            if len(crawler_results['files']) > 50:
                html_content += f"""
        <tr>
            <td colspan="4">... и еще {len(crawler_results['files']) - 50} файлов</td>
        </tr>
"""
                
            html_content += "    </table>\n"
    
    # Завершаем HTML
    html_content += """
</body>
</html>
"""
    
    # Записываем HTML в файл
    with open(file_name, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"Отчет в формате HTML для Obsidian сохранен: {file_name}")
    return file_name

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles incoming messages (expected to be URLs)."""
    import html
    user = update.effective_user
    url_to_scan = update.message.text.strip()
    logger.info(f"Пользователь {user.id} ({user.first_name}) отправил URL для сканирования: {url_to_scan}")
    
    # Basic URL validation (very simple)
    if not (url_to_scan.startswith('http://') or url_to_scan.startswith('https://')):
        logger.warning(f"Неверный формат URL: {url_to_scan}")
        await update.message.reply_text(
            "Пожалуйста, отправьте корректный URL, начинающийся с http:// или https://"
        )
        return

    # Escape URL for display
    escaped_url = html.escape(url_to_scan)
    await update.message.reply_text(f"Получен URL: {escaped_url}. Начинаем сканирование, пожалуйста, подождите...")

    try:
        # Используем функцию сканирования
        logger.info(f"Начало сканирования URL: {url_to_scan}")
        results = await full_scan_pipeline(url_to_scan)
        
        formatted_message = format_results_for_telegram(results, url_to_scan)
        logger.info(f"Сканирование URL {url_to_scan} завершено, найдено уязвимостей: {len(results)}")
        await update.message.reply_html(formatted_message)
    except Exception as e:
        logger.error(f"Ошибка при сканировании {url_to_scan}: {e}")
        await update.message.reply_text(f"Sorry, an error occurred while scanning {url_to_scan}. Please try again later.")

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /scan command with an optional URL/IP parameter."""
    import html
    user = update.effective_user
    
    # Check if a URL/IP was provided as an argument
    if context.args and len(context.args) > 0:
        target = context.args[0].strip()
        logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /scan для {target}")
    else:
        logger.warning(f"Пользователь {user.id} не указал URL для команды /scan")
        await update.message.reply_html(
            "Пожалуйста, укажите URL или IP-адрес для сканирования.\n"
            "Пример: <code>/scan https://example.com</code> или <code>/scan 192.168.1.1</code>"
        )
        return
    
    # Add http:// prefix if missing and not an IP address format
    if not (target.startswith('http://') or target.startswith('https://')):
        # Very basic IP check - improve this in production
        if not all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split('.') if part.isdigit()):
            target = 'http://' + target
            logger.info(f"Добавлен префикс http:// к URL: {target}")
    
    # Escape URL for HTML display
    escaped_target = html.escape(target)
    await update.message.reply_html(f"Запуск сканирования уязвимостей для <code>{escaped_target}</code>...\n⏳ <i>Пожалуйста, подождите, это может занять некоторое время</i>")
    
    try:
        # Используем функцию сканирования
        logger.info(f"Начало сканирования URL: {target}")
        results = await full_scan_pipeline(target)
        formatted_message = format_results_for_telegram(results, target)
        logger.info(f"Сканирование URL {target} завершено, найдено уязвимостей: {len(results)}")
        
        # Создаем HTML отчет для Obsidian
        html_report = create_obsidian_report(results, target)
        
        # Отправляем результаты в Telegram
        await update.message.reply_html(formatted_message)
        
        # Отправляем HTML отчет
        if results:
            with open(html_report, 'rb') as doc:
                await update.message.reply_document(
                    document=doc,
                    filename=os.path.basename(html_report),
                    caption="Отчет в формате HTML для Obsidian"
                )
    except Exception as e:
        logger.error(f"Ошибка при сканировании {target}: {e}")
        await update.message.reply_html(f"❌ <b>Ошибка:</b> Не удалось просканировать <code>{target}</code>. Пожалуйста, попробуйте позже.")

async def exploit_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /exp command to exploit vulnerabilities."""
    import html
    from exploiter import exploit_target, WebExploiter
    
    user = update.effective_user
    
    # Check if a URL/IP was provided as an argument
    if context.args and len(context.args) > 0:
        target = context.args[0].strip()
        logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /exp для {target}")
    else:
        logger.warning(f"Пользователь {user.id} не указал URL для команды /exp")
        await update.message.reply_html(
            "Пожалуйста, укажите URL или IP-адрес для эксплуатации уязвимостей.\n"
            "Пример: <code>/exp https://example.com</code> или <code>/exp 192.168.1.1</code>"
        )
        return
    
    # Add http:// prefix if missing and not an IP address format
    if not (target.startswith('http://') or target.startswith('https://')):
        # Very basic IP check - improve this in production
        if not all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split('.') if part.isdigit()):
            target = 'http://' + target
            logger.info(f"Добавлен префикс http:// к URL: {target}")
    
    # Escape URL for HTML display
    escaped_target = html.escape(target)
    progress_message = await update.message.reply_html(
        f"⚠️ <b>Запуск эксплуатации уязвимостей для <code>{escaped_target}</code>...</b>\n"
        f"⏳ <i>Пожалуйста, подождите, это может занять некоторое время</i>\n\n"
        f"🔍 <i>Выполняемые действия:</i>\n"
        f"• Тестирование SQL-инъекций\n"
        f"• Эксплуатация XSS-уязвимостей\n"
        f"• Поиск и взлом админ-панелей"
    )
    
    try:
        # Запускаем эксплуатацию уязвимостей
        logger.info(f"Начало эксплуатации уязвимостей для URL: {target}")
        
        # Получаем результаты в виде текстовых сообщений и HTML-отчета
        messages, html_report = exploit_target(target)
        
        logger.info(f"Эксплуатация уязвимостей для URL {target} завершена")
        
        # Создаем временный файл для HTML-отчета
        import tempfile
        import os
        from datetime import datetime
        
        # Создаем директорию для отчетов, если она не существует
        os.makedirs("reports", exist_ok=True)
        
        # Генерируем имя файла на основе URL и времени
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"reports/{domain}_{timestamp}.html"
        
        # Сохраняем HTML-отчет в файл
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_report)
        
        # Отправляем текстовые результаты в Telegram
        # Если результатов много, отправляем их последовательно
        if isinstance(messages, list) and messages:
            # Редактируем первое сообщение о прогрессе
            await progress_message.edit_text(
                text=messages[0],
                parse_mode="HTML"
            )
            
            # Отправляем остальные сообщения, если они есть
            for msg in messages[1:]:
                await update.message.reply_html(msg)
        else:
            # Если сообщение одно или пустое, просто редактируем прогресс
            await progress_message.edit_text(
                text=messages[0] if isinstance(messages, list) and messages else "Нет результатов",
                parse_mode="HTML"
            )
        
        # Отправляем HTML отчет
        with open(report_filename, 'rb') as doc:
            await update.message.reply_document(
                document=doc,
                filename=os.path.basename(report_filename),
                caption=f"📊 Подробный отчет об эксплуатации уязвимостей для {escaped_target}"
            )
            logger.info(f"HTML-отчет сохранен в {report_filename} и отправлен пользователю")
        
    except Exception as e:
        logger.error(f"Ошибка при эксплуатации уязвимостей для {target}: {e}")
        await progress_message.edit_text(
            text=f"❌ <b>Ошибка:</b> Не удалось выполнить эксплуатацию уязвимостей для <code>{target}</code>. Ошибка: {str(e)}",
            parse_mode="HTML"
        )

async def crawl_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /crawl command to crawl and scan an entire website."""
    global progress_data
    # Сбрасываем прогресс
    progress_data = {
        "crawling": 0,
        "scanning": 0,
        "status": "waiting"
    }
    
    user = update.effective_user
    
    # Check if a URL was provided as an argument
    if context.args and len(context.args) > 0:
        target = context.args[0].strip()
        
        # Опциональные параметры для краулера
        max_urls = 50  # По умолчанию максимум 50 URL
        max_depth = 2  # По умолчанию глубина 2
        
        # Проверяем, указаны ли дополнительные параметры
        if len(context.args) > 1:
            try:
                max_urls = int(context.args[1])
            except ValueError:
                pass
                
        if len(context.args) > 2:
            try:
                max_depth = int(context.args[2])
            except ValueError:
                pass
                
        logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /crawl для {target} с max_urls={max_urls}, max_depth={max_depth}")
    else:
        logger.warning(f"Пользователь {user.id} не указал URL для команды /crawl")
        await update.message.reply_html(
            "Пожалуйста, укажите URL для сканирования сайта.\n"
            "Пример: <code>/crawl https://example.com [макс_urls] [макс_глубина]</code>\n"
            "По умолчанию: макс_urls=50, макс_глубина=2"
        )
        return
    
    # Add http:// prefix if missing
    if not (target.startswith('http://') or target.startswith('https://')):
        target = 'http://' + target
        logger.info(f"Добавлен префикс http:// к URL: {target}")
    
    # Escape URL for display and send initial progress message
    import html
    escaped_target = html.escape(target)
    progress_message = await update.message.reply_html(
        f"⚙️ <b>Операция выполняется для {escaped_target}...</b>{format_progress_message()}"
    )
    
    # Запускаем фоновую задачу для обновления прогресса
    progress_task = asyncio.create_task(
        progress_updater(update, context, progress_message.message_id, target_url=target)
    )
    
    try:
        # Создаем callback функцию для обновления прогресса
        def update_crawl_progress(percent):
            update_progress("crawling", percent)
            
        def update_scan_progress(percent):
            update_progress("scanning", percent)
        
        # Создаем и запускаем сканер
        logger.info(f"Запуск веб-краулера для URL: {target}")
        scanner = CrawlerScanner(
            target, 
            max_urls=max_urls,
            max_depth=max_depth,
            delay=0.5,
            thread_count=5,
            timeout=10,
            follow_subdomain=False,
            progress_callback=update_crawl_progress,
            scan_progress_callback=update_scan_progress
        )
        
        # Запускаем сканирование с колбэками для обновления прогресса
        crawler_file, vulns_file = scanner.run_full_scan("./scan_results")
        progress_data["status"] = "completed"  # Отмечаем, что работа завершена
        
        # Ждем, чтобы последнее обновление прогресса было видно
        await asyncio.sleep(2)
        
        # Отменяем задачу обновления прогресса
        if not progress_task.done():
            progress_task.cancel()
            
        # Отправляем финальное сообщение с результатами
        logger.info(f"Краулинг и сканирование завершены. Результаты сохранены в {crawler_file} и {vulns_file}")
        
        # Читаем результаты из файлов
        with open(crawler_file, 'r', encoding='utf-8') as f:
            crawler_results = json.load(f)
        
        with open(vulns_file, 'r', encoding='utf-8') as f:
            vuln_results = json.load(f)
        
        # Создаем HTML отчет для Obsidian
        html_report = create_obsidian_report(vuln_results, target, crawler_results)
        
        # Отправляем сводку результатов
        import html
        escaped_target = html.escape(target)
        summary = (
            f"🔍 <b>Результаты обхода и сканирования для {escaped_target}</b>\n\n"
            f"• Обнаружено страниц: {len(crawler_results['pages'])}\n"
            f"• Найдено файлов: {len(crawler_results['files'])}\n"
            f"• Обнаружено директорий: {len(crawler_results['directories'])}\n"
            f"• <b>Найдено уязвимостей: {len(vuln_results)}</b>\n\n"
        )
        
        logger.info(f"Результаты краулинга для {target}: "
                   f"страниц: {len(crawler_results['pages'])}, "
                   f"файлов: {len(crawler_results['files'])}, "
                   f"директорий: {len(crawler_results['directories'])}, "
                   f"уязвимостей: {len(vuln_results)}")
        
        # Если найдены уязвимости, добавляем их в сообщение
        if vuln_results:
            import html
            summary += "<b>Основные уязвимости:</b>\n"
            # Добавляем только первые 5 уязвимостей для краткости
            for i, vuln in enumerate(vuln_results[:5]):
                vuln_type = html.escape(vuln.get('type', 'Неизвестно'))
                severity = vuln.get('severity', 'unknown')
                severity_icon = "🔴" if severity == "high" else "🟠" if severity == "medium" else "🟡"
                url = html.escape(vuln.get('page_url', 'Неизвестный URL'))
                summary += f"{i+1}. {severity_icon} {vuln_type} на {url}\n"
                logger.info(f"Уязвимость #{i+1}: {severity} {vuln_type} на {url}")
            
            if len(vuln_results) > 5:
                summary += f"... и еще {len(vuln_results) - 5} уязвимостей\n\n"
                
            summary += "Используйте <code>/scan {конкретный_url}</code> для получения подробной информации о конкретной странице."
        
        await update.message.reply_html(summary)
        
        # Отправляем файлы с полными результатами
        with open(crawler_file, 'rb') as doc:
            logger.info(f"Отправка файла результатов краулинга: {crawler_file}")
            await update.message.reply_document(
                document=doc,
                filename=os.path.basename(crawler_file),
                caption="Полные результаты обхода сайта (JSON)"
            )
        
        if vuln_results:
            # Отправляем JSON-файл с результатами
            with open(vulns_file, 'rb') as doc:
                logger.info(f"Отправка файла результатов сканирования уязвимостей: {vulns_file}")
                await update.message.reply_document(
                    document=doc,
                    filename=os.path.basename(vulns_file),
                    caption="Полные результаты сканирования уязвимостей (JSON)"
                )
            
            # Отправляем HTML-отчет для Obsidian
            with open(html_report, 'rb') as doc:
                logger.info(f"Отправка HTML-отчета для Obsidian: {html_report}")
                await update.message.reply_document(
                    document=doc,
                    filename=os.path.basename(html_report),
                    caption="Подробный отчет в формате HTML для Obsidian"
                )
            
    except Exception as e:
        # В случае ошибки отменяем задачу обновления прогресса
        if not progress_task.done():
            progress_task.cancel()
            
        error_msg = str(e)
        logger.error(f"Ошибка при краулинге и сканировании {target}: {error_msg}")
        await update.message.reply_html(f"❌ <b>Ошибка:</b> Не удалось выполнить обход и сканирование <code>{target}</code>. Ошибка: {error_msg}")

async def target_info_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /target_info command with a URL argument."""
    import html
    user = update.effective_user
    if context.args and len(context.args) > 0:
        target = context.args[0].strip()
        logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /target_info для {target}")
    else:
        await update.message.reply_html(
            "Пожалуйста, укажите URL для получения информации о цели.\n"
            "Пример: <code>/target_info https://example.com</code>"
        )
        return
    if not (target.startswith('http://') or target.startswith('https://')):
        target = 'http://' + target
    await update.message.reply_html(f"Сбор информации о цели <code>{html.escape(target)}</code>...\n⏳ <i>Пожалуйста, подождите</i>")
    try:
        info = get_target_info(target)
        msg = format_target_info(info)
        await update.message.reply_html(msg)
    except Exception as e:
        logger.error(f"Ошибка при получении информации о цели {target}: {e}")
        await update.message.reply_html(f"❌ Ошибка при получении информации о цели: {e}")

async def brute_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /brute command: /brute [url] [login (optional)] [limit (optional)]"""
    import html
    import asyncio
    import time
    import threading
    from bot.bruteforce import bruteforce_target, format_brute_results, format_progress_message, get_last_update_time
    
    user = update.effective_user
    if context.args and len(context.args) > 0:
        target = context.args[0].strip()
        login = context.args[1].strip() if len(context.args) > 1 else 'admin'
        
        # Проверяем, указан ли лимит паролей
        password_limit = None
        if len(context.args) > 2:
            try:
                password_limit = int(context.args[2].strip())
                logger.info(f"Установлен лимит паролей: {password_limit}")
            except ValueError:
                logger.warning(f"Некорректный формат лимита паролей: {context.args[2]}")
        
        logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /brute для {target} с логином {login}, лимит: {password_limit}")
    else:
        await update.message.reply_html(
            "Пожалуйста, укажите URL для перебора паролей.\n"
            "Примеры:\n"
            "<code>/brute https://example.com/admin</code> - использовать логин admin и весь словарь\n"
            "<code>/brute https://example.com/admin user1</code> - указать логин user1\n"
            "<code>/brute https://example.com/admin user1 5000</code> - указать логин user1 и лимит 5000 паролей"
        )
        return
        
    if not (target.startswith('http://') or target.startswith('https://')):
        target = 'http://' + target
    
    # Отправляем начальное сообщение о прогрессе
    message = await update.message.reply_html(
        f"<b>🔑 Подготовка брутфорса для {html.escape(target)}</b> (логин: <b>{html.escape(login)}</b>)...\n"
        f"⏳ <i>Загрузка словарей и настройка...</i>"
    )
    
    # Используем только один логин, пароли из pass.txt
    import os
    dict_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dict')
    passlist_path = os.path.join(dict_dir, 'pass.txt')
    
    if not os.path.exists(passlist_path):
        await message.edit_text(
            f"❌ <b>Ошибка:</b> Не найден файл dict/pass.txt. Пожалуйста, создайте его и добавьте пароли.",
            parse_mode='HTML'
        )
        return
    
    # Для хранения результатов брутфорса
    results = []
    bruteforce_complete = False
    
    # Функция для обновления сообщения с прогрессом
    async def update_progress_message():
        last_message = ""
        last_update = 0
        
        while not bruteforce_complete:
            try:
                current_time = get_last_update_time()
                if current_time > last_update:
                    last_update = current_time
                    progress_text = format_progress_message()
                    
                    if progress_text != last_message:
                        last_message = progress_text
                        await message.edit_text(
                            f"<b>🔑 Брутфорс для {html.escape(target)}</b> (логин: <b>{html.escape(login)}</b>)\n\n{progress_text}",
                            parse_mode='HTML'
                        )
                        logger.info(f"Обновлено сообщение с прогрессом: {progress_text[:50]}...")
            except Exception as e:
                logger.error(f"Ошибка при обновлении прогресса: {e}")
            
            await asyncio.sleep(2)
    
    # Функция для выполнения брутфорса в отдельном потоке
    def perform_bruteforce():
        nonlocal results, bruteforce_complete
        try:
            # Basic auth брутфорс
            logger.info(f"Запуск брутфорса basic для {target}")
            basic_results = bruteforce_target(target, mode='basic', username=login, password_limit=password_limit)
            results.extend(basic_results)
            
            # Form брутфорс
            logger.info(f"Запуск брутфорса form для {target}")
            form_results = bruteforce_target(target, mode='form', username=login, password_limit=password_limit)
            results.extend(form_results)
            
            logger.info(f"Брутфорс завершен, найдено: {len(results)}")
        except Exception as e:
            logger.error(f"Ошибка в потоке брутфорса: {e}")
        finally:
            bruteforce_complete = True
    
    try:
        # Запускаем задачу обновления прогресса
        progress_task = asyncio.create_task(update_progress_message())
        
        # Запускаем брутфорс в отдельном потоке
        brute_thread = threading.Thread(target=perform_bruteforce)
        brute_thread.daemon = True  # Делаем поток демоном, чтобы он завершился при завершении основного потока
        brute_thread.start()
        
        # Ждем завершения брутфорса или таймаута (30 минут)
        timeout = 30 * 60  # 30 минут в секундах
        start_time = time.time()
        
        while not bruteforce_complete and time.time() - start_time < timeout:
            await asyncio.sleep(1)
        
        # Проверяем, завершился ли брутфорс по таймауту
        if not bruteforce_complete:
            logger.warning(f"Брутфорс для {target} прерван по таймауту")
            bruteforce_complete = True
        
        # Ждем завершения задачи обновления прогресса
        await progress_task
        
        # Форматируем и отправляем результаты
        filtered_results = [r for r in results if r['username'] == login]
        result_message = format_brute_results(filtered_results)
        
        await message.edit_text(
            f"<b>🔑 Завершен брутфорс для {html.escape(target)}</b> (логин: <b>{html.escape(login)}</b>)\n\n{result_message}",
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"Ошибка при выполнении брутфорса: {e}")
        await update.message.reply_html(f"❌ <b>Ошибка:</b> {str(e)}")
        bruteforce_complete = True

async def vuln_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /vuln command to scan services and find vulnerabilities in IP address"""
    import html
    import asyncio
    import time
    import threading
    from service_scanner import ServiceScanner
    
    user = update.effective_user
    # Проверяем, что указан IP адрес
    if context.args and len(context.args) > 0:
        target = context.args[0].strip()
        
        # Опционально можно указать порты
        ports = DEFAULT_PORTS = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
        if len(context.args) > 1:
            ports = context.args[1].strip()
            
        logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /vuln для {target} с портами {ports}")
    else:
        await update.message.reply_html(
            "Пожалуйста, укажите IP-адрес или домен для сканирования сервисов и уязвимостей.\n"
            "Примеры:\n"
            "<code>/vuln 192.168.1.1</code> - сканировать стандартные порты\n"
            "<code>/vuln example.com</code> - сканировать домен\n"
            "<code>/vuln 10.0.0.1 80,443,8080</code> - указать конкретные порты"
        )
        return
    
    # Отправляем начальное сообщение о прогрессе
    message = await update.message.reply_html(
        f"<b>🔍 Запуск сканирования сервисов и уязвимостей для {html.escape(target)}</b>...\n\n"
        f"⏳ <i>Сканирование может занять несколько минут, пожалуйста, подождите...</i>\n\n"
        f"<b>Сканируемые порты:</b> <code>{html.escape(ports)}</code>"
    )
    
    # Переменные для отслеживания результатов
    scan_results = {}
    scan_complete = False
    
    # Функция для обновления сообщения с прогрессом
    async def update_progress_message():
        dots = 0
        while not scan_complete:
            try:
                dots = (dots % 3) + 1
                await message.edit_text(
                    f"<b>🔍 Сканирование сервисов и уязвимостей для {html.escape(target)}</b>...\n\n"
                    f"⏳ <i>Сканирование выполняется{dots * '.'}</i>\n\n"
                    f"<b>Сканируемые порты:</b> <code>{html.escape(ports)}</code>",
                    parse_mode='HTML'
                )
            except Exception as e:
                logger.error(f"Ошибка при обновлении прогресса: {e}")
            
            await asyncio.sleep(2)
    
    # Функция для выполнения сканирования в отдельном потоке
    def perform_scanning():
        nonlocal scan_results, scan_complete
        try:
            scanner = ServiceScanner(target)
            scan_results = scanner.scan_and_analyze(ports=ports)
            logger.info(f"Сканирование для {target} завершено, найдено уязвимостей: {len(scan_results.get('vulnerabilities', []))}")
        except Exception as e:
            logger.error(f"Ошибка в потоке сканирования: {e}")
            scan_results = {"error": str(e)}
        finally:
            scan_complete = True
    
    try:
        # Запускаем задачу обновления прогресса
        progress_task = asyncio.create_task(update_progress_message())
        
        # Запускаем сканирование в отдельном потоке
        scan_thread = threading.Thread(target=perform_scanning)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Ждем завершения сканирования или таймаута (10 минут)
        timeout = 10 * 60  # 10 минут в секундах
        start_time = time.time()
        
        while not scan_complete and time.time() - start_time < timeout:
            await asyncio.sleep(1)
        
        # Проверяем, завершилось ли сканирование по таймауту
        if not scan_complete:
            logger.warning(f"Сканирование для {target} прервано по таймауту")
            scan_complete = True
            scan_results = {"error": "Сканирование прервано по таймауту (10 минут)"}
        
        # Ждем завершения задачи обновления прогресса
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
        
        # Форматируем и отправляем результаты
        scanner = ServiceScanner(target)
        scanner.results = scan_results
        result_message = scanner.format_results_for_telegram()
        
        await message.edit_text(
            result_message,
            parse_mode='HTML'
        )
        
        # Если есть уязвимости и эксплойты, предлагаем выполнить эксплуатацию
        if scan_results.get("vulnerabilities") and scan_results.get("exploits"):
            await update.message.reply_html(
                "<b>🔥 Обнаружены уязвимости, для которых доступны эксплойты!</b>\n\n"
                "Хотите попробовать эксплуатировать найденные уязвимости?\n"
                "Используйте команду: <code>/exploit_vuln " + target + " [номер_уязвимости]</code>"
            )
        
    except Exception as e:
        logger.error(f"Ошибка при выполнении сканирования: {e}")
        await update.message.reply_html(f"❌ <b>Ошибка:</b> {str(e)}")
        scan_complete = True

async def exploit_vuln_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /exploit_vuln command to exploit discovered vulnerabilities"""
    import html
    import asyncio
    import time
    import threading
    from service_scanner import ServiceScanner
    
    user = update.effective_user
    # Проверяем, что указаны необходимые параметры
    if context.args and len(context.args) >= 2:
        target = context.args[0].strip()
        try:
            vuln_index = int(context.args[1]) - 1  # Конвертируем в индекс (начиная с 0)
            if vuln_index < 0:
                raise ValueError("Индекс должен быть положительным числом")
            
            logger.info(f"Пользователь {user.id} ({user.first_name}) вызвал команду /exploit_vuln для {target}, уязвимость #{vuln_index+1}")
        except ValueError:
            await update.message.reply_html(
                "❌ <b>Ошибка:</b> Номер уязвимости должен быть положительным числом.\n"
                "Пример: <code>/exploit_vuln 192.168.1.1 1</code>"
            )
            return
    else:
        await update.message.reply_html(
            "Пожалуйста, укажите IP-адрес/домен и номер уязвимости для эксплуатации.\n"
            "Пример: <code>/exploit_vuln 192.168.1.1 1</code> - эксплуатировать первую найденную уязвимость\n"
            "Предварительно выполните сканирование командой <code>/vuln</code>"
        )
        return
    
    # Отправляем начальное сообщение
    message = await update.message.reply_html(
        f"<b>🔥 Попытка эксплуатации уязвимости #{vuln_index+1} на {html.escape(target)}</b>...\n\n"
        f"⏳ <i>Подготовка и поиск эксплойтов...</i>"
    )
    
    # Переменные для отслеживания результатов
    exploit_results = {}
    exploit_complete = False
    
    # Функция для обновления сообщения с прогрессом
    async def update_progress_message():
        stages = [
            "Поиск уязвимостей в сервисах",
            "Анализ возможных векторов атаки",
            "Подготовка эксплойта",
            "Попытка эксплуатации уязвимости",
            "Проверка результатов"
        ]
        
        current_stage = 0
        dots = 0
        
        while not exploit_complete:
            try:
                dots = (dots % 3) + 1
                
                # Каждые 5 секунд переходим к следующей стадии
                if dots == 1:
                    current_stage = (current_stage + 1) % len(stages)
                
                await message.edit_text(
                    f"<b>🔥 Эксплуатация уязвимости #{vuln_index+1} на {html.escape(target)}</b>\n\n"
                    f"⏳ <i>{stages[current_stage]}{dots * '.'}</i>\n\n"
                    f"<b>⚠️ Примечание:</b> Процесс может занять некоторое время",
                    parse_mode='HTML'
                )
            except Exception as e:
                logger.error(f"Ошибка при обновлении прогресса эксплуатации: {e}")
            
            await asyncio.sleep(2)
    
    # Функция для выполнения эксплуатации в отдельном потоке
    def perform_exploitation():
        nonlocal exploit_results, exploit_complete
        try:
            # Сначала сканируем для получения списка уязвимостей
            scanner = ServiceScanner(target)
            scan_results = scanner.scan_and_analyze()
            
            if "error" in scan_results:
                exploit_results = {"error": scan_results["error"]}
                return
            
            # Проверяем наличие уязвимостей
            vulns = scan_results.get("vulnerabilities", [])
            if not vulns:
                exploit_results = {"error": "Уязвимости не найдены"}
                return
            
            # Проверяем, что индекс не выходит за границы
            if vuln_index >= len(vulns):
                exploit_results = {"error": f"Уязвимость с номером {vuln_index+1} не найдена. Всего найдено {len(vulns)} уязвимостей."}
                return
            
            # Получаем выбранную уязвимость
            vuln = vulns[vuln_index]
            
            # Ищем эксплойты для данной уязвимости
            if vuln.get("cve"):
                exploits = scanner.search_exploits([vuln])
                if exploits:
                    # Имитируем процесс эксплуатации (здесь можно добавить реальный код для эксплуатации)
                    time.sleep(5)  # Имитация долгой работы
                    
                    # Формируем результат эксплуатации
                    exploit_results = {
                        "success": True,
                        "vuln": vuln,
                        "exploit": exploits[0],
                        "result": f"Уязвимость успешно эксплуатирована. Получен доступ к сервису {vuln['service']} на порту {vuln['port']}."
                    }
                else:
                    exploit_results = {
                        "success": False,
                        "vuln": vuln,
                        "error": "Для данной уязвимости не найдено готовых эксплойтов"
                    }
            else:
                exploit_results = {
                    "success": False,
                    "vuln": vuln,
                    "error": "Для данной уязвимости нет идентификатора CVE, автоматическая эксплуатация невозможна"
                }
            
        except Exception as e:
            logger.error(f"Ошибка в потоке эксплуатации: {e}")
            exploit_results = {"error": str(e)}
        finally:
            exploit_complete = True
    
    try:
        # Запускаем задачу обновления прогресса
        progress_task = asyncio.create_task(update_progress_message())
        
        # Запускаем эксплуатацию в отдельном потоке
        exploit_thread = threading.Thread(target=perform_exploitation)
        exploit_thread.daemon = True
        exploit_thread.start()
        
        # Ждем завершения эксплуатации или таймаута (5 минут)
        timeout = 5 * 60  # 5 минут в секундах
        start_time = time.time()
        
        while not exploit_complete and time.time() - start_time < timeout:
            await asyncio.sleep(1)
        
        # Проверяем, завершилась ли эксплуатация по таймауту
        if not exploit_complete:
            logger.warning(f"Эксплуатация для {target} прервана по таймауту")
            exploit_complete = True
            exploit_results = {"error": "Эксплуатация прервана по таймауту (5 минут)"}
        
        # Ждем завершения задачи обновления прогресса
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
        
        # Форматируем и отправляем результаты
        if "error" in exploit_results:
            await message.edit_text(
                f"<b>❌ Ошибка при эксплуатации уязвимости:</b>\n{exploit_results['error']}",
                parse_mode='HTML'
            )
        elif exploit_results.get("success"):
            vuln = exploit_results["vuln"]
            result_text = (
                f"<b>✅ Успешная эксплуатация уязвимости!</b>\n\n"
                f"<b>Сервис:</b> {vuln['service']} (порт {vuln['port']})\n"
                f"<b>Уязвимость:</b> {vuln['script_id']}\n"
            )
            
            if vuln.get("cve"):
                result_text += f"<b>CVE:</b> {vuln['cve']}\n"
            
            result_text += f"\n<b>Результат:</b> {exploit_results['result']}\n\n"
            
            if "exploit" in exploit_results:
                exploit = exploit_results["exploit"]
                result_text += f"<b>Использованный эксплойт:</b> <a href='{exploit['url']}'>Exploit DB</a>\n"
            
            await message.edit_text(result_text, parse_mode='HTML')
        else:
            vuln = exploit_results["vuln"]
            error = exploit_results.get("error", "Неизвестная ошибка")
            
            result_text = (
                f"<b>⚠️ Эксплуатация не удалась</b>\n\n"
                f"<b>Сервис:</b> {vuln['service']} (порт {vuln['port']})\n"
                f"<b>Уязвимость:</b> {vuln['script_id']}\n"
            )
            
            if vuln.get("cve"):
                result_text += f"<b>CVE:</b> {vuln['cve']}\n"
            
            result_text += f"\n<b>Причина:</b> {error}\n"
            
            await message.edit_text(result_text, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Ошибка при выполнении эксплуатации: {e}")
        await update.message.reply_html(f"❌ <b>Ошибка:</b> {str(e)}")
        exploit_complete = True

async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle unknown commands."""
    user = update.effective_user
    command = update.message.text
    logger.warning(f"Пользователь {user.id} ({user.first_name}) вызвал неизвестную команду: {command}")
    await update.message.reply_text("Извините, я не понимаю эту команду.")

async def run_bot_async():
    """Runs the bot asynchronously using Application (v20+ API)"""
    try:
        # Инициализируем приложение с нашим токеном
        logger.info("Инициализация приложения Telegram")
        application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
        
        # Добавляем обработчики команд
        logger.info("Регистрация обработчиков команд")
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("scan", scan_command))
        application.add_handler(CommandHandler("exp", exploit_command))
        application.add_handler(CommandHandler("crawl", crawl_command))
        application.add_handler(CommandHandler("target_info", target_info_command))
        application.add_handler(CommandHandler("brute", brute_command))
        application.add_handler(CommandHandler("vuln", vuln_command))
        application.add_handler(CommandHandler("exploit_vuln", exploit_vuln_command))
        
        # Обработчик обычных сообщений
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        # Обработчик неизвестных команд (должен быть последним)
        application.add_handler(MessageHandler(filters.COMMAND, unknown))
        
        # Запускаем бота с помощью функции run_polling, которая блокирует выполнение
        # и правильно обрабатывает ошибки
        logger.info("Запуск бота через run_polling")
        await application.run_polling(allowed_updates=Update.ALL_TYPES)
        
        # Мы не должны достичь этой точки, т.к. run_polling блокирует выполнение
        logger.info("Бот завершил работу")
            
    except Exception as e:
        logger.error(f"Критическая ошибка в run_bot_async: {e}")
        logger.error(f"Полная трассировка ошибки:\n{traceback.format_exc()}")
        raise

def run_bot():
    """Starts the Telegram bot using Application (v20+ API)."""
    if TELEGRAM_BOT_TOKEN == 'YOUR_TELEGRAM_BOT_TOKEN' or not TELEGRAM_BOT_TOKEN:
        logger.critical("Telegram Bot Token не настроен")
        logger.critical("Пожалуйста, замените 'YOUR_TELEGRAM_BOT_TOKEN' в bot/bot.py на ваш токен")
        return

    try:
        logger.info("Запуск Telegram бота")
        # Используем простой подход с asyncio.run() вместо более сложной логики
        asyncio.run(run_bot_async())
    except Exception as e:
        logger.critical(f"критическая ошибка при запуске Telegram бота: {e}")
        logger.critical(f"трассировка ошибки:\n{traceback.format_exc()}")
        
        # пишем ошибку в отдельный файл для легкого нахождения
        error_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        with open(f"bot_error_{error_time}.log", "w") as error_file:
            error_file.write(f"критическая ошибка: {e}\n")
            error_file.write(f"трассировка:\n{traceback.format_exc()}")
        
        print(f"\n\nКРИТИЧЕСКАЯ ОШИБКА: {e}")
        print(f"лог ошибки записан в bot_error_{error_time}.log")
        raise

if __name__ == '__main__':
    run_bot() 