#!/usr/bin/env python3
import time
import random
import urllib.parse
import re
import concurrent.futures
from urllib.parse import urlparse, urljoin
from collections import deque
import requests
from bs4 import BeautifulSoup
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('web_crawler')

# Список расширений файлов для поиска
INTERESTING_EXTENSIONS = [
    # Веб-файлы
    'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'jspx', 'do', 'action',
    # Файлы данных
    'xml', 'json', 'csv', 'txt', 'md',
    # Скрипты
    'js', 'py', 'rb', 'sh', 'pl', 'cgi',
    # Стили
    'css', 'scss', 'sass', 'less',
    # Конфигурации
    'conf', 'cfg', 'config', 'ini', 'env', 'yaml', 'yml',
    # Документы
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    # Архивы
    'zip', 'rar', 'tar', 'gz', '7z',
    # Изображения (опционально)
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg',
    # Бэкапы
    'bak', 'backup', 'old', 'tmp', 'temp'
]

# Директории и файлы для проверки (дополнительно к найденным)
COMMON_DIRECTORIES = [
    'admin', 'administrator', 'wp-admin', 'cpanel', 'phpmyadmin',
    'login', 'user', 'users', 'wp-content', 'upload', 'uploads',
    'backup', 'backups', 'data', 'site', 'database', 'db',
    'logs', 'tmp', 'temp', 'dev', 'development', 'test', 'testing',
    'demo', 'examples', 'api', 'apis', 'v1', 'v2', 'v3',
    'console', 'dashboard', 'manage', 'management', 'administration',
    'files', 'download', 'downloads', 'content', 'assets',
    'includes', 'include', 'css', 'js', 'images', 'img', 'static',
    'docs', 'documentation', 'doc', 'config', 'setup'
]

COMMON_FILES = [
    'robots.txt', 'sitemap.xml', '.htaccess', 'config.php', 'wp-config.php',
    'config.inc.php', 'configuration.php', 'settings.php', 'settings.ini',
    'web.config', 'config.json', '.env', '.git/HEAD', '.gitignore',
    'readme.md', 'README.md', 'LICENSE', 'CHANGELOG', 'phpinfo.php',
    'info.php', 'test.php', 'admin.php', 'login.php', 'portal.php',
    'version.txt', 'package.json', 'composer.json', 'Gemfile',
    'requirements.txt', 'error_log', 'error.log', 'access.log',
    'server-status', 'server-info', 'crossdomain.xml', 'clientaccesspolicy.xml'
]

# Заголовки для запросов
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'DNT': '1',
}

class WebCrawler:
    """Класс для автоматического обхода веб-сайтов, поиска файлов и директорий."""
    
    def __init__(self, base_url, max_urls=1000, max_depth=3, delay=0.5, 
                 respect_robots=True, thread_count=5, timeout=10, 
                 cookies=None, headers=None, proxy=None, follow_subdomain=False):
        """
        Инициализация краулера.
        
        Args:
            base_url (str): Базовый URL для сканирования
            max_urls (int): Максимальное количество URL для сканирования
            max_depth (int): Максимальная глубина обхода
            delay (float): Задержка между запросами в секундах
            respect_robots (bool): Учитывать robots.txt
            thread_count (int): Количество потоков для параллельного сканирования
            timeout (int): Таймаут запросов в секундах
            cookies (dict): Куки для запросов
            headers (dict): Заголовки для запросов
            proxy (dict): Прокси для запросов
            follow_subdomain (bool): Следовать по ссылкам на поддомены
        """
        self.base_url = base_url
        self.max_urls = max_urls
        self.max_depth = max_depth
        self.delay = delay
        self.respect_robots = respect_robots
        self.thread_count = thread_count
        self.timeout = timeout
        self.cookies = cookies
        self.headers = headers or DEFAULT_HEADERS
        self.proxy = proxy
        self.follow_subdomain = follow_subdomain
        
        # Функция обратного вызова для отслеживания прогресса
        self.page_callback = None
        
        # Получаем домен из базового URL
        parsed_url = urlparse(base_url)
        self.base_domain = parsed_url.netloc
        self.base_scheme = parsed_url.scheme
        
        # Очереди и множества для отслеживания
        self.urls_to_crawl = deque()  # Очередь URL для обхода
        self.urls_crawled = set()     # Множество обработанных URL
        self.urls_discovered = set()  # Множество всех найденных URL
        self.files_discovered = set() # Множество найденных файлов
        self.dirs_discovered = set()  # Множество найденных директорий
        self.disallowed_urls = set()  # Множество запрещенных URL из robots.txt
        
        # Результаты сканирования
        self.results = {
            'pages': [],      # Список страниц
            'files': [],      # Список файлов
            'directories': [] # Список директорий
        }
        
        # Инициализация сессии
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.cookies:
            self.session.cookies.update(self.cookies)
        if self.proxy:
            self.session.proxies.update(self.proxy)
        
        # Загрузка robots.txt, если требуется
        if self.respect_robots:
            self._load_robots_txt()
    
    def _load_robots_txt(self):
        """Загружает и обрабатывает robots.txt, если он доступен."""
        robots_url = f"{self.base_scheme}://{self.base_domain}/robots.txt"
        try:
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                logger.info(f"Загружен robots.txt с {robots_url}")
                lines = response.text.splitlines()
                for line in lines:
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed_url = f"{self.base_scheme}://{self.base_domain}{path}"
                            self.disallowed_urls.add(disallowed_url)
                logger.info(f"Найдено {len(self.disallowed_urls)} запрещенных URL в robots.txt")
        except Exception as e:
            logger.warning(f"Не удалось загрузить robots.txt: {e}")
    
    def _is_valid_url(self, url):
        """Проверяет, является ли URL допустимым для сканирования."""
        # Проверка на None или пустую строку
        if not url:
            return False
        
        # Исключаем URL с фрагментами
        if '#' in url:
            url = url.split('#')[0]
        
        # Исключаем некоторые типы URL
        if (url.startswith('javascript:') or url.startswith('mailto:') 
                or url.startswith('tel:') or url.startswith('data:')):
            return False
        
        # Проверяем, принадлежит ли URL к базовому домену
        try:
            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                return True  # Относительный URL
            
            # Проверка поддоменов
            if self.follow_subdomain:
                return self.base_domain in parsed_url.netloc
            else:
                return parsed_url.netloc == self.base_domain
        except:
            return False
    
    def _is_allowed_url(self, url):
        """Проверяет, разрешен ли URL для сканирования согласно robots.txt."""
        if not self.respect_robots:
            return True
        
        for disallowed_url in self.disallowed_urls:
            if url.startswith(disallowed_url):
                return False
        
        return True
    
    def _normalize_url(self, url, base_url=None):
        """Нормализует URL, объединяя его с базовым, если это относительный URL."""
        if not base_url:
            base_url = self.base_url
        
        # Удаляем фрагменты
        if '#' in url:
            url = url.split('#')[0]
        
        # Объединяем с базовым URL, если это относительный путь
        full_url = urljoin(base_url, url)
        
        # Удаляем параметры, если они не важны для идентификации ресурса
        # parsed_url = urlparse(full_url)
        # return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        return full_url
    
    def _get_page(self, url, depth=0):
        """
        Получает содержимое страницы и извлекает из нее ссылки.
        
        Args:
            url (str): URL для получения
            depth (int): Текущая глубина обхода
            
        Returns:
            dict: Информация о странице
        """
        # Проверяем, был ли URL уже обработан
        if url in self.urls_crawled:
            return None
        
        # Проверяем, не превышена ли максимальная глубина
        if depth > self.max_depth:
            return None
        
        # Проверяем, разрешен ли URL
        if not self._is_allowed_url(url):
            logger.info(f"URL {url} запрещен согласно robots.txt")
            return None
        
        # Добавляем URL в множество обработанных
        self.urls_crawled.add(url)
        
        # Вызываем функцию обратного вызова, если она определена
        if self.page_callback:
            # Если колбэк вернул False, останавливаем обработку этого URL
            if not self.page_callback(url):
                return None
        
        try:
            # Добавляем задержку для предотвращения перегрузки сервера
            time.sleep(self.delay + random.uniform(0, 0.2))
            
            # Отправляем запрос на получение страницы
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Если это не HTML-страница, считаем ее файлом
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
                self.files_discovered.add(url)
                self.results['files'].append({
                    'url': url,
                    'content_type': content_type,
                    'status_code': response.status_code,
                    'size': len(response.content)
                })
                return None
            
            # Сохраняем информацию о странице
            page_info = {
                'url': url,
                'status_code': response.status_code,
                'content_type': content_type,
                'title': None,
                'headers': dict(response.headers),
                'size': len(response.content)
            }
            
            # Если ответ не успешный, не обрабатываем дальше
            if response.status_code != 200:
                self.results['pages'].append(page_info)
                return None
            
            # Парсим HTML для извлечения ссылок
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Получаем заголовок страницы
            title_tag = soup.find('title')
            if title_tag:
                page_info['title'] = title_tag.text.strip()
            
            # Добавляем информацию о странице в результаты
            self.results['pages'].append(page_info)
            
            # Извлекаем ссылки
            links = []
            for link in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe'], href=True) + \
                      soup.find_all(['script', 'img', 'iframe', 'source', 'embed'], src=True) + \
                      soup.find_all('form', action=True):
                
                # Получаем атрибут с URL
                link_url = None
                if link.has_attr('href'):
                    link_url = link['href']
                elif link.has_attr('src'):
                    link_url = link['src']
                elif link.has_attr('action'):
                    link_url = link['action']
                
                if link_url:
                    links.append(link_url)
            
            # Обрабатываем найденные ссылки
            for link in links:
                if not link:
                    continue
                
                # Нормализуем URL
                full_url = self._normalize_url(link, url)
                
                # Если URL уже обнаружен, пропускаем
                if full_url in self.urls_discovered:
                    continue
                
                # Проверяем, является ли URL допустимым
                if not self._is_valid_url(full_url):
                    continue
                
                # Добавляем URL в множество обнаруженных
                self.urls_discovered.add(full_url)
                
                # Проверяем, является ли URL файлом
                parsed_url = urlparse(full_url)
                path = parsed_url.path
                
                # Извлекаем директорию из пути
                dir_path = path.rsplit('/', 1)[0] if '/' in path else '/'
                if dir_path:
                    dir_url = f"{parsed_url.scheme}://{parsed_url.netloc}{dir_path}"
                    if dir_url not in self.dirs_discovered:
                        self.dirs_discovered.add(dir_url)
                        self.results['directories'].append({
                            'url': dir_url,
                            'path': dir_path,
                            'source': url
                        })
                
                # Проверяем расширение файла
                if '.' in path.split('/')[-1]:
                    ext = path.split('.')[-1].lower()
                    if ext in INTERESTING_EXTENSIONS:
                        self.files_discovered.add(full_url)
                        self.results['files'].append({
                            'url': full_url,
                            'extension': ext,
                            'path': path,
                            'source': url
                        })
                        continue
                
                # Добавляем URL в очередь для обхода
                if len(self.urls_crawled) < self.max_urls:
                    self.urls_to_crawl.append((full_url, depth + 1))
            
            return page_info
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Ошибка при получении {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Неожиданная ошибка при обработке {url}: {e}")
            return None
    
    def _check_common_paths(self):
        """Проверяет наличие общих файлов и директорий."""
        logger.info("Проверка общих файлов и директорий...")
        
        # Создаем список задач для проверки
        tasks = []
        
        # Добавляем общие файлы
        for file in COMMON_FILES:
            file_url = f"{self.base_scheme}://{self.base_domain}/{file}"
            if file_url not in self.urls_discovered:
                tasks.append(file_url)
        
        # Добавляем общие директории
        for directory in COMMON_DIRECTORIES:
            dir_url = f"{self.base_scheme}://{self.base_domain}/{directory}/"
            if dir_url not in self.urls_discovered:
                tasks.append(dir_url)
        
        # Проверяем наличие файлов и директорий
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            futures = [executor.submit(self._check_path_exists, task) for task in tasks]
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        url, status_code = result
                        # Определяем, это файл или директория
                        parsed_url = urlparse(url)
                        path = parsed_url.path
                        
                        if path.endswith('/'):
                            # Это директория
                            if url not in self.dirs_discovered:
                                self.dirs_discovered.add(url)
                                self.results['directories'].append({
                                    'url': url,
                                    'path': path,
                                    'status_code': status_code,
                                    'source': 'common_check'
                                })
                        else:
                            # Это файл
                            if url not in self.files_discovered:
                                self.files_discovered.add(url)
                                ext = path.split('.')[-1].lower() if '.' in path else ''
                                self.results['files'].append({
                                    'url': url,
                                    'extension': ext,
                                    'path': path,
                                    'status_code': status_code,
                                    'source': 'common_check'
                                })
                except Exception as e:
                    logger.error(f"Ошибка при проверке общего пути: {e}")
    
    def _check_path_exists(self, url):
        """Проверяет существование пути по URL."""
        try:
            # Добавляем задержку для предотвращения перегрузки сервера
            time.sleep(self.delay + random.uniform(0, 0.2))
            
            # Отправляем HEAD-запрос для экономии трафика
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            
            # Если получили код 200 или 403 (доступ запрещен), значит ресурс существует
            if response.status_code in [200, 403]:
                logger.info(f"Найден ресурс: {url} (код {response.status_code})")
                return url, response.status_code
            
            # Если получили 301 или 302, проверяем редирект
            elif response.status_code in [301, 302] and 'Location' in response.headers:
                redirect_url = response.headers['Location']
                # Если редирект относительный, преобразуем его в абсолютный
                if not redirect_url.startswith('http'):
                    redirect_url = urljoin(url, redirect_url)
                
                # Проверяем, находится ли редирект в том же домене
                if self._is_valid_url(redirect_url):
                    logger.info(f"Найден редирект: {url} -> {redirect_url}")
                    return url, response.status_code
            
            return None
        except requests.exceptions.RequestException:
            return None
    
    def crawl(self):
        """Запускает процесс сканирования сайта."""
        logger.info(f"Начало сканирования сайта: {self.base_url}")
        
        # Добавляем базовый URL в очередь
        self.urls_to_crawl.append((self.base_url, 0))
        self.urls_discovered.add(self.base_url)
        
        # Обходим сайт, пока есть URL в очереди и не достигнут лимит
        while self.urls_to_crawl and len(self.urls_crawled) < self.max_urls:
            # Запускаем параллельное сканирование
            batch_size = min(self.thread_count, len(self.urls_to_crawl))
            batch = []
            
            for _ in range(batch_size):
                if not self.urls_to_crawl:
                    break
                batch.append(self.urls_to_crawl.popleft())
            
            # Обрабатываем батч URL параллельно
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = [executor.submit(self._get_page, url, depth) for url, depth in batch]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Ошибка при обработке URL: {e}")
        
        # Проверяем общие файлы и директории
        self._check_common_paths()
        
        logger.info("Сканирование завершено")
        logger.info(f"Обработано URL: {len(self.urls_crawled)}")
        logger.info(f"Найдено страниц: {len(self.results['pages'])}")
        logger.info(f"Найдено файлов: {len(self.results['files'])}")
        logger.info(f"Найдено директорий: {len(self.results['directories'])}")
        
        return self.results

# Функция для запуска краулера с параметрами по умолчанию
def crawl_website(url, **kwargs):
    """
    Запускает сканирование веб-сайта.
    
    Args:
        url (str): URL сайта для сканирования
        **kwargs: Дополнительные параметры для краулера
    
    Returns:
        dict: Результаты сканирования
    """
    crawler = WebCrawler(url, **kwargs)
    return crawler.crawl()

# Если файл запущен напрямую, выполняем тестовое сканирование
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        print(f"Начало сканирования: {target_url}")
        
        results = crawl_website(
            target_url,
            max_urls=100,
            max_depth=2,
            delay=0.5,
            thread_count=5
        )
        
        # Выводим результаты
        print(f"Найдено страниц: {len(results['pages'])}")
        print(f"Найдено файлов: {len(results['files'])}")
        print(f"Найдено директорий: {len(results['directories'])}")
        
        # Сохраняем результаты в файл
        with open('crawler_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print("Результаты сохранены в файл crawler_results.json")
    else:
        print("Укажите URL для сканирования. Пример: python web_crawler.py https://example.com") 