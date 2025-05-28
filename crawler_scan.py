#!/usr/bin/env python3
import json
import argparse
import logging
import datetime
import os
from web_crawler import WebCrawler
from ml_models.predictor import predict_vulnerabilities

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('crawler_scan')

class CrawlerScanner:
    """Класс для интеграции веб-краулера и сканера уязвимостей."""
    
    def __init__(self, base_url, max_urls=200, max_depth=3, delay=0.5, 
                 thread_count=10, timeout=10, cookies=None, headers=None,
                 follow_subdomain=False, respect_robots=True,
                 progress_callback=None, scan_progress_callback=None):
        """
        Инициализация сканера.
        
        Args:
            base_url (str): URL для сканирования
            max_urls (int): Максимальное количество URL для обхода
            max_depth (int): Максимальная глубина обхода
            delay (float): Задержка между запросами
            thread_count (int): Количество потоков для краулера
            timeout (int): Таймаут для запросов
            cookies (dict): Куки для запросов
            headers (dict): Заголовки для запросов
            follow_subdomain (bool): Сканировать поддомены
            respect_robots (bool): Учитывать robots.txt
            progress_callback (function): Функция обратного вызова для обновления прогресса краулинга
            scan_progress_callback (function): Функция обратного вызова для обновления прогресса сканирования
        """
        self.base_url = base_url
        self.max_urls = max_urls
        self.max_depth = max_depth
        self.delay = delay
        self.thread_count = thread_count
        self.timeout = timeout
        self.cookies = cookies
        self.headers = headers
        self.follow_subdomain = follow_subdomain
        self.respect_robots = respect_robots
        
        # Функции обратного вызова для обновления прогресса
        self.progress_callback = progress_callback
        self.scan_progress_callback = scan_progress_callback
        
        # Результаты сканирования
        self.crawler_results = None
        self.vulnerability_results = []
        
    def crawl(self):
        """Запускает краулер для обхода сайта."""
        logger.info(f"Запуск обхода сайта: {self.base_url}")
        
        # Создаем обертку для отслеживания прогресса
        original_crawl_method = WebCrawler.crawl
        
        # Переопределяем метод crawl для отслеживания прогресса
        def crawl_with_progress(self_crawler):
            total_processed = 0
            max_urls = self_crawler.max_urls
            
            # Создаем подсчет для отображения прогресса
            def progress_tracker(url):
                nonlocal total_processed
                total_processed += 1
                percent = min(int((total_processed / max_urls) * 100), 100)
                
                # Вызываем функцию обратного вызова, если она определена
                if self.progress_callback:
                    self.progress_callback(percent)
                    
                # Возвращаем True, чтобы продолжить краулинг
                return True
            
            # Добавляем трекер прогресса в WebCrawler
            self_crawler.page_callback = progress_tracker
            
            # Вызываем оригинальный метод
            return original_crawl_method(self_crawler)
        
        # Временно заменяем метод
        WebCrawler.crawl = crawl_with_progress
        
        try:
            crawler = WebCrawler(
                self.base_url,
                max_urls=self.max_urls,
                max_depth=self.max_depth,
                delay=self.delay,
                thread_count=self.thread_count,
                timeout=self.timeout,
                cookies=self.cookies,
                headers=self.headers,
                follow_subdomain=self.follow_subdomain,
                respect_robots=self.respect_robots
            )
            
            self.crawler_results = crawler.crawl()
        finally:
            # Восстанавливаем оригинальный метод
            WebCrawler.crawl = original_crawl_method
        
        logger.info(f"Обход сайта завершен. Найдено {len(self.crawler_results['pages'])} страниц, "
                   f"{len(self.crawler_results['files'])} файлов, "
                   f"{len(self.crawler_results['directories'])} директорий.")
        
        # Финальное обновление прогресса
        if self.progress_callback:
            self.progress_callback(100)
        
        return self.crawler_results
    
    def scan_vulnerabilities(self):
        """Сканирует найденные URL на наличие уязвимостей."""
        if not self.crawler_results:
            logger.error("Невозможно запустить сканирование уязвимостей: обход сайта не выполнен.")
            return []
        
        logger.info("Начало сканирования уязвимостей...")
        
        # Объединяем все найденные страницы и файлы для сканирования
        pages_to_scan = self.crawler_results['pages']
        files_to_scan = [f for f in self.crawler_results['files'] 
                          if f.get('status_code') == 200 and 'content_type' in f]
        
        total_to_scan = len(pages_to_scan) + len(files_to_scan)
        logger.info(f"Найдено {total_to_scan} ресурсов для сканирования")
        
        processed_count = 0
        
        # Сканируем страницы
        for i, page in enumerate(pages_to_scan):
            logger.info(f"Сканирование страницы {i+1}/{len(pages_to_scan)}: {page['url']}")
            
            # Обновляем прогресс
            processed_count += 1
            if self.scan_progress_callback:
                progress = min(int((processed_count / total_to_scan) * 100), 100)
                self.scan_progress_callback(progress)
            
            # Подготавливаем данные для сканера
            site_data = {
                "url": page['url'],
                "content": self._get_content(page['url']),
                "headers": page.get('headers', {})
            }
            
            # Запускаем сканирование
            vulnerabilities = predict_vulnerabilities(site_data)
            
            if vulnerabilities:
                # Добавляем результаты в общий список
                for vuln in vulnerabilities:
                    vuln['page_url'] = page['url']
                    vuln['page_title'] = page.get('title', 'Без заголовка')
                
                self.vulnerability_results.extend(vulnerabilities)
                logger.info(f"Найдено {len(vulnerabilities)} уязвимостей на странице {page['url']}")
            else:
                logger.info(f"Уязвимости не найдены на странице {page['url']}")
        
        # Сканируем файлы (только определенные типы)
        scan_file_types = ['text/html', 'text/plain', 'application/json', 'application/xml', 
                           'application/javascript', 'text/css', 'text/xml']
        
        files_to_scan_filtered = [f for f in files_to_scan 
                                  if any(ft in f.get('content_type', '') for ft in scan_file_types)]
        
        for i, file in enumerate(files_to_scan_filtered):
            logger.info(f"Сканирование файла {i+1}/{len(files_to_scan_filtered)}: {file['url']}")
            
            # Обновляем прогресс
            processed_count += 1
            if self.scan_progress_callback:
                progress = min(int((processed_count / total_to_scan) * 100), 100)
                self.scan_progress_callback(progress)
            
            # Подготавливаем данные для сканера
            site_data = {
                "url": file['url'],
                "content": self._get_content(file['url']),
                "headers": file.get('headers', {})
            }
            
            # Запускаем сканирование
            vulnerabilities = predict_vulnerabilities(site_data)
            
            if vulnerabilities:
                # Добавляем результаты в общий список
                for vuln in vulnerabilities:
                    vuln['page_url'] = file['url']
                    vuln['page_title'] = os.path.basename(file['url'])
                
                self.vulnerability_results.extend(vulnerabilities)
                logger.info(f"Найдено {len(vulnerabilities)} уязвимостей в файле {file['url']}")
            else:
                logger.info(f"Уязвимости не найдены в файле {file['url']}")
        
        logger.info(f"Сканирование завершено. Найдено {len(self.vulnerability_results)} уязвимостей.")
        
        # Финальное обновление прогресса
        if self.scan_progress_callback:
            self.scan_progress_callback(100)
        
        return self.vulnerability_results
    
    def _get_content(self, url):
        """Получает содержимое страницы или файла."""
        try:
            import requests
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
            else:
                logger.warning(f"Не удалось получить содержимое {url}, код ответа: {response.status_code}")
                return ""
        except Exception as e:
            logger.error(f"Ошибка при получении содержимого {url}: {e}")
            return ""
    
    def save_results(self, output_dir="."):
        """Сохраняет результаты сканирования в файлы."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Создаем директорию для результатов, если она не существует
        os.makedirs(output_dir, exist_ok=True)
        
        # Формируем имена файлов
        crawler_filename = os.path.join(output_dir, f"crawler_results_{timestamp}.json")
        vulns_filename = os.path.join(output_dir, f"vulnerability_results_{timestamp}.json")
        
        # Сохраняем результаты краулера
        if self.crawler_results:
            with open(crawler_filename, 'w', encoding='utf-8') as f:
                json.dump(self.crawler_results, f, indent=2, ensure_ascii=False)
            logger.info(f"Результаты обхода сохранены в {crawler_filename}")
        
        # Сохраняем результаты сканирования уязвимостей
        if self.vulnerability_results:
            with open(vulns_filename, 'w', encoding='utf-8') as f:
                json.dump(self.vulnerability_results, f, indent=2, ensure_ascii=False)
            logger.info(f"Результаты сканирования уязвимостей сохранены в {vulns_filename}")
        
        return crawler_filename, vulns_filename
    
    def run_full_scan(self, output_dir="."):
        """Запускает полный процесс сканирования: обход сайта и поиск уязвимостей."""
        # Запускаем краулер
        self.crawl()
        
        # Сканируем на уязвимости
        self.scan_vulnerabilities()
        
        # Сохраняем результаты
        return self.save_results(output_dir)

def main():
    """Основная функция для запуска из командной строки."""
    parser = argparse.ArgumentParser(description='Веб-краулер и сканер уязвимостей')
    parser.add_argument('url', help='URL для сканирования')
    parser.add_argument('--max-urls', type=int, default=200, help='Максимальное количество URL для обхода')
    parser.add_argument('--max-depth', type=int, default=3, help='Максимальная глубина обхода')
    parser.add_argument('--delay', type=float, default=0.5, help='Задержка между запросами в секундах')
    parser.add_argument('--threads', type=int, default=10, help='Количество потоков для краулера')
    parser.add_argument('--timeout', type=int, default=10, help='Таймаут для запросов в секундах')
    parser.add_argument('--follow-subdomains', action='store_true', help='Сканировать поддомены')
    parser.add_argument('--ignore-robots', action='store_true', help='Игнорировать robots.txt')
    parser.add_argument('--output-dir', default='./scan_results', help='Директория для сохранения результатов')
    
    args = parser.parse_args()
    
    # Создаем и запускаем сканер
    scanner = CrawlerScanner(
        args.url,
        max_urls=args.max_urls,
        max_depth=args.max_depth,
        delay=args.delay,
        thread_count=args.threads,
        timeout=args.timeout,
        follow_subdomain=args.follow_subdomains,
        respect_robots=not args.ignore_robots
    )
    
    # Запускаем полное сканирование
    crawler_file, vulns_file = scanner.run_full_scan(args.output_dir)
    
    print(f"\nСканирование завершено!")
    print(f"Обработано URL: {len(scanner.crawler_results['pages']) + len(scanner.crawler_results['files'])}")
    print(f"Найдено уязвимостей: {len(scanner.vulnerability_results)}")
    print(f"\nРезультаты обхода: {crawler_file}")
    print(f"Результаты сканирования уязвимостей: {vulns_file}")

if __name__ == "__main__":
    main() 