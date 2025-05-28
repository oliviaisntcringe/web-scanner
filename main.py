import os
import sys
import time
import asyncio
import argparse
import logging
from datetime import datetime
from urllib.parse import urlparse
import json

# Import components
from ml_models.predictor import predict_vulnerabilities
from crawler.crawler import crawl_site  # Импортируем существующий краулер
from bot.bot import run_bot
# Future imports (when implemented):
# from report_generator import ReportGenerator

# Добавляем импорт нашего веб-краулера
from crawler_scan import CrawlerScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    ]
)
logger = logging.getLogger('web_scanner')

class WebScanner:
    """
    Main web vulnerability scanner class that coordinates all components
    """
    def __init__(self, config=None):
        """Initialize the scanner with optional configuration"""
        self.config = config or {}
        self.targets = []
        self.results = {}
        
        # Initialize ML predictor
        self.predictor = predict_vulnerabilities
        
        # Crawler settings (можно настраивать через config)
        self.crawler_max_depth = self.config.get('crawler_max_depth', 2)
        self.crawler_user_agent = self.config.get('crawler_user_agent', 
                                                "Mozilla/5.0 (compatible; WebVulnerabilityScanner/1.0)")
        self.crawler_delay = self.config.get('crawler_delay', 0.1)
        
        logger.info("Web vulnerability scanner initialized")

    def validate_target(self, target):
        """
        Validate and normalize the target URL/IP
        Returns a normalized URL or raises ValueError
        """
        # Add http:// if protocol is missing
        if not target.startswith(('http://', 'https://')):
            # Simple check if it could be an IP address
            if all(part.isdigit() and 0 <= int(part) <= 255 
                  for part in target.split('.') if part.isdigit()):
                target = f"http://{target}"
            else:
                # Try to determine if it's a domain
                if '.' in target and not target.startswith('//'):
                    target = f"http://{target}"
                else:
                    raise ValueError(f"Invalid target format: {target}")
        
        # Validate URL format
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                raise ValueError(f"Invalid URL: {target}")
            return target
        except Exception as e:
            raise ValueError(f"Failed to parse target URL {target}: {str(e)}")

    async def crawl_target(self, target):
        """
        Crawl the target website to discover pages and endpoints
        """
        logger.info(f"Crawling target: {target}")
        
        # Используем существующую функцию crawl_site, запуская её в отдельном потоке,
        # чтобы не блокировать асинхронный event loop
        crawled_data = await asyncio.to_thread(
            crawl_site, 
            target, 
            max_depth=self.crawler_max_depth,
            user_agent=self.crawler_user_agent,
            delay=self.crawler_delay
        )
        
        # Преобразуем данные краулера в формат, понятный для анализатора
        pages = []
        for page_data in crawled_data:
            # Извлекаем основные данные о странице
            url = page_data['url']
            content_type = page_data.get('content_type', 'text/html')
            
            # Обрабатываем формы на странице
            for form in page_data.get('forms', []):
                form_data = {
                    "url": form['action'],
                    "method": form['method'].upper(),
                    "params": {},
                    "content_type": "application/x-www-form-urlencoded",
                    "form_data": True,
                    "page_content": page_data.get('content', ''),
                    "headers": page_data.get('headers', {})
                }
                
                # Собираем параметры формы
                for input_field in form.get('inputs', []):
                    if input_field.get('name'):
                        form_data["params"][input_field['name']] = input_field.get('value', '')
                
                pages.append(form_data)
            
            # Обрабатываем и добавляем саму страницу (GET-запрос)
            page = {
                "url": url,
                "method": "GET",
                "params": {},
                "content_type": content_type,
                "page_content": page_data.get('content', ''),
                "links": page_data.get('links_on_page', []),
                "headers": page_data.get('headers', {})
            }
            pages.append(page)
            
            # Обрабатываем статические ресурсы
            for resource in page_data.get('static_resources', []):
                resource_data = {
                    "url": resource['url'],
                    "method": "GET",
                    "params": {},
                    "content_type": f"application/{resource['type']}",
                    "is_static": True
                }
                pages.append(resource_data)
        
        logger.info(f"Crawling completed. Found {len(pages)} pages/endpoints/forms")
        return pages

    async def analyze_page(self, page_data):
        """
        Analyze a single page/endpoint for vulnerabilities
        """
        logger.info(f"Analyzing page: {page_data['url']}")
        
        # This would pass the page data to the ML predictor
        vulnerabilities = self.predictor(page_data)
        
        # Additional processing for the results
        for vuln in vulnerabilities:
            # Add timestamp
            vuln['timestamp'] = datetime.now().isoformat()
            
            # Add target information
            vuln['target_url'] = page_data['url']
            vuln['request_method'] = page_data.get('method', 'GET')
            
            # If no severity provided by the detector, assign default
            if 'severity' not in vuln:
                vuln['severity'] = 'medium'  # Default severity
        
        return vulnerabilities

    async def scan_target(self, target):
        """
        Full scan of a target - crawling and vulnerability detection
        """
        logger.info(f"Starting scan for target: {target}")
        start_time = time.time()
        
        try:
            normalized_target = self.validate_target(target)
            
            # Step 1: Crawl the website
            pages = await self.crawl_target(normalized_target)
            logger.info(f"Found {len(pages)} pages/endpoints")
            
            # Step 2: Analyze each page for vulnerabilities
            all_vulnerabilities = []
            for page in pages:
                page_vulns = await self.analyze_page(page)
                all_vulnerabilities.extend(page_vulns)
            
            # Record results
            scan_duration = time.time() - start_time
            scan_result = {
                'target': normalized_target,
                'scan_time': scan_duration,
                'pages_analyzed': len(pages),
                'vulnerabilities': all_vulnerabilities,
                'timestamp': datetime.now().isoformat(),
                'vulnerability_count': len(all_vulnerabilities)
            }
            
            self.results[normalized_target] = scan_result
            logger.info(f"Scan completed for {normalized_target}. Found {len(all_vulnerabilities)} vulnerabilities in {scan_duration:.2f} seconds")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning target {target}: {str(e)}")
            raise

    async def check_exploitable(self, target):
        """
        Check target for exploitable vulnerabilities and provide exploit details
        """
        logger.info(f"Checking exploitable vulnerabilities for: {target}")
        
        # First do a normal scan
        scan_result = await self.scan_target(target)
        
        # Filter and enhance vulnerabilities that are exploitable
        exploitable_vulns = []
        for vuln in scan_result['vulnerabilities']:
            # Check if the vulnerability is likely exploitable
            # This would involve more complex logic in a real implementation
            if vuln['severity'] == 'high':
                # Add exploit details for high severity findings
                if 'A01' in vuln['type']:  # Broken Access Control
                    vuln['exploit_details'] = f"curl -X GET {vuln['target_url']} -H 'X-Custom-IP-Authorization: 127.0.0.1'"
                    exploitable_vulns.append(vuln)
                
                elif 'A03' in vuln['type'] and 'SQL' in vuln['type']:  # SQL Injection
                    vuln['exploit_details'] = f"curl -X {vuln['request_method']} {vuln['target_url']} -d 'username=admin%27%20OR%201%3D1--%20&password=anything'"
                    exploitable_vulns.append(vuln)
                
                elif 'A03' in vuln['type'] and 'XSS' in vuln['type']:  # XSS
                    vuln['exploit_details'] = f"curl -X GET {vuln['target_url']} -d 'q=%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E'"
                    exploitable_vulns.append(vuln)
                
                elif 'A07' in vuln['type']:  # Injection
                    vuln['exploit_details'] = f"curl -X GET {vuln['target_url']} -d 'cmd=cat%20/etc/passwd'"
                    exploitable_vulns.append(vuln)
        
        # Create result with only exploitable vulnerabilities
        exploit_result = {
            'target': scan_result['target'],
            'scan_time': scan_result['scan_time'],
            'vulnerabilities': exploitable_vulns,
            'timestamp': datetime.now().isoformat(),
            'vulnerability_count': len(exploitable_vulns)
        }
        
        logger.info(f"Exploit check completed. Found {len(exploitable_vulns)} exploitable vulnerabilities")
        return exploit_result

# Импортируем run_bot после определения всех классов и функций
def run_bot():
    """Импортируем функцию запуска бота"""
    try:
        from bot.bot import run_bot as start_bot
        start_bot()
    except Exception as e:
        logger.error(f"Error starting bot: {e}")
        print(f"Failed to start Telegram bot: {e}")
        print("Please check your internet connection and bot token.")

# Асинхронная функция для сканирования одного URL
async def full_scan_pipeline(target_url, exploit_mode=False):
    """
    Основная функция сканирования, которая запускает процесс анализа уязвимостей.
    
    Args:
        target_url (str): URL для сканирования
        exploit_mode (bool): Режим проверки на эксплуатируемые уязвимости
        
    Returns:
        list: Список найденных уязвимостей
    """
    # Формируем данные для сканирования
    try:
        import requests
        response = requests.get(target_url, timeout=10)
        site_data = {
            "url": target_url,
            "content": response.text,
            "headers": dict(response.headers)
        }
        
        # Запускаем сканирование
        vulnerabilities = predict_vulnerabilities(site_data)
        
        # В режиме эксплойта добавляем детали об эксплуатации
        if exploit_mode and vulnerabilities:
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
        
        return vulnerabilities
    except Exception as e:
        logger.error(f"Error during scanning: {e}")
        return []

async def main_async():
    """Async main function"""
    args = parse_arguments()
    
    # Настраиваем логгер
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Создаем базовую конфигурацию для сканера
    config = {
        'crawler_max_depth': args.depth,
        'crawler_delay': args.delay,
        'verbose': args.verbose
    }
    
    # Если указан параметр --target, выполняем сканирование
    if args.target:
        try:
            # Проверяем, нужно ли запустить веб-краулер
            if args.crawl:
                logger.info(f"Starting web crawler on {args.target}")
                
                # Создаем сканер с параметрами командной строки
                crawler_scanner = CrawlerScanner(
                    args.target,
                    max_urls=args.max_urls,
                    max_depth=args.depth,
                    delay=args.delay,
                    thread_count=args.threads,
                    follow_subdomain=args.follow_subdomains,
                    respect_robots=not args.ignore_robots
                )
                
                # Запускаем полное сканирование
                crawler_file, vulns_file = crawler_scanner.run_full_scan("scan_results")
                
                # Выводим результаты
                print(f"\nCrawling and scanning completed!")
                print(f"Pages processed: {len(crawler_scanner.crawler_results['pages'])}")
                print(f"Files discovered: {len(crawler_scanner.crawler_results['files'])}")
                print(f"Directories found: {len(crawler_scanner.crawler_results['directories'])}")
                print(f"Vulnerabilities found: {len(crawler_scanner.vulnerability_results)}")
                print(f"\nCrawl results saved to: {crawler_file}")
                print(f"Vulnerability results saved to: {vulns_file}")
                
                # Если задан --output, сохраняем результаты в указанный файл
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(crawler_scanner.vulnerability_results, f, indent=2, ensure_ascii=False)
                    print(f"Results also saved to: {args.output}")
            else:
                # Обычное сканирование одного URL
                logger.info(f"Starting scan on {args.target}")
                results = await full_scan_pipeline(args.target, exploit_mode=args.exploit)
                
                if results:
                    print(f"\nFound {len(results)} potential vulnerabilities:")
                    for i, vuln in enumerate(results, 1):
                        print(f"{i}. {vuln['type']}: {vuln['details']}")
                        if 'severity' in vuln:
                            print(f"   Severity: {vuln['severity']}")
                        if args.exploit and 'exploit_details' in vuln:
                            print(f"   Exploit: {vuln['exploit_details']}")
                        print()
                else:
                    print("No vulnerabilities found.")
                
                # Если задан --output, сохраняем результаты в указанный файл
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2, ensure_ascii=False)
                    print(f"Results saved to: {args.output}")
            
            # Если не указан флаг --no-bot, то запустим бота после CLI-сканирования
            if not args.no_bot:
                logger.info("Starting Telegram bot after scan...")
                run_bot()
                
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            
            # Если была ошибка при сканировании, но не указан флаг --no-bot,
            # всё равно запускаем бота
            if not args.no_bot:
                logger.info("Starting Telegram bot despite scan error...")
                run_bot()
            else:
                sys.exit(1)
    else:
        # Если не указан параметр --target, то просто запускаем бота
        # Это поведение по умолчанию
        if not args.no_bot:
            logger.info("Starting Telegram bot...")
            # Инициализируем сканер, чтобы проверить возможные ошибки при инициализации
            # заранее, а не когда пользователь уже отправит запрос на сканирование
            scanner = WebScanner(config)
            run_bot()
        else:
            # Если указан флаг --no-bot и не указан --target, то выводим справку
            logger.error("No target specified and bot is disabled. Nothing to do.")
            parser = argparse.ArgumentParser()
            parser.print_help()
            sys.exit(1)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner with ML')
    parser.add_argument('--target', '-t', help='Target URL to scan')
    parser.add_argument('--exploit', '-e', action='store_true', help='Check for exploitable vulnerabilities')
    parser.add_argument('--no-bot', action='store_true', help='Do not start the Telegram bot')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--depth', '-d', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests in seconds (default: 0.1)')
    # Добавляем параметры для веб-краулера
    parser.add_argument('--crawl', '-c', action='store_true', help='Crawl the target website')
    parser.add_argument('--max-urls', type=int, default=100, help='Maximum number of URLs to crawl (default: 100)')
    parser.add_argument('--follow-subdomains', action='store_true', help='Follow links to subdomains')
    parser.add_argument('--ignore-robots', action='store_true', help='Ignore robots.txt')
    parser.add_argument('--threads', type=int, default=5, help='Number of crawler threads (default: 5)')
    
    return parser.parse_args()

def main():
    """Main entry point"""
    # Выводим приветственное сообщение
    print("=" * 60)
    print(" Web Vulnerability Scanner with ML".center(60))
    print(" Telegram Bot Edition".center(60))
    print("=" * 60)
    print(" Type Ctrl+C to exit".center(60))
    print("=" * 60)
    
    try:
        # Run the async main function
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nScanner stopped by user")
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 