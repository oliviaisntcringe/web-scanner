import os
import json
import re
import time
import requests
from typing import Dict, List, Tuple, Any, Optional
import logging
import threading
import ipaddress
import socket
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

# Подавляем предупреждения о небезопасных SSL-соединениях
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import nmap  # Пробуем импортировать python-nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("python-nmap не установлен, будет использоваться только HTTP-сканирование")

# Настройка логирования
logger = logging.getLogger("service_scanner")

# Константы
DEFAULT_PORTS = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
VULN_SCRIPTS = "vuln,auth,brute,default,discovery,dos,exploit,external,fuzzer,intrusive,malware,safe,version"

# Порты для HTTP-сканирования
HTTP_PORTS = [80, 81, 443, 800, 801, 8000, 8080, 8081, 8443, 8888, 7001, 7002, 9000, 9001, 9090]

# Известные веб-серверы и их возможные уязвимости
WEB_SERVER_VULNS = {
    "apache": [
        {"name": "Apache Struts", "cve": "CVE-2017-5638", "description": "Remote Code Execution vulnerability in Apache Struts"},
        {"name": "Apache HTTP Server", "cve": "CVE-2021-41773", "description": "Path Traversal vulnerability in Apache HTTP Server"}
    ],
    "nginx": [
        {"name": "Nginx", "cve": "CVE-2019-9511", "description": "HTTP/2 DoS vulnerability in Nginx"},
        {"name": "Nginx", "cve": "CVE-2018-16845", "description": "Vulnerability in Nginx HTTP/2 implementation"}
    ],
    "iis": [
        {"name": "Microsoft IIS", "cve": "CVE-2017-7269", "description": "Buffer overflow in IIS 6.0 WebDAV service"},
        {"name": "Microsoft IIS", "cve": "CVE-2015-1635", "description": "HTTP.sys Remote Code Execution"}
    ],
    "tomcat": [
        {"name": "Apache Tomcat", "cve": "CVE-2020-1938", "description": "AJP Ghostcat vulnerability in Apache Tomcat"},
        {"name": "Apache Tomcat", "cve": "CVE-2019-0232", "description": "Remote Code Execution via CGI Servlet"}
    ],
    "wordpress": [
        {"name": "WordPress", "cve": "CVE-2021-24867", "description": "Cross-Site Scripting (XSS) vulnerability"},
        {"name": "WordPress", "cve": "CVE-2020-36326", "description": "SQL Injection in WordPress plugin"}
    ],
    "joomla": [
        {"name": "Joomla", "cve": "CVE-2023-23752", "description": "Joomla Unauthorized Access vulnerability"},
        {"name": "Joomla", "cve": "CVE-2020-35616", "description": "Improper Authorization in Joomla"}
    ],
    "drupal": [
        {"name": "Drupal", "cve": "CVE-2018-7600", "description": "Drupalgeddon2 Remote Code Execution"},
        {"name": "Drupal", "cve": "CVE-2019-6340", "description": "Remote Code Execution via REST API"}
    ],
    "phpMyAdmin": [
        {"name": "phpMyAdmin", "cve": "CVE-2016-5734", "description": "Remote Code Execution vulnerability"},
        {"name": "phpMyAdmin", "cve": "CVE-2018-12613", "description": "Local File Inclusion vulnerability"}
    ]
}

class ServiceScanner:
    """Класс для сканирования сервисов и поиска уязвимостей"""
    
    def __init__(self, target: str):
        """
        Инициализация сканера сервисов
        
        Args:
            target: IP-адрес или домен для сканирования
        """
        self.target = target
        self.results = {
            "services": [],
            "vulnerabilities": [],
            "exploits": []
        }
        self.scan_time = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.session.verify = False  # Отключаем проверку SSL для тестирования
        
    def validate_target(self) -> bool:
        """Проверяет, что цель сканирования - это валидный IP адрес или домен"""
        try:
            # Пытаемся распарсить как IP
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            # Если не IP, проверяем на домен
            domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')
            if domain_pattern.match(self.target):
                return True
            logger.error(f"Неверный формат IP или домена: {self.target}")
            return False
    
    def run_nmap_scan(self, ports: str = DEFAULT_PORTS, scan_vulns: bool = True) -> Dict:
        """
        Запускает nmap сканирование сервисов и уязвимостей с использованием python-nmap
        
        Args:
            ports: Строка с портами для сканирования (например "80,443,8080")
            scan_vulns: Запускать ли скрипты для поиска уязвимостей
            
        Returns:
            Dict: Результаты сканирования
        """
        if not NMAP_AVAILABLE:
            logger.warning("python-nmap не установлен, используется HTTP-сканирование вместо nmap")
            return {"error": "nmap не доступен на этой системе"}
            
        self.scan_time = time.time()
        
        try:
            # Создаем сканер nmap
            nm = nmap.PortScanner()
            
            # Формируем аргументы для сканирования
            args = '-sV -Pn'  # Определение версий и без пинга
            
            # Если нужно искать уязвимости, добавляем скрипты
            if scan_vulns:
                args += f' --script {VULN_SCRIPTS}'
            
            logger.info(f"Запуск nmap сканирования для {self.target} с аргументами: {args}")
            
            # Запускаем сканирование
            nm.scan(hosts=self.target, ports=ports, arguments=args)
            
            # Обрабатываем результаты
            scan_results = self._parse_nmap_results(nm)
            
            self.scan_time = time.time() - self.scan_time
            logger.info(f"Сканирование nmap завершено за {self.scan_time:.2f} секунд")
            
            return scan_results
            
        except nmap.PortScannerError as e:
            logger.error(f"Ошибка nmap: {e}")
            return {"error": f"Ошибка nmap: {str(e)}"}
        except Exception as e:
            logger.error(f"Ошибка при сканировании: {e}")
            return {"error": f"Ошибка при сканировании: {str(e)}"}
    
    def run_http_scan(self, ports: List[int] = None) -> Dict:
        """
        Запускает HTTP сканирование сервисов и поиск уязвимостей
        
        Args:
            ports: Список портов для сканирования
            
        Returns:
            Dict: Результаты сканирования
        """
        self.scan_time = time.time()
        
        # Если порты не указаны, используем стандартные HTTP порты
        if ports is None:
            ports = HTTP_PORTS
        
        # Если передана строка с портами, преобразуем в список
        if isinstance(ports, str):
            try:
                # Обрабатываем порты вида "80,443,8080-8090"
                port_list = []
                for part in ports.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        port_list.extend(range(start, end + 1))
                    else:
                        port_list.append(int(part))
                ports = port_list
            except Exception as e:
                logger.error(f"Ошибка при парсинге портов: {e}")
                ports = HTTP_PORTS
                
        results = {
            "services": [],
            "vulnerabilities": []
        }
        
        logger.info(f"Запуск HTTP сканирования для {self.target} на портах {ports}")
        
        # Сначала проверяем, открыты ли порты с помощью сокетов
        open_ports = self._check_open_ports(ports)
        logger.info(f"Обнаружено {len(open_ports)} открытых портов: {open_ports}")
        
        # Используем ThreadPoolExecutor для параллельного сканирования
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {
                executor.submit(self._scan_http_port, port): port for port in open_ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_result = future.result()
                    if port_result:
                        if "service" in port_result:
                            results["services"].append(port_result["service"])
                        if "vulnerabilities" in port_result:
                            results["vulnerabilities"].extend(port_result["vulnerabilities"])
                except Exception as e:
                    logger.error(f"Ошибка при сканировании порта {port}: {e}")
        
        self.scan_time = time.time() - self.scan_time
        logger.info(f"HTTP сканирование завершено за {self.scan_time:.2f} секунд")
        
        return results
    
    def _check_open_ports(self, ports: List[int]) -> List[int]:
        """
        Проверяет, открыты ли указанные порты на цели
        
        Args:
            ports: Список портов для проверки
            
        Returns:
            List[int]: Список открытых портов
        """
        open_ports = []
        
        for port in ports:
            try:
                # Создаем сокет
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Таймаут 1 секунда
                
                # Пытаемся подключиться
                result = sock.connect_ex((self.target, port))
                
                # Если результат 0, порт открыт
                if result == 0:
                    open_ports.append(port)
                    
                sock.close()
            except Exception as e:
                logger.debug(f"Ошибка при проверке порта {port}: {e}")
        
        return open_ports
    
    def _scan_http_port(self, port: int) -> Dict:
        """
        Сканирует один порт по HTTP/HTTPS и ищет уязвимости
        
        Args:
            port: Порт для сканирования
            
        Returns:
            Dict: Результаты сканирования порта
        """
        result = {}
        
        # Определяем протокол (http или https)
        protocol = "https" if port == 443 or port == 8443 else "http"
        url = f"{protocol}://{self.target}:{port}"
        
        try:
            # Пытаемся получить ответ от сервера
            response = self.session.get(url, timeout=3)
            
            # Получаем информацию о сервере
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            # Определяем тип сервера и версию
            service_name = "http"
            product = server or powered_by or "Unknown"
            version = ""
            
            # Пытаемся извлечь версию из заголовка Server
            if server:
                version_match = re.search(r'[\d\.]+', server)
                if version_match:
                    version = version_match.group(0)
            
            # Создаем запись о сервисе
            service = {
                "port": str(port),
                "protocol": "tcp",
                "name": service_name,
                "product": product,
                "version": version,
                "extrainfo": f"Status: {response.status_code}"
            }
            
            result["service"] = service
            
            # Ищем потенциальные уязвимости на основе заголовков и содержимого
            vulnerabilities = self._find_http_vulnerabilities(response, port)
            if vulnerabilities:
                result["vulnerabilities"] = vulnerabilities
            
        except requests.RequestException as e:
            logger.debug(f"Ошибка при сканировании {url}: {e}")
        
        return result
    
    def _find_http_vulnerabilities(self, response: requests.Response, port: int) -> List[Dict]:
        """
        Ищет потенциальные уязвимости в HTTP-ответе
        
        Args:
            response: HTTP-ответ
            port: Порт, на котором был получен ответ
            
        Returns:
            List[Dict]: Список найденных уязвимостей
        """
        vulnerabilities = []
        
        # Получаем информацию о сервере
        server = response.headers.get('Server', '').lower()
        x_powered_by = response.headers.get('X-Powered-By', '').lower()
        content = response.text.lower()
        
        # Проверяем заголовки безопасности
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header'
        }
        
        for header, desc in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    "port": str(port),
                    "service": "http",
                    "script_id": "http-security-headers",
                    "output": f"{desc}. This may lead to security issues like clickjacking or MIME-sniffing.",
                    "cve": ""
                })
        
        # Проверяем на наличие информации о сервере и добавляем известные уязвимости
        for server_type, vulns in WEB_SERVER_VULNS.items():
            if server_type in server or server_type in x_powered_by or server_type in content:
                for vuln in vulns:
                    vulnerabilities.append({
                        "port": str(port),
                        "service": "http",
                        "script_id": f"http-vuln-{vuln['name'].lower().replace(' ', '-')}",
                        "output": f"Potential {vuln['name']} vulnerability: {vuln['description']}",
                        "cve": vuln['cve']
                    })
        
        # Проверяем на наличие админ-панелей
        admin_panels = [
            '/admin', '/administrator', '/wp-admin', '/wp-login.php', '/admin.php',
            '/administrator.php', '/login.php', '/backend', '/joomla/administrator',
            '/cms/administrator', '/manager', '/panel', '/cpanel', '/webadmin'
        ]
        
        for panel in admin_panels:
            try:
                panel_url = f"{response.url.rstrip('/')}{panel}"
                panel_resp = self.session.get(panel_url, timeout=2)
                
                # Если страница существует и содержит признаки админ-панели
                if panel_resp.status_code == 200 and ('login' in panel_resp.text.lower() or 'admin' in panel_resp.text.lower()):
                    vulnerabilities.append({
                        "port": str(port),
                        "service": "http",
                        "script_id": "http-admin-panel",
                        "output": f"Admin panel found at {panel_url}",
                        "cve": ""
                    })
            except requests.RequestException:
                pass
        
        return vulnerabilities
    
    def _parse_nmap_results(self, nm_scanner: nmap.PortScanner) -> Dict:
        """
        Парсит результаты nmap из объекта PortScanner
        
        Args:
            nm_scanner: Объект сканера nmap
            
        Returns:
            Dict: Структурированные результаты сканирования
        """
        try:
            results = {
                "services": [],
                "vulnerabilities": []
            }
            
            # Проверяем, что цель была отсканирована
            if self.target not in nm_scanner.all_hosts():
                return {"error": f"Хост {self.target} не был отсканирован"}
            
            # Получаем информацию о хосте
            host_data = nm_scanner[self.target]
            
            # Обрабатываем информацию о портах и сервисах
            if 'tcp' in host_data:
                for port_num, port_info in host_data['tcp'].items():
                    service = {
                        "port": str(port_num),
                        "protocol": "tcp",
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', ''),
                        "version": port_info.get('version', ''),
                        "extrainfo": port_info.get('extrainfo', '')
                    }
                    results["services"].append(service)
                    
                    # Ищем информацию о уязвимостях в скриптах
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            # Ищем уязвимости по ключевым словам в имени скрипта и выводе
                            vuln_keywords = ["vuln", "exploit", "cve", "vulnerability"]
                            if any(keyword in script_name.lower() for keyword in vuln_keywords) or \
                               any(keyword in script_output.lower() for keyword in vuln_keywords):
                                
                                # Пытаемся извлечь CVE
                                cve_match = re.search(r"CVE-\d{4}-\d{4,7}", script_output)
                                cve = cve_match.group(0) if cve_match else ""
                                
                                vulnerability = {
                                    "port": str(port_num),
                                    "service": port_info.get('name', 'unknown'),
                                    "script_id": script_name,
                                    "output": script_output,
                                    "cve": cve
                                }
                                results["vulnerabilities"].append(vulnerability)
            
            # Аналогично для UDP, если есть
            if 'udp' in host_data:
                for port_num, port_info in host_data['udp'].items():
                    service = {
                        "port": str(port_num),
                        "protocol": "udp",
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', ''),
                        "version": port_info.get('version', ''),
                        "extrainfo": port_info.get('extrainfo', '')
                    }
                    results["services"].append(service)
                    
                    # Аналогично обрабатываем скрипты для UDP
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            vuln_keywords = ["vuln", "exploit", "cve", "vulnerability"]
                            if any(keyword in script_name.lower() for keyword in vuln_keywords) or \
                               any(keyword in script_output.lower() for keyword in vuln_keywords):
                                
                                cve_match = re.search(r"CVE-\d{4}-\d{4,7}", script_output)
                                cve = cve_match.group(0) if cve_match else ""
                                
                                vulnerability = {
                                    "port": str(port_num),
                                    "service": port_info.get('name', 'unknown'),
                                    "script_id": script_name,
                                    "output": script_output,
                                    "cve": cve
                                }
                                results["vulnerabilities"].append(vulnerability)
            
            return results
            
        except Exception as e:
            logger.error(f"Ошибка при парсинге результатов nmap: {e}")
            return {"error": f"Ошибка при парсинге результатов: {str(e)}"}
    
    def search_exploits(self, vuln_results: List[Dict]) -> List[Dict]:
        """
        Ищет доступные эксплойты для найденных уязвимостей
        
        Args:
            vuln_results: Список найденных уязвимостей
            
        Returns:
            List[Dict]: Список эксплойтов
        """
        exploits = []
        
        for vuln in vuln_results:
            if not vuln.get("cve"):
                continue
                
            cve = vuln["cve"]
            
            try:
                # Поиск эксплойтов через API Exploit Database
                url = f"https://www.exploit-db.com/search?cve={cve.replace('CVE-', '')}"
                
                # Здесь можно использовать прямой запрос к API ExploitDB, но для простоты используем scraping
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    if "No results found" not in response.text:
                        # Находим доступные эксплойты
                        exploits.append({
                            "cve": cve,
                            "url": url,
                            "description": f"Потенциальные эксплойты для {cve}",
                            "port": vuln["port"],
                            "service": vuln["service"]
                        })
            except Exception as e:
                logger.warning(f"Ошибка при поиске эксплойта для {cve}: {e}")
        
        return exploits
    
    def format_results_for_telegram(self) -> str:
        """
        Форматирует результаты сканирования для отправки в Telegram
        
        Returns:
            str: Отформатированное сообщение
        """
        if "error" in self.results:
            return f"❌ <b>Ошибка:</b> {self.results['error']}"
        
        message = f"<b>🔍 Результаты сканирования для {self.target}</b>\n\n"
        
        # Добавляем информацию о сервисах
        if self.results["services"]:
            message += "<b>📊 Обнаруженные сервисы:</b>\n"
            for service in self.results["services"]:
                service_info = f"{service['name']} ({service['port']}/{service['protocol']})"
                if service["product"] or service["version"]:
                    service_info += f": {service['product']} {service['version']}"
                message += f"• {service_info}\n"
            message += "\n"
        else:
            message += "❌ <b>Сервисы не обнаружены</b>\n\n"
        
        # Добавляем информацию о уязвимостях
        if self.results["vulnerabilities"]:
            message += f"<b>⚠️ Обнаружено уязвимостей: {len(self.results['vulnerabilities'])}</b>\n"
            for i, vuln in enumerate(self.results["vulnerabilities"][:5]):  # Ограничиваем до 5 уязвимостей
                service_info = f"{vuln['service']} (порт {vuln['port']})"
                message += f"{i+1}. <b>{vuln['script_id']}</b> в {service_info}\n"
                if vuln["cve"]:
                    message += f"   CVE: {vuln['cve']}\n"
                
                # Сокращаем вывод для телеграма
                output = vuln["output"]
                if len(output) > 100:
                    output = output[:100] + "..."
                message += f"   <pre>{output}</pre>\n"
            
            if len(self.results["vulnerabilities"]) > 5:
                message += f"... и еще {len(self.results['vulnerabilities']) - 5} уязвимостей\n"
            message += "\n"
        else:
            message += "✅ <b>Уязвимостей не обнаружено</b>\n\n"
        
        # Добавляем информацию о эксплойтах
        if self.results["exploits"]:
            message += f"<b>🔥 Найдены потенциальные эксплойты: {len(self.results['exploits'])}</b>\n"
            for i, exploit in enumerate(self.results["exploits"]):
                message += f"{i+1}. <b>{exploit['cve']}</b> для {exploit['service']} (порт {exploit['port']})\n"
                message += f"   Подробнее: <a href='{exploit['url']}'>Exploit DB</a>\n"
        
        message += f"\n⏱️ Время сканирования: {self.scan_time:.2f} секунд"
        
        # Проверяем на превышение лимита длины сообщения в Telegram
        if len(message) > 4096:
            message = message[:4000] + "...\n\n(Сообщение сокращено из-за превышения лимита)"
        
        return message
    
    def scan_and_analyze(self, ports: str = DEFAULT_PORTS, scan_vulns: bool = True) -> Dict:
        """
        Проводит полное сканирование и анализ цели
        
        Args:
            ports: Строка с портами для сканирования
            scan_vulns: Искать ли уязвимости
            
        Returns:
            Dict: Полные результаты сканирования и анализа
        """
        # Проверяем валидность цели
        if not self.validate_target():
            self.results = {"error": f"Неверный формат IP адреса или домена: {self.target}"}
            return self.results
        
        # Выбираем метод сканирования - nmap или HTTP
        if NMAP_AVAILABLE:
            logger.info("Используем nmap для сканирования")
            scan_results = self.run_nmap_scan(ports, scan_vulns)
            
            # Если nmap недоступен или вернул ошибку, переключаемся на HTTP-сканирование
            if "error" in scan_results:
                logger.info(f"nmap вернул ошибку: {scan_results['error']}. Переключаемся на HTTP-сканирование")
                scan_results = self.run_http_scan(ports)
        else:
            logger.info("nmap недоступен, используем HTTP-сканирование")
            scan_results = self.run_http_scan(ports)
        
        if "error" in scan_results:
            self.results = scan_results
            return self.results
        
        # Сохраняем результаты сканирования
        self.results["services"] = scan_results["services"]
        self.results["vulnerabilities"] = scan_results["vulnerabilities"]
        
        # Если есть уязвимости, ищем эксплойты
        if scan_results["vulnerabilities"]:
            self.results["exploits"] = self.search_exploits(scan_results["vulnerabilities"])
        
        return self.results

def scan_services(target: str, ports: str = DEFAULT_PORTS) -> Dict:
    """
    Функция для быстрого сканирования сервисов по IP или домену
    
    Args:
        target: IP-адрес или домен для сканирования
        ports: Строка с портами для сканирования
        
    Returns:
        Dict: Результаты сканирования
    """
    scanner = ServiceScanner(target)
    return scanner.scan_and_analyze(ports=ports)

def format_scan_results(results: Dict) -> str:
    """
    Форматирует результаты сканирования для отправки в Telegram
    
    Args:
        results: Результаты сканирования
        
    Returns:
        str: Отформатированное сообщение
    """
    scanner = ServiceScanner("")
    scanner.results = results
    return scanner.format_results_for_telegram()

if __name__ == "__main__":
    # Настройка логирования
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Пример использования
    target = "127.0.0.1"  # Замените на реальный IP для тестирования
    scanner = ServiceScanner(target)
    results = scanner.scan_and_analyze()
    print(scanner.format_results_for_telegram()) 