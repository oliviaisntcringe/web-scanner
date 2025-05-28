import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time # Added for request delays
import sys
import os

# Добавляем путь к родительской директории, чтобы импортировать web_crawler
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_crawler import WebCrawler

MAX_DEPTH = 2 # Configuration for crawl depth
VISITED_URLS = set()
MAX_NON_HTML_CONTENT_SIZE = 1024 * 1024 # 1MB limit for storing non-HTML content
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; WebVulnerabilityScanner/1.0)"
DEFAULT_DELAY = 0.1 # Default delay of 0.1 seconds between requests

def crawl_page(url, base_domain, user_agent, delay, robots_txt_content=None):
    """Crawls a single page, extracts its data, and identifies links, forms, and static resources."""
    if url in VISITED_URLS:
        return None, []
    VISITED_URLS.add(url)
    
    # Apply delay before making the request
    if delay > 0:
        time.sleep(delay)
        
    print(f"Crawling {url}...")

    try:
        headers_for_request = {'User-Agent': user_agent}
        response = requests.get(url, headers=headers_for_request, timeout=10)
        response.raise_for_status()

        content_type = response.headers.get('content-type', '').lower()
        page_headers = dict(response.headers)
        
        page_data = {
            "url": url,
            "content": None, 
            "headers": page_headers,
            "forms": [],
            "links_on_page": [],
            "static_resources": [], # For JS, CSS files linked
            "content_type": content_type,
            "robots_txt_content": robots_txt_content
        }

        if 'html' in content_type:
            page_data["content"] = response.text
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            extracted_forms = []
            for form_tag in soup.find_all('form'):
                action = form_tag.get('action')
                method = form_tag.get('method', 'get').lower()
                form_action_url = urljoin(url, action) if action else url
                inputs = []
                for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    if input_tag.name == 'textarea': input_type = 'textarea'
                    elif input_tag.name == 'select': input_type = 'select'
                    input_value = input_tag.get('value')
                    if input_tag.name == 'textarea': input_value = input_tag.string
                    elif input_tag.name == 'select':
                        selected_option = input_tag.find('option', selected=True)
                        if selected_option: input_value = selected_option.get('value', selected_option.string)
                        else:
                            first_option = input_tag.find('option')
                            if first_option: input_value = first_option.get('value', first_option.string)
                            else: input_value = None
                    inputs.append({'type': input_type, 'name': input_name, 'value': input_value})
                extracted_forms.append({'action': form_action_url, 'method': method, 'inputs': inputs})
            page_data["forms"] = extracted_forms
            
            # Extract links
            found_links = []
            for a_tag in soup.find_all('a', href=True):
                raw_link = a_tag['href']
                try:
                    abs_link = urljoin(url, raw_link)
                    parsed_link = urlparse(abs_link)
                    if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc == base_domain:
                        clean_link = parsed_link._replace(fragment='').geturl()
                        found_links.append(clean_link)
                        page_data["links_on_page"].append(clean_link)
                except Exception as e:
                    print(f"Error processing link '{raw_link}' on {url}: {e}")
            
            # Extract JS and CSS files
            for script_tag in soup.find_all('script', src=True):
                src = script_tag['src']
                abs_src = urljoin(url, src)
                parsed_src = urlparse(abs_src)
                if parsed_src.scheme in ['http', 'https'] and parsed_src.netloc == base_domain:
                    page_data["static_resources"].append({"type": "js", "url": parsed_src._replace(fragment='').geturl()})
            
            for link_tag in soup.find_all('link', rel='stylesheet', href=True):
                href = link_tag['href']
                abs_href = urljoin(url, href)
                parsed_href = urlparse(abs_href)
                if parsed_href.scheme in ['http', 'https'] and parsed_href.netloc == base_domain:
                     page_data["static_resources"].append({"type": "css", "url": parsed_href._replace(fragment='').geturl()})

            print(f"Found {len(page_data['links_on_page'])} links, {len(page_data['forms'])} forms, {len(page_data['static_resources'])} static resources on {url} (HTML)")
            return page_data, list(set(found_links))
        else:
            print(f"Processing non-HTML content at {url} (type: {content_type})")
            if any(ct in content_type for ct in ['javascript', 'json', 'xml', 'css', 'plain']):
                if len(response.content) <= MAX_NON_HTML_CONTENT_SIZE:
                    try: page_data["content"] = response.text
                    except UnicodeDecodeError: 
                        print(f"Could not decode non-HTML content as text for {url}.")
                        page_data["content"] = None 
                else:
                    print(f"Non-HTML content at {url} is too large ({len(response.content)} bytes), skipping storage.")
            return page_data, [] 

    except requests.exceptions.Timeout: print(f"Timeout crawling {url}"); return None, []
    except requests.exceptions.RequestException as e: print(f"Error crawling {url}: {e}"); return None, []
    except Exception as e: print(f"An unexpected error occurred while crawling {url}: {e}"); return None, []

def crawl_site(url, max_depth=2, user_agent=None, delay=0.1):
    """
    Функция-обертка для совместимости с существующим кодом.
    Использует наш новый WebCrawler для обхода сайта.
    
    Args:
        url (str): URL сайта для обхода
        max_depth (int): Максимальная глубина обхода
        user_agent (str): User-Agent для запросов
        delay (float): Задержка между запросами
        
    Returns:
        list: Список страниц и ресурсов
    """
    # Создаем заголовки для запросов, если указан User-Agent
    headers = None
    if user_agent:
        headers = {
            'User-Agent': user_agent
        }
    
    # Создаем экземпляр краулера
    crawler = WebCrawler(
        url, 
        max_depth=max_depth,
        delay=delay,
        headers=headers,
        max_urls=100,
        thread_count=5
    )
    
    # Запускаем краулер
    results = crawler.crawl()
    
    # Преобразуем результаты в формат, ожидаемый существующим кодом
    pages = []
    
    # Обрабатываем найденные страницы
    for page in results['pages']:
        page_data = {
            'url': page['url'],
            'content_type': page.get('content_type', 'text/html'),
            'headers': page.get('headers', {}),
            'links_on_page': [],
            'forms': [],
            'static_resources': []
        }
        
        # Добавляем страницу в результаты
        pages.append(page_data)
    
    # Обрабатываем найденные файлы как статические ресурсы
    for file in results['files']:
        # Определяем тип ресурса
        url = file['url']
        file_type = 'unknown'
        
        if 'extension' in file:
            ext = file['extension'].lower()
            if ext in ['js']:
                file_type = 'javascript'
            elif ext in ['css']:
                file_type = 'css'
            elif ext in ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp']:
                file_type = 'image'
            elif ext in ['html', 'htm']:
                file_type = 'html'
            elif ext in ['xml', 'json']:
                file_type = ext
        
        # Создаем данные о ресурсе
        resource_data = {
            'url': url,
            'type': file_type
        }
        
        # Ищем страницу, которая ссылается на этот ресурс
        if 'source' in file:
            source = file['source']
            for page in pages:
                if page['url'] == source:
                    page['static_resources'].append(resource_data)
                    break
        
    return pages

if __name__ == '__main__':
    # Example Usage
    # Create a dummy server for testing or use a live, simple site you have permission to test.
    # For this example, let's assume a very simple local site or a safe public one.
    
    # To test locally, you can run a simple HTTP server:
    # In one terminal: python -m http.server 8000
    # Then in another, run this script with target_url = "http://localhost:8000/some_page.html"
    
    # Example: target_url = "http://localhost:8000/test_site/page1.html" 
    # Ensure you have test_site/page1.html, page2.html etc. with links.

    # A safer public site for a quick test (be mindful of crawling policies)
    target_url = "http://info.cern.ch/" # The first website
    # target_url = "https://www.google.com" # Example, but google has strict crawling policies, not ideal for this simple crawler

    print(f"Starting crawl for: {target_url}")
    crawled_data = crawl_site(target_url, max_depth=0, user_agent="TestScanner/1.0", delay=0.5) # Limit depth to 0 for initial page only for form test

    if crawled_data:
        print(f"\n--- Crawl Results ({len(crawled_data)} pages) ---")
        for i, page in enumerate(crawled_data):
            print(f"Page {i+1}: {page['url']} (Type: {page.get('content_type','N/A')})")
            print(f"  Headers count: {len(page['headers'])}")
            if page.get('robots_txt_content'):
                print(f"  robots.txt (first 100 chars): {page['robots_txt_content'][:100].replace('\n',' ')}...")
            
            if 'html' in page.get('content_type',''):
                print(f"  Forms found: {len(page['forms'])}")
                if page['forms']:
                    for form_idx, form_data in enumerate(page['forms']):
                        print(f"    Form {form_idx+1}: action='{form_data['action']}', method='{form_data['method']}', inputs={len(form_data['inputs'])}")
                        if form_data['inputs']:
                            print(f"      Example input: name='{form_data['inputs'][0].get('name')}', type='{form_data['inputs'][0].get('type')}', value='{str(form_data['inputs'][0].get('value'))[:50]}'")
                print(f"  Links on page (in scope): {len(page['links_on_page'])}")
                print(f"  Static Resources (JS/CSS): {len(page['static_resources'])}")
                if page['static_resources']:
                    for res in page['static_resources'][:2]: # Print first 2 static resources
                        print(f"    - Type: {res['type']}, URL: {res['url']}")
            elif page.get("content"):
                print(f"  Non-HTML Content length: {len(page['content'])} bytes")
            else:
                print("  No content stored (either non-HTML and large, or error).")
    else:
        print("No data crawled.")

    # Test with a non-existent or error-prone URL
    # print("\n--- Testing error case ---")
    # error_url = "http://thissitedoesnotexist12345.com"
    # crawled_error_data = crawl_site(error_url)
    # print(f"Crawled error data count: {len(crawled_error_data)}")

    # Test with non-html content
    # print("\n--- Testing non-HTML case ---")
    # non_html_url = "https://www.w3.org/Style/css/ पानी .css" # example css file
    # crawled_non_html_data = crawl_site(non_html_url)
    # if crawled_non_html_data and crawled_non_html_data[0]:
    #     print(f"URL: {crawled_non_html_data[0]['url']}, Content Present: {bool(crawled_non_html_data[0]['content'])}") 