import requests
import socket
import ssl
from urllib.parse import urlparse
from requests.exceptions import RequestException

# Попытка определить используемые технологии по заголовкам и контенту
TECH_SIGNATURES = {
    'X-Powered-By': {
        'php': 'PHP',
        'express': 'Node.js (Express)',
        'asp.net': 'ASP.NET',
        'django': 'Python (Django)',
        'laravel': 'PHP (Laravel)',
        'ruby': 'Ruby',
        'java': 'Java',
        'wordpress': 'WordPress',
        'drupal': 'Drupal',
        'joomla': 'Joomla',
        'nginx': 'nginx',
        'apache': 'Apache',
    },
    'Server': {
        'nginx': 'nginx',
        'apache': 'Apache',
        'iis': 'Microsoft IIS',
        'gunicorn': 'Python (gunicorn)',
        'caddy': 'Caddy',
        'lighttpd': 'Lighttpd',
        'openresty': 'OpenResty',
    },
    'Set-Cookie': {
        'wordpress': 'WordPress',
        'drupal': 'Drupal',
        'joomla': 'Joomla',
        'laravel': 'Laravel',
        'ci_session': 'CodeIgniter',
        'symfony': 'Symfony',
    }
}

WAF_SIGNATURES = [
    ('cloudflare', ['cf-ray', 'cloudflare']),
    ('sucuri', ['sucuri']),
    ('imperva', ['incapsula', 'imperva']),
    ('f5', ['bigip', 'f5']),
    ('aws', ['awselb', 'aws-alb']),
    ('mod_security', ['mod_security', 'modsecurity']),
    ('dome9', ['dome9']),
    ('barracuda', ['barracuda']),
    ('360', ['360wzws']),
    ('yundun', ['yundun']),
    ('aeSecure', ['aesecure']),
    ('dotdefender', ['dotdefender']),
    ('profense', ['profense']),
    ('citrix', ['citrix']),
    ('sitelock', ['sitelock']),
    ('webknight', ['webknight']),
    ('urlscan', ['urlscan']),
    ('denyall', ['denyall']),
    ('fortinet', ['fortinet']),
    ('radware', ['radware']),
    ('sophos', ['sophos']),
    ('stackpath', ['stackpath']),
    ('yunsuo', ['yunsuo']),
    ('baidu', ['baidu']),
    ('aliyun', ['aliyun']),
    ('tencent', ['tencent']),
]

def get_ip_and_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        dns = socket.gethostbyaddr(ip)[0]
        return ip, dns
    except Exception:
        return None, None

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'notBefore': cert['notBefore'],
                'notAfter': cert['notAfter'],
            }
    except Exception:
        return None

def detect_technologies(headers, content):
    techs = set()
    for header, sigs in TECH_SIGNATURES.items():
        value = headers.get(header, '').lower()
        for sig, name in sigs.items():
            if sig in value:
                techs.add(name)
    # Поиск по контенту (простые эвристики)
    content = content.lower()
    if 'wp-content' in content or 'wordpress' in content:
        techs.add('WordPress')
    if 'drupal' in content:
        techs.add('Drupal')
    if 'joomla' in content:
        techs.add('Joomla')
    if 'laravel' in content:
        techs.add('Laravel')
    if 'django' in content:
        techs.add('Python (Django)')
    if 'react' in content:
        techs.add('React.js')
    if 'vue' in content:
        techs.add('Vue.js')
    if 'angular' in content:
        techs.add('Angular')
    return list(techs)

def detect_waf(headers, content):
    wafs = set()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, sigs in WAF_SIGNATURES:
        for sig in sigs:
            for k, v in headers_lower.items():
                if sig in k or sig in v:
                    wafs.add(waf)
            if sig in content.lower():
                wafs.add(waf)
    return list(wafs)

def get_target_info(url):
    parsed = urlparse(url)
    domain = parsed.hostname
    info = {'url': url, 'domain': domain}
    try:
        resp = requests.get(url, timeout=7, allow_redirects=True, verify=False)
        headers = resp.headers
        content = resp.text
    except RequestException as e:
        info['error'] = str(e)
        return info
    # IP и DNS
    ip, dns = get_ip_and_dns(domain)
    info['ip'] = ip
    info['dns'] = dns
    # SSL
    ssl_info = get_ssl_info(domain)
    if ssl_info:
        info['ssl'] = ssl_info
    # Технологии
    info['technologies'] = detect_technologies(headers, content)
    # WAF
    info['waf'] = detect_waf(headers, content)
    # Заголовки
    info['headers'] = dict(headers)
    return info

def format_target_info(info):
    if 'error' in info:
        return f"❌ Ошибка при получении информации о цели: {info['error']}"
    msg = f"<b>ℹ️ Информация о цели:</b>\n"
    msg += f"<b>URL:</b> {info['url']}\n"
    msg += f"<b>Домен:</b> {info['domain']}\n"
    if info.get('ip'):
        msg += f"<b>IP:</b> {info['ip']}\n"
    if info.get('dns'):
        msg += f"<b>DNS:</b> {info['dns']}\n"
    if info.get('ssl'):
        ssl = info['ssl']
        msg += f"<b>SSL:</b> {ssl['subject'].get('commonName', '')} (выдан: {ssl['issuer'].get('commonName', '')})\n"
        msg += f"<b>Срок действия:</b> {ssl['notBefore']} - {ssl['notAfter']}\n"
    if info.get('technologies'):
        msg += f"<b>Технологии:</b> {', '.join(info['technologies'])}\n"
    if info.get('waf'):
        msg += f"<b>WAF:</b> {', '.join(info['waf'])}\n"
    if info.get('headers'):
        msg += f"<b>Заголовки:</b>\n"
        for k, v in info['headers'].items():
            msg += f"<code>{k}: {v}</code>\n"
    return msg 