# Detector for Remote Code Execution (RCE) / Command Injection
import random
import re
from urllib.parse import unquote_plus, parse_qs, urlparse

def detect(site_data, samples=None):
    """Detects Remote Code Execution / Command Injection vulnerabilities."""
    # 'samples' here are RCE samples
    vulnerabilities = []
    url = site_data.get("url", "")
    url_lower = url.lower()
    unquoted_url = unquote_plus(url_lower)
    content = site_data.get("content", "")
    content_lower = content.lower()
    
    # Проверяем, есть ли у нас ML-модель для RCE
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на RCE с помощью ML
        ml_result = ml_detector.predict(site_data, "rce")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "RCE_ML_Detection",
                "details": f"ML-модель обнаружила признаки RCE с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для RCE: {e}")
    
    # Extract URL parameters
    parsed_url = urlparse(url)
    url_params = parse_qs(parsed_url.query)
    
    # Extract form parameters if available
    form_params = {}
    if site_data.get("form_data") and site_data.get("params"):
        form_params = site_data.get("params", {})

    # Common RCE/Command Injection patterns and keywords
    # These are checked directly and then attempt correlation if samples are available.
    rce_patterns = [
        # Shell command execution functions (PHP, Python, Perl etc. often visible in params or error messages)
        r"system\s*\(", r"exec\s*\(", r"shell_exec\s*\(", r"passthru\s*\(", r"popen\s*\(", r"proc_open\s*\(",
        r"pcntl_exec\s*\(", r"os\.system\s*\(", r"subprocess\.call\s*\(", r"subprocess\.run\s*\(",
        r"`[^`]+`",  # Backticks command execution (e.g., in PHP, Perl)
        
        # Shell metacharacters and command chains often used in payloads
        r";[\s]*(?:ls|dir|cat|type|whoami|id|uname|echo|net|curl|wget|telnet|nc|netcat|ping)",
        r"\|[\s]*(?:ls|dir|cat|type|whoami|id|uname|echo|net|curl|wget|telnet|nc|netcat|ping)",
        r"&&[\s]*(?:ls|dir|cat|type|whoami|id|uname|echo|net|curl|wget|telnet|nc|netcat|ping)",
        r"\|\|[\s]*(?:ls|dir|cat|type|whoami|id|uname|echo|net|curl|wget|telnet|nc|netcat|ping)",
        r"(?:\$|\(|\{|\\)[\s]*(?:ls|dir|cat|type|whoami|id|uname|echo)",
        
        # Common dangerous commands used in payloads
        r"(?:^|\s|;|&|\||\(|`)cat[\s]+(?:/etc/passwd|/etc/shadow|c:\\windows\\win.ini)",
        r"(?:^|\s|;|&|\||\(|`)rm[\s]+(?:-rf|/s|/q)",
        r"(?:^|\s|;|&|\||\(|`)wget[\s]+(?:http|https|ftp)://",
        r"(?:^|\s|;|&|\||\(|`)echo[\s]+[\"\']?(?:<\?php|<script)",
        r"(?:^|\s|;|&|\||\(|`)bash[\s]+-c",
        
        # Reverse shell patterns
        r"(?:nc|netcat|telnet)[\s]+(?:-e[\s]+(?:/bin/sh|/bin/bash|cmd\.exe)|[\d\.]+[\s]+\d+)",
        r"python[\s]+-c[\s]+[\"\']*import[\s]+socket,subprocess,os",
        r"bash[\s]+-i[\s]*>[\s]*(?:/dev/tcp|&\d)",
        r"ruby[\s]+-rsocket[\s]+-e",
        r"perl[\s]+-e[\s]+[\"\']*use[\s]+Socket",
        r"(?:>/dev/tcp/|>[\s]*&[\s]*\d+)",
        
        # Common eval/code execution
        r"eval\s*\((?:request|post|get|base64_decode|gzinflate)\s*\(",
        r"eval\((?:stripslashes|urldecode)\(",
        r"assert\s*\((?:stripslashes|urldecode)\(",
        r"preg_replace\s*\([\"\']/[^/]+/e",
        r"create_function\s*\("
    ]
    
    # Suspicious parameter names that might be used for command injection
    suspicious_param_names = [
        "cmd", "command", "exec", "execute", "ping", "query", "jump", "code", "payload",
        "run", "daemon", "upload", "dir", "folder", "path", "ip", "url", "uri", "script",
        "shell", "bash", "sh", "powershell", "cmd.exe", "system", "pass", "passwd", "pwd"
    ]
    
    # Common command output patterns that might appear in response if RCE is successful
    command_output_patterns = [
        # id command output
        r"uid=\d+\(.+?\)\s+gid=\d+\(.+?\)",
        # Linux uname command output
        r"Linux\s+[\w.-]+\s+\d+\.\d+\.\d+\S*\s+#\d+",
        # Windows ipconfig/ifconfig output
        r"Windows\s+IP\s+Configuration",
        r"IPv[46]\s+Address[\.\s\:]+[\d\.a-f\:]+",
        # Directory listing output patterns
        r"(?:Directory of|total\s+\d+|[-d](?:r[-w]){2}[-w])",
        # ping command output
        r"\d+\s+bytes\s+from\s+[\d\.a-f\:]+\:\s+(?:icmp_seq|\w+TTL)=\d+",
        # whoami / hostname output (user@host format)
        r"(?:root|admin|administrator|[a-z_][a-z0-9_-]{0,30})@[a-zA-Z0-9_-]+",
        # netstat output
        r"(?:tcp|udp)\s+\d+\s+\d+\s+[\d\.a-f\:]+\:[\d]+\s+[\d\.a-f\:]+\:[\d]+\s+(?:ESTABLISHED|LISTEN)",
        # Process listing (ps command)
        r"\s*PID\s+TTY\s+TIME\s+CMD",
        r"\s*\d+\s+\w+\s+\d{2}:\d{2}:\d{2}\s+\w+"
    ]
    
    # Check URL parameters for RCE patterns
    for param_name, param_values in url_params.items():
        # Check if parameter name is suspicious
        param_name_lower = param_name.lower()
        is_suspicious_param = param_name_lower in suspicious_param_names
        
        for param_value in param_values:
            # Check for direct command injection patterns in parameter value
            for pattern in rce_patterns:
                if re.search(pattern, param_value, re.IGNORECASE):
                    severity = "high" if is_suspicious_param else "medium"
                    vulnerabilities.append({
                        "type": "RCE_URL_Parameter",
                        "details": f"Command injection pattern detected in URL parameter '{param_name}': {param_value[:100]}",
                        "severity": severity
                    })
                    break

    # Check form parameters for RCE patterns
    for param_name, param_value in form_params.items():
        if isinstance(param_value, str):
            param_name_lower = param_name.lower()
            is_suspicious_param = param_name_lower in suspicious_param_names
            
            for pattern in rce_patterns:
                if re.search(pattern, param_value, re.IGNORECASE):
                    severity = "high" if is_suspicious_param else "medium"
                    vulnerabilities.append({
                        "type": "RCE_Form_Parameter",
                        "details": f"Command injection pattern detected in form parameter '{param_name}': {param_value[:100]}",
                        "severity": severity
                    })
                    break
    
    # Check for suspicious parameters with potentially dangerous values
    for param_name, param_values in url_params.items():
        param_name_lower = param_name.lower()
        if param_name_lower in suspicious_param_names:
            for param_value in param_values:
                # Check for command syntax in parameter value
                if any(char in param_value for char in [';', '|', '&', '`', '$', '(', ')']):
                    vulnerabilities.append({
                        "type": "RCE_Suspicious_Parameter",
                        "details": f"Suspicious parameter '{param_name}' contains command syntax characters: {param_value[:100]}",
                        "severity": "medium"
                    })
                    break
    
    # Check response content for command output patterns
    for pattern in command_output_patterns:
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        if match:
            # Extract context around the match
            matched_text = match.group(0)
            start_pos = max(0, match.start() - 40)
            end_pos = min(len(content), match.end() + 40)
            context = content[start_pos:end_pos].replace('<', '&lt;').replace('>', '&gt;')
            
            vulnerabilities.append({
                "type": "RCE_Command_Output",
                "details": f"Response contains possible command execution output: '{matched_text}' with context: '{context}'",
                "severity": "high"
            })
            break
    
    # Check for RCE-related error messages in the content
    rce_error_patterns = [
        r"sh:\s+\d+:\s+(?:[\w\/\.\-\_]+):\s+not found",
        r"(?:Warning|Fatal error):\s+(?:system|exec|passthru|shell_exec|popen)\(\):",
        r"(?:eval|Warning).*?: failed to open stream",
        r"cannot\s+execute\s+binary\s+file",
        r"command\s+not\s+found",
        r"Permission\s+denied.*?fork",
        r"OSError:\s+\[Errno\s+\d+\]\s+(?:Permission\s+denied|No\s+such\s+file\s+or\s+directory)",
        r"Invalid\s+command\s+'\S+'",
        r"syntax\s+error\s+near\s+unexpected\s+token"
    ]
    
    for pattern in rce_error_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            vulnerabilities.append({
                "type": "RCE_Error_Message",
                "details": f"Response contains error message that may indicate command injection attempt: '{match.group(0)}'",
                "severity": "medium"
            })
            break
    
    # Check with samples if available
    if samples and not vulnerabilities:  # Only check samples if no vulnerabilities found yet
        for sample in random.sample(samples, min(len(samples), 10)):
            if sample.get("is_vulnerable"):
                sample_payload = sample.get("raw_payload", "").lower()
                
                if sample_payload and sample_payload in unquoted_url:
                    vulnerabilities.append({
                        "type": "RCE_Sample_Match",
                        "details": f"URL contains a pattern matching known RCE payload: '{sample_payload[:100]}'",
                        "severity": "high"
                    })
                    break
                
                # Check for similar but not exact match (payload structure)
                # Extract core components of the sample payload
                sample_core_components = []
                for pattern in [r';[\s]*\w+', r'\|[\s]*\w+', r'&&[\s]*\w+', r'\$\([\s]*\w+']:
                    matches = re.findall(pattern, sample_payload)
                    sample_core_components.extend(matches)
                
                # Check if any of these components are in our URL
                for component in sample_core_components:
                    if component in unquoted_url:
                        vulnerabilities.append({
                            "type": "RCE_Similar_Pattern",
                            "details": f"URL contains pattern similar to known RCE payload component: '{component}'",
                            "severity": "medium"
                        })
                        break

    return vulnerabilities 