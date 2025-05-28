# Detector for Local File Inclusion (LFI)
import random
import re
from urllib.parse import unquote_plus, parse_qs, urlparse

def detect(site_data, samples=None):
    """Detects Local File Inclusion vulnerabilities."""
    # 'samples' here are LFI samples
    vulnerabilities = []
    url = site_data.get("url", "")
    url_lower = url.lower()
    unquoted_url = unquote_plus(url_lower)
    content = site_data.get("content", "")
    content_lower = content.lower()
    
    # Проверяем, есть ли у нас ML-модель для LFI
    try:
        # Импортируем наш ML-детектор
        from ml_models.ml_detector import MLDetector
        ml_detector = MLDetector()
        
        # Проверяем сайт на LFI с помощью ML
        ml_result = ml_detector.predict(site_data, "lfi")
        
        # Если модель предсказала уязвимость с высокой уверенностью, добавляем ее
        if ml_result["prediction"] and ml_result["confidence"] > 0.7:
            vulnerabilities.append({
                "type": "LFI_ML_Detection",
                "details": f"ML-модель обнаружила признаки LFI с уверенностью {ml_result['confidence']:.2f}",
                "severity": "high"
            })
    except Exception as e:
        print(f"Ошибка при использовании ML для LFI: {e}")
    
    # Extract URL parameters
    parsed_url = urlparse(url)
    url_params = parse_qs(parsed_url.query)
    path = parsed_url.path.lower()

    # Common LFI patterns to check in URL or content (even without samples)
    lfi_patterns = [
        # Path traversal variations
        r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c",
        r"%2e%2e%2f", r"%2e%2e\\", r"%2e%2e%5c", 
        r"..%c0%af", r"%c0%ae%c0%ae/", # UTF-8 encoded ../ (example)
        
        # Common target files
        r"/etc/passwd", r"c:\\windows\\win.ini", r"/etc/shadow", r"/proc/self/environ",
        r"/var/www/html/", r"/var/log/", r"/etc/hosts", r"/windows/system32/",
        r"/boot.ini", r"/windows/win.ini", r"/windows/repair/sam",
        
        # PHP Wrappers
        r"php://filter", r"php://input", r"data://text/plain", r"phar://", r"zip://",
        r"expect://", r"file://", r"glob://", r"compress.zlib://", r"compress.bzip2://",
        r"convert.base64-encode", r"convert.base64-decode",
        
        # Null byte injection (used to bypass extensions)
        r"%00", r"\0", r"0x00"
    ]
    
    # Extended file paths for different environments
    linux_files = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", 
        "/etc/motd", "/etc/issue", "/etc/mysql/my.cnf", "/proc/self/environ",
        "/proc/version", "/proc/cmdline", "/var/log/apache/access.log",
        "/var/log/apache2/access.log", "/var/log/httpd/access.log", 
        "/var/log/apache/error.log", "/var/log/apache2/error.log", 
        "/var/log/httpd/error.log", "/var/www/html/index.php", 
        "/var/www/index.php", "/var/www/html/wp-config.php"
    ]
    
    windows_files = [
        "c:\\windows\\win.ini", "c:\\windows\\system32\\drivers\\etc\\hosts",
        "c:\\windows\\system.ini", "c:\\windows\\repair\\sam",
        "c:\\boot.ini", "c:\\xampp\\php\\php.ini", "c:\\xampp\\apache\\conf\\httpd.conf",
        "c:\\xampp\\apache\\logs\\access.log", "c:\\xampp\\apache\\logs\\error.log",
        "c:\\xampp\\tomcat\\conf\\server.xml", "c:\\windows\\php.ini",
        "c:\\windows\\system32\\config\\systemprofile\\desktop"
    ]

    # Find file inclusion attempts in URL parameters
    for param_name, param_values in url_params.items():
        for param_value in param_values:
            # Check if parameter contains any of the LFI patterns
            for pattern in lfi_patterns:
                if re.search(pattern, param_value, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "LFI_Parameter",
                        "details": f"Potential LFI detected in parameter '{param_name}': {param_value}",
                        "severity": "high"
                    })
                    break
            
            # Check if parameter contains path to common sensitive files
            for linux_file in linux_files:
                if linux_file.lower() in param_value.lower():
                    vulnerabilities.append({
                        "type": "LFI_Linux_Sensitive_File",
                        "details": f"Parameter '{param_name}' appears to reference Linux sensitive file: {linux_file}",
                        "severity": "high"
                    })
                    break
                    
            for windows_file in windows_files:
                if windows_file.lower() in param_value.lower() or windows_file.replace("\\", "/").lower() in param_value.lower():
                    vulnerabilities.append({
                        "type": "LFI_Windows_Sensitive_File",
                        "details": f"Parameter '{param_name}' appears to reference Windows sensitive file: {windows_file}",
                        "severity": "high"
                    })
                    break
    
    # Check for direct path traversal in URL path
    traversal_in_path = False
    for pattern in [r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c", r"%2e%2e%2f", r"%2e%2e%5c"]:
        if re.search(pattern, path, re.IGNORECASE):
            traversal_in_path = True
            vulnerabilities.append({
                "type": "LFI_Path_Traversal",
                "details": f"Directory traversal sequence detected in URL path: {path}",
                "severity": "high"
            })
            break

    # Check for file inclusion in URL path (not using parameters)
    for linux_file in linux_files:
        if linux_file.lower() in path:
            vulnerabilities.append({
                "type": "LFI_Path_Linux_File",
                "details": f"URL path appears to directly include Linux sensitive file: {linux_file}",
                "severity": "high"
            })
            break
            
    for windows_file in windows_files:
        windows_file_slash = windows_file.replace("\\", "/").lower()
        if windows_file.lower() in path or windows_file_slash in path:
            vulnerabilities.append({
                "type": "LFI_Path_Windows_File",
                "details": f"URL path appears to directly include Windows sensitive file: {windows_file}",
                "severity": "high"
            })
            break

    # Check for LFI error messages in the content
    lfi_error_messages = [
        "failed to open stream: No such file or directory",
        "include\\(\\): Failed opening",
        "Warning: include\\(",
        "Warning: require_once\\(",
        "Warning: include_once\\(",
        "Warning: require\\(",
        "Warning: fread\\(\\): supplied argument is not a valid File-Handle resource",
        "file_get_contents\\(\\): failed to open stream",
        "Invalid argument supplied for foreach\\(\\)",
        "open_basedir restriction in effect",
        "Permission denied",
        "The specified file could not be accessed",
        "No such file or directory in",
        "Root element is missing"
    ]
    
    for error_msg in lfi_error_messages:
        match = re.search(error_msg, content, re.IGNORECASE)
        if match:
            # Extract context around the error message
            error_text = match.group(0)
            start_pos = max(0, match.start() - 40)
            end_pos = min(len(content), match.end() + 40)
            context = content[start_pos:end_pos].replace('<', '&lt;').replace('>', '&gt;')
            
            vulnerabilities.append({
                "type": "LFI_Error_Message",
                "details": f"LFI error message detected: '{error_text}' with context: '{context}'",
                "severity": "medium"
            })
            break

    # Check for common file content leakage indicators
    file_content_indicators = [
        # /etc/passwd format
        r"root:x:\d+:\d+:.*?:/root:/bin/(?:bash|sh)",
        # win.ini content
        r"for 16-bit app support",
        # Config file format
        r"(?:mysql_connect|mysqli_connect|database_host|db_name|db_user|db_password)",
        # Apache config
        r"(?:DocumentRoot|ServerName|ServerAdmin)",
        # Log file formats
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"
    ]
    
    for indicator in file_content_indicators:
        match = re.search(indicator, content, re.IGNORECASE)
        if match:
            vulnerabilities.append({
                "type": "LFI_File_Content_Leaked",
                "details": f"Content appears to contain file data that might have been leaked via LFI: '{match.group(0)[:50]}...'",
                "severity": "high"
            })
            break
    
    # Check for samples correlations if available and we haven't found direct evidence
    if samples and len(vulnerabilities) == 0:
        for sample in random.sample(samples, min(len(samples), 10)):
            if sample.get("is_vulnerable"):
                sample_url = sample.get("url", "").lower()
                sample_html = sample.get("html", "").lower()
                sample_raw_payload = sample.get("raw_payload", "").lower()
                
                # Check if sample payload is similar to current URL
                if sample_raw_payload and (sample_raw_payload in unquoted_url or 
                                           sample_raw_payload.replace("../", "%2e%2e%2f") in unquoted_url):
                    vulnerabilities.append({
                        "type": "LFI_Sample_Correlation",
                        "details": f"URL matches LFI vulnerability pattern from sample. Sample payload: {sample_raw_payload[:100]}",
                        "severity": "medium"
                    })
                    break

    return vulnerabilities 