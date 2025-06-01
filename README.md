# Web Vulnerability Scanner & Security Suite

![Project Status](https://img.shields.io/badge/status-active-green) ![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Python](https://img.shields.io/badge/python-3.8%2B-yellow)

A comprehensive web security toolkit that combines advanced web crawling, machine learning-based vulnerability detection, and a Telegram bot interface for easy security testing and monitoring.

## 🌟 Project Overview

This project is a full-featured web security scanner designed to detect vulnerabilities in websites through multiple scanning techniques. It combines traditional pattern matching with machine learning models to provide accurate vulnerability detection across 14 types of security issues, following OWASP Top 10 categories.

### 📊 Project Status

| Component | Completion | Stability | Note |
|-----------|------------|-----------|------|
| Web Crawler | 95% | High | Core functionality complete |
| ML Models | 80% | Medium | More training data needed |
| Vulnerability Detection | 85% | High | Regular pattern updates |
| Telegram Bot | 90% | High | All commands operational |
| Reporting | 75% | Medium | More formats needed |
| Exploitation | 70% | Medium | Limited to common vulnerabilities |

## 🚀 Features

### Core Components
- **Advanced Web Crawler**: Thoroughly scans websites to discover pages, forms, and resources
- **ML-Powered Vulnerability Detection**: Uses machine learning to identify 14 types of security vulnerabilities
- **Telegram Bot Interface**: Control scanning operations via convenient Telegram commands
- **Service Scanner**: Detects running services and their versions for vulnerability mapping
- **Exploitation Module**: Tests discovered vulnerabilities to verify exploitability
- **Detailed Reports**: Generates comprehensive reports in multiple formats

### Vulnerability Detection
- **OWASP Top 10 Coverage**:
  - A01: Broken Access Control
  - A02: Cryptographic Failures
  - A03: Injection (SQL, XSS, Command)
  - A04: Insecure Design
  - A05: Security Misconfiguration
  - A06: Vulnerable Components
  - A07: Authentication Failures
  - A08: Software Data Integrity Failures
  - A09: Logging and Monitoring Failures
  - A10: Server-Side Request Forgery (SSRF)
- **Additional Vulnerabilities**:
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  - Cross-Site Request Forgery (CSRF)
  - Directory Traversal

### Scanning Modes
- **Single URL Analysis**: Quick scan of a specific page
- **Full Crawl & Scan**: Comprehensive website security audit
- **Exploitation Check**: Verify if vulnerabilities can be exploited
- **Service Scanning**: Check for vulnerable services and versions
- **Bruteforce Testing**: Test for weak credentials

## 📋 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web-scanner.git
cd web-scanner

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python main.py
```

### Telegram Bot Configuration

To use the Telegram bot functionality, you need to configure your bot token and optionally set authorized chat IDs:

1. Edit the file `bot/bot.py` and replace the `TELEGRAM_BOT_TOKEN` value with your actual token:
   ```python
   # Line 59 in bot/bot.py
   TELEGRAM_BOT_TOKEN = 'YOUR_BOT_TOKEN_HERE'
   ```

2. (Optional) To restrict bot access to specific users, uncomment and modify the `AUTHORIZED_USERS` list:
   ```python
   # Line 60-61 in bot/bot.py
   AUTHORIZED_USERS = [123456789, 987654321] # Replace with your chat IDs
   ```

You can get your chat ID by sending a message to [@userinfobot](https://t.me/userinfobot) on Telegram.

## 🔧 Usage

### Command Line Interface

```bash
# Basic scan
python main.py --target https://example.com

# Full crawl and scan with 5 threads, max 200 URLs, depth 3
python main.py --target https://example.com --crawl --max-urls 200 --depth 3 --threads 5

# Enable exploitation checks
python main.py --target https://example.com --exploit

# Ignore robots.txt restrictions
python main.py --target https://example.com --crawl --ignore-robots

# Save results to file
python main.py --target https://example.com --output results.json

# Run without Telegram bot
python main.py --target https://example.com --no-bot
```

### Telegram Bot Commands

```
/start - Get started with the bot
/scan [url] - Scan a single URL for vulnerabilities
/crawl [url] [max_urls] [max_depth] - Crawl and scan entire website
/exp [url] - Check for exploitable vulnerabilities
/info [url] - Get basic information about target
/brute [url] [service] - Run bruteforce on login services
/vuln [url] - Run vulnerability scan without crawling
```

## 🔍 Key Files & Directories

- `main.py` - Main application entry point
- `web_crawler.py` - Website crawling functionality
- `service_scanner.py` - Service and port scanning
- `exploiter.py` - Vulnerability exploitation module
- `ml_models/` - Machine learning models for vulnerability detection
- `bot/` - Telegram bot interface
- `reports/` - Generated security reports
- `dict/` - Wordlists for bruteforce and discovery

## 🚧 Future Development

### Planned Features
- [ ] Integration with CI/CD pipelines
- [ ] Desktop GUI interface
- [ ] API endpoint for programmatic access
- [ ] Enhanced ML models with deep learning
- [ ] Scheduled scanning and monitoring
- [ ] Custom exploit development module
- [ ] WAF detection and bypass techniques
- [ ] Cloud-based scanning service

### Improvements Needed
- [ ] Additional training data for ML models
- [ ] Performance optimization for large sites
- [ ] More report formats (PDF, HTML)
- [ ] Parallel vulnerability testing
- [ ] Proxy and authentication support
- [ ] Rate limiting and stealth options

## 🛡️ Responsible Use

This tool is designed for security professionals to test systems they are authorized to scan. Always obtain proper permission before scanning any website or system. Unauthorized scanning may be illegal in many jurisdictions.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 