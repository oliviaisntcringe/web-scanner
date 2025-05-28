# Project: Web Vulnerability Scanner with Telegram Bot

This project aims to crawl websites, analyze them for vulnerabilities using machine learning models, and report findings via a Telegram bot.

## Components
- Web Crawler: Automatically discovers all pages, files, and directories on a target website
- ML Vulnerability Analyzer: Uses machine learning models to detect 14 types of vulnerabilities
- Telegram Bot Interface: Easily scan websites via Telegram commands

## Features

- **Automatic Web Crawling**: Finds all files, directories, and pages on target websites
- **Advanced Vulnerability Detection**: Uses pattern matching and ML models
- **Telegram Integration**: Send commands via Telegram bot
- **Detailed Reports**: Get comprehensive vulnerability reports with severity ratings
- **Multiple Scanning Modes**:
  - Single URL scan
  - Exploitable vulnerabilities check
  - Full website crawl and scan

## Usage

### Telegram Bot Commands

- `/scan [url]` - Scan a single URL for vulnerabilities
- `/exp [url]` - Check for exploitable vulnerabilities
- `/crawl [url] [max_urls] [max_depth]` - Crawl and scan an entire website

### Command Line Usage

```
python main.py --target https://example.com [options]
```

Options:
- `--crawl` or `-c`: Enable web crawler
- `--max-urls N`: Maximum number of URLs to crawl (default: 100)
- `--depth N` or `-d N`: Maximum crawl depth (default: 2)
- `--exploit` or `-e`: Check for exploitable vulnerabilities
- `--follow-subdomains`: Also scan subdomains
- `--ignore-robots`: Ignore robots.txt restrictions
- `--threads N`: Number of crawler threads (default: 5)
- `--output FILE` or `-o FILE`: Save results to a file
- `--verbose` or `-v`: Verbose output
- `--no-bot`: Don't start the Telegram bot

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the bot: `python main.py` 