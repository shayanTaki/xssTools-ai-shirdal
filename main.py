#!/usr/bin/env python3

# ایمپورت کتابخانه های مورد نیاز
import requests
from bs4 import BeautifulSoup
import re
import sys
import json
import time
import urllib.parse
from typing import List, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor
import colorama
from colorama import Fore, Style
import html
import warnings
import socket
from urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict

# غیرفعال کردن هشدارهای درخواست ناامن
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


class VulnerabilityScanner:
    def __init__(self):
        self.mistral_api_key = None  # کلید API برای Mistral AI
        self.base_url = None  # URL هدف
        self.headers = None  # هدرهای درخواست
        self.session = requests.Session()  # ایجاد یک session برای درخواست ها
        self.visited_urls = set()  # URL های بازدید شده
        self.found_vulnerabilities = defaultdict(list) # آسیب پذیری های پیدا شده

        # الگوهای XSS توسعه یافته
        self.xss_patterns = {
            'basic_xss': [ # XSS پایه
                r'<script\b[^>]*>.*?</script>',
                r'javascript:.*?[(].*?[)]',
                r'on\w+\s*=\s*(["\']).*?\1',
                r'data:text/html.*?base64',
                r'<img[^>]+src\s*=\s*(["\'])[^>]*?onerror\s*=',
            ],
            'attribute_injection': [ # تزریق ویژگی
                r'["\'].*?["\']',
                r'\[[^]]*\]',
                r'\(\s*[^)]*\s*\)',
            ],
            'dom_manipulation': [  # دستکاری DOM
                r'document\.(location|cookie|referrer)',
                r'window\.(name|location)',
                r'localStorage|sessionStorage',
                r'eval\s*\(',
                r'setTimeout|setInterval',
            ],
            'protocol_handlers': [ # هندلرهای پروتکل
                r'vbscript:.*',
                r'data:.*',
                r'view-source:.*',
            ],
            'encoded_payloads': [ # پیلودهای کدگذاری شده
                r'%3C.*%3E',  # URL encoded
                r'&#x.*?;',  # Hex encoded
                r'&#\d+;',  # Decimal encoded
                r'\\x[0-9a-fA-F]{2}',  # Hex escaped
            ]
        }

        # بررسی های سیاست امنیت محتوا (CSP)
        self.csp_checks = [
            'default-src',
            'script-src',
            'style-src',
            'img-src',
            'connect-src',
            'font-src',
            'frame-src',
            'report-uri'
        ]

        # هدرهای امنیتی
        self.security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy'
        ]