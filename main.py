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

        def check_dns_vulnerability(self) -> Dict:
            """بررسی آسیب پذیری های مربوط به DNS"""
            try:
                hostname = urllib.parse.urlparse(self.base_url).hostname  # دریافت hostname از URL
                ip_addresses = socket.gethostbyname_ex(hostname)  # دریافت آدرس های IP مربوط به hostname
                return {
                    'hostname': hostname,  # نام میزبان
                    'ip_addresses': ip_addresses[2],  # آدرس های IP
                    'aliases': ip_addresses[1]  # نام های مستعار
                }
            except socket.gaierror as e:  # مدیریت خطا در صورت عدم دسترسی به DNS
                return {'error': str(e)}




        def check_security_headers(self, response: requests.Response) -> Dict:
            """تجزیه و تحلیل هدرهای امنیتی"""
            headers_analysis = {}  # دیکشنری برای ذخیره نتایج تحلیل هدرها
            for header in self.security_headers:  # بررسی هر هدر امنیتی
                if header in response.headers:  # بررسی وجود هدر
                    headers_analysis[header] = {
                        'present': True,  # هدر وجود دارد
                        'value': response.headers[header]  # مقدار هدر
                    }
                else:  # هدر وجود ندارد
                    headers_analysis[header] = {
                        'present': False,  # هدر وجود ندارد
                        'recommendation': f"Add {header} header for enhanced security"  # توصیه برای اضافه کردن هدر
                    }
            return headers_analysis  # # بازگرداندن نتایج تحلیل

        def analyze_form_security(self, form: BeautifulSoup) -> Dict:
            """تجزیه و تحلیل ویژگی های امنیتی فرم"""
            csrf_token = False  # وجود توکن CSRF
            autocomplete = form.get('autocomplete', 'on')  # مقدار ویژگی autocomplete
            method = form.get('method', 'get').lower()  # متد فرم
            action = form.get('action', '')  # آدرس action فرم

            # بررسی وجود توکن CSRF
            for input_tag in form.find_all('input'):  # بررسی تمام فیلدهای input
                if any(token in input_tag.get('name', '').lower() for token in
                       ['csrf', 'token', '_token']):  # بررسی نام فیلد برای یافتن توکن CSRF
                    csrf_token = True  # توکن CSRF پیدا شد
                    break

            return {  # بازگرداندن نتایج تحلیل
                'has_csrf_token': csrf_token,  # آیا توکن CSRF دارد؟
                'method': method,  # متد فرم
                'action': action,  # آدرس action فرم
                'autocomplete': autocomplete,  # مقدار autocomplete
                'risk_level': 'High' if not csrf_token and method == 'post' else 'Medium' if method == 'get' else 'Low'
                # سطح ریسک
            }