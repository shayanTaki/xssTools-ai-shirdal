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

        def find_injection_points(self, html_content: str) -> List[Dict]:
            """یافتن نقاط تزریق احتمالی در HTML"""
            injection_points = []  # لیستی برای ذخیره نقاط تزریق
            soup = BeautifulSoup(html_content, 'html.parser')  # ایجاد parser HTML

            # بررسی فیلدهای ورودی
            for input_tag in soup.find_all(['input', 'textarea']):  # یافتن تمام فیلدهای input و textarea
                input_type = input_tag.get('type', 'text')  # نوع فیلد ورودی
                if input_type not in ['hidden', 'submit', 'button']:  # بررسی نوع فیلد
                    injection_points.append({
                        'type': 'input',  # نوع نقطه تزریق
                        'element': str(input_tag),  # المان HTML
                        'risk': 'High' if input_type in ['text', 'search', 'url'] else 'Medium'  # سطح ریسک
                    })

            # بررسی پارامترهای URL
            parsed_url = urllib.parse.urlparse(self.base_url)  # تجزیه URL
            if parsed_url.query:  # بررسی وجود پارامتر در URL
                params = urllib.parse.parse_qs(parsed_url.query)  # استخراج پارامترها
                for param in params:  # بررسی هر پارامتر
                    injection_points.append({
                        'type': 'url_parameter',  # نوع نقطه تزریق
                        'parameter': param,  # نام پارامتر
                        'risk': 'High'  # سطح ریسک
                    })

            return injection_points  # بازگرداندن لیست نقاط تزریق




        def test_xss_payload(self, url: str, param: str, payload: str) -> Dict:
            """تست یک پیلود XSS در برابر یک پارامتر"""
            try:
                # ایجاد URL تست
                parsed = urllib.parse.urlparse(url)  # تجزیه URL
                params = urllib.parse.parse_qs(parsed.query)  # استخراج پارامترها
                params[param] = [payload]  # تنظیم مقدار پارامتر با پیلود
                new_query = urllib.parse.urlencode(params, doseq=True)  # کدگذاری پارامترها
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))  # ایجاد URL جدید

                # ارسال درخواست
                response = self.session.get(test_url, verify=False, timeout=5)  # ارسال درخواست GET

                return {  # بازگرداندن نتایج تست
                    'url': test_url,  # URL تست
                    'payload': payload,  # پیلود استفاده شده
                    'reflected': payload in response.text,  # آیا پیلود در پاسخ منعکس شده است؟
                    'encoded_reflected': html.escape(payload) in response.text,
                    # آیا پیلود کدگذاری شده در پاسخ منعکس شده است؟
                    'status_code': response.status_code  # کد وضعیت HTTP
                }
            except requests.RequestException as e:  # مدیریت خطا در صورت بروز مشکل در درخواست
                return {
                    'url': test_url,  # URL تست
                    'payload': payload,  # پیلود استفاده شده
                    'error': str(e)  # پیام خطا
                }




        def generate_xss_payloads(self) -> List[str]:
            """تولید پیلودهای XSS مختلف برای تست"""
            return [  # لیستی از پیلودهای XSS
                "<script>alert('XSS')</script>",  # تزریق اسکریپت
                "<img src=x onerror=alert('XSS')>",  # تزریق از طریق ویژگی onerror
                "<svg/onload=alert('XSS')>",  # تزریق از طریق ویژگی onload
                "javascript:alert('XSS')",  # تزریق جاوا اسکریپت
                "\"><script>alert('XSS')</script>",  # تزریق اسکریپت با بستن تگ
                "';alert('XSS')//",  # تزریق جاوا اسکریپت با بستن رشته و کامنت
                "<scr<script>ipt>alert('XSS')</scr</script>ipt>",  # تزریق اسکریپت با تگ های شکسته
                "<<SCRIPT>>alert('XSS');//<<SCRIPT>>",  # تزریق اسکریپت با حروف بزرگ
                "<%<!--'%><script>alert('XSS');</script -->",  # تزریق اسکریپت با استفاده از کامنت های HTML
                "<iframe src=\"javascript:alert('XSS')\">",  # تزریق از طریق iframe
                "<object data=\"javascript:alert('XSS')\">",  # تزریق از طریق object
                "<svg><script>alert('XSS')</script></svg>",  # تزریق اسکریپت داخل تگ svg
                "<math><maction xlink:href=\"javascript:alert('XSS')\">",  # تزریق از طریق math
                "<table background=\"javascript:alert('XSS')\">",  # تزریق از طریق background
                "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">",  # تزریق از طریق data URI
            ]