import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup  # حفظ برای سازگاری
import os
import shutil
from datetime import datetime
import pytz
import base64
from urllib.parse import parse_qs, unquote
import jdatetime  
import ssl
import html as html_lib
import concurrent.futures
import random

URLS_FILE = 'Files/urls.txt'
KEYWORDS_FILE = 'Files/key.json'
OUTPUT_DIR = 'configs'
README_FILE = 'README.md'
REQUEST_TIMEOUT = 10
CONCURRENT_REQUESTS = 30  # تعداد دانلودهای همزمان صفحات وب
CONCURRENT_TESTS = 400    # افزایش تعداد تست‌های همزمان شبکه به ۴۰۰ برای سرعت مافوق صوت
TEST_TIMEOUT = 1.0       # کاهش تایم‌اوت به ۱ ثانیه (برای گیت‌هاب اکشنز بسیار عالی و کافی است)
MAX_CONFIGS_TO_TEST = 5000 # سقف تعداد تست‌ها برای تضمین پایداری زمان اجرا در گیت‌هاب
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# کامپایل سراسری ریجکس‌های عمومی برای بهینه‌سازی سرعت پردازش CPU
RE_VMESS = re.compile(r'^vmess://', re.IGNORECASE)
RE_SSR = re.compile(r'^ssr://', re.IGNORECASE)
RE_STANDARD_PROTO = re.compile(r'^(vless|trojan|hysteria2|tuic|ss)://([^@\s]+)@([^:\s/?#]+):([0-9]+)([^#\s]*)(?:#([^\s]*))?', re.IGNORECASE)

# کش حافظه موقت برای ذخیره کشور مربوط به هر آی‌پی
IP_LOCATION_CACHE = {}

def is_persian_like(text):
    if not isinstance(text, str) or not text.strip():
        return False
    has_persian_char = False
    has_latin_char = False
    for char in text:
        if '\u0600' <= char <= '\u06FF' or char in ['\u200C', '\u200D']:
            has_persian_char = True
        elif 'a' <= char.lower() <= 'z':
            has_latin_char = True
    return has_persian_char and not has_latin_char

def decode_base64(data):
    try:
        data = data.replace('_', '/').replace('-', '+').strip()
        data = re.sub(r'[^A-Za-z0-9+/]', '', data)
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return None

def should_filter_config(config):
    if 'i_love_' in config.lower():
        return True
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        return True
    if len(config) >= MAX_CONFIG_LENGTH:
        return True
    if '%2525' in config:
        return True
    return False

# ==================== بخش پارس کردن و استخراج متادیتا ====================
def parse_config_details(config):
    config = config.strip()
    try:
        if RE_VMESS.match(config):
            b64_part = config[8:]
            decoded = decode_base64(b64_part)
            if decoded:
                data = json.loads(decoded)
                port_val = data.get("port", 0)
                try:
                    port = int(port_val)
                except ValueError:
                    port = 0
                return {
                    "host": data.get("add"),
                    "port": port,
                    "is_tls": str(data.get("tls")).lower() == "tls",
                    "sni": data.get("sni") or data.get("host"),
                    "name": data.get("ps", "")
                }
        elif RE_SSR.match(config):
            b64_part = config[6:]
            decoded = decode_base64(b64_part)
            if decoded:
                parts = decoded.split('/?')
                main_parts = parts[0].split(':')
                if len(main_parts) >= 2:
                    host = main_parts[0]
                    try:
                        port = int(main_parts[1])
                    except ValueError:
                        port = 0
                    name = ""
                    if len(parts) > 1:
                        params = parse_qs(parts[1])
                        if 'remarks' in params and params['remarks']:
                            name = decode_base64(params['remarks'][0]) or ""
                    return {
                        "host": host,
                        "port": port,
                        "is_tls": False,
                        "sni": None,
                        "name": name
                    }
        else:
            match = RE_STANDARD_PROTO.match(config)
            if match:
                proto, credentials, host, port_str, query, fragment = match.groups()
                try:
                    port = int(port_str)
                except ValueError:
                    port = 0
                name = unquote(fragment) if fragment else ""
                
                is_tls = False
                sni = None
                if query:
                    params = parse_qs(query.lstrip('?'))
                    security = params.get('security', [''])[0].lower()
                    if security in ['tls', 'xtls', 'reality']:
                        is_tls = True
                    sni = params.get('sni', [None])[0]
                
                if proto.lower() in ['trojan', 'hysteria2', 'tuic']:
                    is_tls = True
                    
                return {
                    "host": host,
                    "port": port,
                    "is_tls": is_tls,
                    "sni": sni,
                    "name": name
                }
            else:
                # پشتیبانی ثانویه از فرمت قدیمی Shadowsocks
                if config.lower().startswith("ss://"):
                    main_part = config[5:]
                    name = ""
                    if "#" in main_part:
                        main_part, name_b64 = main_part.split("#", 1)
                        name = unquote(name_b64)
                    decoded = decode_base64(main_part)
                    if decoded and "@" in decoded:
                        cred, host_port = decoded.rsplit("@", 1)
                        if ":" in host_port:
                            host, port_str = host_port.split(":", 1)
                            try:
                                port = int(port_str)
                            except ValueError:
                                port = 0
                            return {
                                "host": host,
                                "port": port,
                                "is_tls": False,
                                "sni": None,
                                "name": name
                            }
    except Exception as e:
        logging.debug(f"Parser error for: {config[:30]} - {e}")
    return None

# ==================== بخش متدهای تست زنده بودن کانفیگ با IP مستقیم ====================
async def test_tcp_connection(ip, port):
    """بررسی سریع اتصال لایه انتقال TCP با IP مستقیم بدون نیاز به ریزالو مجدد"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=TEST_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def test_tls_handshake(ip, port, sni=None, host=None):
    """شبیه‌سازی هندشیک لایه امنیتی TLS با آدرس‌دهی مستقیم IP و ارسال فرستنده فرضی SNI"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=sni or host or ip),
            timeout=TEST_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def validate_config(details, ip):
    if not details or not ip or not details.get("port"):
        return False
    
    port = details["port"]
    
    # اجرای تست نوع اول (TCP)
    tcp_alive = await test_tcp_connection(ip, port)
    if not tcp_alive:
        return False
    
    # اجرای تست نوع دوم (TLS) در صورت نیاز کانفیگ
    if details.get("is_tls"):
        tls_alive = await test_tls_handshake(ip, port, details.get("sni"), details.get("host"))
        if not tls_alive:
            return False
            
    return True

# ==================== بخش موازی‌سازی رزولوشن DNS و موقعیت جغرافیایی گروهی ====================
async def resolve_dns_parallel(hosts):
    """برطرف‌سازی بسیار سریع دامنه‌ها به آی‌پى با ترد‌پول افزایش‌یافته"""
    resolved = {}
    sem = asyncio.Semaphore(100) # کنترل همزمان درخواست‌های شبکه به وب‌سرور دی‌ان‌اس
    
    # رجکس تشخیص آی‌پی برای جلوگیری از ریزالو بیهوده
    ip_pattern = re.compile(r'^(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    
    async def worker(host):
        if not host:
            return
        if ip_pattern.match(host):
            resolved[host] = host
            return
        async with sem:
            try:
                loop = asyncio.get_running_loop()
                # اجرای getaddrinfo با ترد‌پول سفارشی
                info = await loop.getaddrinfo(host, None)
                if info:
                    resolved[host] = info[0][4][0]
            except Exception:
                pass
                
    # افزایش اندازه ترد‌پول پیش‌فرض سیستم برای جلوگیری از قفل شدن لوپ DNS در پایتون
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=150))
    
    tasks = [worker(h) for h in hosts]
    await asyncio.gather(*tasks)
    return resolved

async def batch_geolocate_ips(session, ips):
    """ارسال گروهی آی‌پی‌ها به وب‌سرویس در دسته‌های ۱۰۰تایی برای افزایش چشمگیر سرعت"""
    ips_to_query = list({ip for ip in ips if ip and ip not in IP_LOCATION_CACHE})
    if not ips_to_query:
        return
        
    chunk_size = 100
    chunks = [ips_to_query[i:i + chunk_size] for i in range(0, len(ips_to_query), chunk_size)]
    
    async def fetch_chunk(chunk):
        body = [{"query": ip, "fields": "status,countryCode"} for ip in chunk]
        url = "http://ip-api.com/batch"
        try:
            async with session.post(url, json=body, timeout=5.0) as resp:
                if resp.status == 200:
                    results = await resp.json()
                    for item in results:
                        ip_val = item.get("query")
                        if item.get("status") == "success" and ip_val:
                            IP_LOCATION_CACHE[ip_val] = item.get("countryCode", "").upper()
                elif resp.status == 429:
                    logging.warning("Hit IP-API 429 rate limit.")
        except Exception as e:
            logging.error(f"Error in batch geolocation chunk: {e}")

    tasks = [fetch_chunk(c) for c in chunks]
    await asyncio.gather(*tasks)

def detect_country_sync(resolved_ips_map, host, name, country_keywords_for_naming):
    """مکان‌یابی فوق سریع و غیرشبکه‌ای بر اساس داده‌های کش و آماده‌شده پیشین"""
    if host and '.' in host:
        tld = host.split('.')[-1].lower()
        tld_mapping = {
            "de": "Germany", "fr": "France", "fi": "Finland", "nl": "Netherlands", 
            "ir": "Iran", "uk": "United Kingdom", "us": "United States", "sg": "Singapore",
            "tr": "Turkey", "jp": "Japan", "hk": "Hong Kong", "ca": "Canada", "ru": "Russia"
        }
        if tld in tld_mapping:
            return tld_mapping[tld]

    name_str = name if isinstance(name, str) else ""
    if name_str:
        for country_key, keywords in country_keywords_for_naming.items():
            if isinstance(keywords, list):
                for kw in keywords:
                    if isinstance(kw, str) and not is_persian_like(kw):
                        is_abbr = (len(kw) in [2, 3]) and kw.isupper()
                        if is_abbr:
                            if re.search(r'\b' + re.escape(kw) + r'\b', name_str, re.IGNORECASE):
                                return country_key
                        else:
                            if kw.lower() in name_str.lower():
                                return country_key

    resolved_ip = resolved_ips_map.get(host)
    if resolved_ip:
        cc = IP_LOCATION_CACHE.get(resolved_ip)
        if cc:
            for country_key, keywords in country_keywords_for_naming.items():
                if isinstance(keywords, list):
                    if cc in keywords:
                        return country_key
                        
    return None

# ==================== بخش واکشی صفحات ====================
async def fetch_url(session, url):
    """دانلود خام صفحات بدون رندر DOM برای حذف سربار CPU"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, headers=headers) as response:
            response.raise_for_status()
            html_text = await response.text()
            unescaped_content = html_lib.unescape(html_text)
            logging.info(f"Successfully fetched: {url}")
            return unescaped_content
    except Exception as e:
        logging.warning(f"Failed to fetch {url}: {e}")
        return None

def find_matches(text, compiled_patterns):
    matches = {category: set() for category in compiled_patterns}
    for category, patterns in compiled_patterns.items():
        for pattern in patterns:
            try:
                found = pattern.findall(text)
                if found:
                    cleaned_found = {item.strip() for item in found if item.strip()}
                    matches[category].update(cleaned_found)
            except Exception as e:
                logging.error(f"Error matching pattern in {category}: {e}")
    return {k: v for k, v in matches.items() if v}

def save_to_file(directory, category_name, items_set):
    if not items_set:
        return False, 0
    file_path = os.path.join(directory, f"{category_name}.txt")
    count = len(items_set)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(items_set)):
                f.write(f"{item}\n")
        logging.info(f"Saved {count} items to {file_path}")
        return True, count
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return False, 0

# ==================== تولید فایل راهنما ====================
def generate_simple_readme(protocol_counts, country_counts, all_keywords_data, github_repo_path="Argh94/V2RayAutoConfig", github_branch="main"):
    tz = pytz.timezone('Asia/Tehran')
    now = datetime.now(tz)
    jalali_date = jdatetime.datetime.fromgregorian(datetime=now)
    time_str = jalali_date.strftime("%H:%M")
    date_str = jalali_date.strftime("%d-%m-%Y")
    timestamp = f"آخرین به‌روزرسانی: {time_str} {date_str}"

    raw_github_base_url = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/{OUTPUT_DIR}"
    total_configs = sum(protocol_counts.values())

    md_content = f"""# 🚀 V2Ray AutoConfig

<p align="center">
  <img src="https://img.shields.io/github/license/{github_repo_path}?style=flat-square&color=blue" alt="License" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python" alt="Python 3.9+" />
  <img src="https://img.shields.io/github/actions/workflow/status/{github_repo_path}/scraper.yml?style=flat-square" alt="GitHub Workflow Status" />
  <img src="https://img.shields.io/github/last-commit/{github_repo_path}?style=flat-square" alt="Last Commit" />
  <br>
  <img src="https://img.shields.io/github/issues/{github_repo_path}?style=flat-square" alt="GitHub Issues" />
  <img src="https://img.shields.io/badge/Configs-{total_configs}-blue?style=flat-square" alt="Total Configs" />
  <img src="https://img.shields.io/github/stars/{github_repo_path}?style=social" alt="GitHub Stars" />
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square" alt="Project Status" />
  <img src="https://img.shields.io/badge/language-فارسی%20%26%20English-007EC6?style=flat-square" alt="Language" />
</p>

## {timestamp}

---

## 📖 درباره پروژه
این پروژه به‌صورت خودکار کانفیگ‌های VPN را از منابع مختلف جمع‌آوری، تست و دسته‌بندی می‌کند.

> **نکته:** کانفیگ‌هایی که بیش از حد طولانی یا حاوی کاراکترهای غیرضروری (مانند تعداد زیاد `%25`) باشند، برای اطمینان از کیفیت، فیلتر می‌شوند.

---

## 📁 کانفیگ‌های پروتکل‌ها
{f'در حال حاضر {total_configs} کانفیگ فعال در دسترس است.' if total_configs else 'هیچ کانفیگی یافت نشد.'}

<div align="center">

| پروتکل | تعداد | لینک دانلود |
|:-------:|:-----:|:------------:|
"""
    if protocol_counts:
        for category_name, count in sorted(protocol_counts.items()):
            file_link = f"{raw_github_base_url}/{category_name}.txt"
            md_content += f"| {category_name} | {count} | [`{category_name}.txt`]({file_link}) |\n"
    else:
        md_content += "| - | - | - |\n"

    md_content += "</div>\n\n---\n\n"
    md_content += f"""
## 🌍 کانفیگ‌های کشورها
{f'کانفیگ‌ها بر اساس نام کشورها دسته‌بندی شده‌اند.' if country_counts else 'هیچ کانفیگ مرتبط با کشوری یافت نشد.'}

<div align="center">

| کشور | تعداد | لینک دانلود |
|:----:|:-----:|:------------:|
"""
    if country_counts:
        for country_category_name, count in sorted(country_counts.items()):
            flag_image_markdown = ""
            persian_name_str = ""
            iso_code_original_case = ""

            if country_category_name in all_keywords_data:
                keywords_list = all_keywords_data[country_category_name]
                if keywords_list and isinstance(keywords_list, list):
                    iso_code_lowercase_for_url = ""
                    for item in keywords_list:
                        if isinstance(item, str) and len(item) == 2 and item.isupper() and item.isalpha():
                            iso_code_lowercase_for_url = item.lower()
                            iso_code_original_case = item
                            break
                    if iso_code_lowercase_for_url:
                        flag_image_url = f"https://flagcdn.com/w20/{iso_code_lowercase_for_url}.png"
                        flag_image_markdown = f'<img src="{flag_image_url}" width="20" alt="{country_category_name} flag"> '
                    for item in keywords_list:
                        if isinstance(item, str):
                            if iso_code_original_case and item == iso_code_original_case:
                                continue
                            if item.lower() == country_category_name.lower() and not is_persian_like(item):
                                continue
                            if len(item) in [2, 3] and item.isupper() and item.isalpha() and item != iso_code_original_case:
                                continue
                            if is_persian_like(item):
                                persian_name_str = item
                                break
            display_parts = []
            if flag_image_markdown:
                display_parts.append(flag_image_markdown)
            display_parts.append(country_category_name)
            if persian_name_str:
                display_parts.append(f"({persian_name_str})")
            country_display_text = " ".join(display_parts)
            file_link = f"{raw_github_base_url}/{country_category_name}.txt"
            md_content += f"| {country_display_text} | {count} | [`{country_category_name}.txt`]({file_link}) |\n"
    else:
        md_content += "| - | - | - |\n"

    md_content += "</div>\n\n---\n\n"
    md_content += """
## 🛠️ نحوه استفاده
1. **دانلود کانفیگ‌ها**: از جدول‌های بالا، فایل موردنظر خود را دانلود کنید.
2. فایل کانفیگ را در کلاینت خود وارد کنید و اتصال را تست کنید.
"""
    try:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")

# ==================== بدنه اصلی اجرا ====================
async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories_data = json.load(f)

    # کامپایل یک‌باره تمام ریجکس‌های پروتکل از کلیدواژه‌ها
    compiled_patterns = {}
    for cat, patterns in categories_data.items():
        if cat in PROTOCOL_CATEGORIES:
            compiled_patterns[cat] = []
            for pat_str in patterns:
                if isinstance(pat_str, str):
                    try:
                        compiled_patterns[cat].append(re.compile(pat_str, re.IGNORECASE | re.MULTILINE))
                    except re.error as e:
                        logging.error(f"Regex compiler error: {pat_str} in {cat}: {e}")

    country_keywords_for_naming = {
        cat: patterns for cat, patterns in categories_data.items() if cat not in PROTOCOL_CATEGORIES
    }

    logging.info(f"Loaded {len(urls)} URLs and compiled patterns.")

    # ۱. واکشی محتوای آدرس‌های وب به صورت همزمان (CONCURRENT_REQUESTS = 30)
    sem_fetch = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, u):
        async with sem_fetch:
            return await fetch_url(session, u)

    async with aiohttp.ClientSession() as session:
        fetched_contents = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

    # ۲. استخراج و فیلتر اولیه کانفیگ‌ها به صورت کاملاً یکتا (Deduplicated)
    all_extracted_configs = set()
    for text in fetched_contents:
        if not text:
            continue
        page_matches = find_matches(text, compiled_patterns)
        for protocol_cat, configs_found in page_matches.items():
            for cfg in configs_found:
                if not should_filter_config(cfg):
                    all_extracted_configs.add(cfg)

    logging.info(f"Total Unique configs found before parsing: {len(all_extracted_configs)}")

    # ۳. تست آسنکرون و سریع کانفیگ‌های یکتا به منظور حذف مرده‌ها
    # ابتدا آماده‌سازی جفت‌های (کانفیگ، دیتایلز)
    candidate_configs = []
    unique_hosts = set()
    for cfg in all_extracted_configs:
        details = parse_config_details(cfg)
        if details and details.get("host"):
            candidate_configs.append((cfg, details))
            unique_hosts.add(details["host"])

    # اعمال سقف و فیلتر محافظ زمان اجرا در گیت‌هاب اکشنز (در صورت انفجار تعداد کانفیگ‌ها)
    if len(candidate_configs) > MAX_CONFIGS_TO_TEST:
        logging.info(f"Sampling {MAX_CONFIGS_TO_TEST} configs out of {len(candidate_configs)} to guarantee GitHub Action speed.")
        candidate_configs = random.sample(candidate_configs, MAX_CONFIGS_TO_TEST)
        unique_hosts = {details["host"] for _, details in candidate_configs}

    logging.info(f"Total candidate configs to validate: {len(candidate_configs)}")

    # حل موازی دامنه‌ها به آی‌پی (DNS Resolution) پیش از تست شبکه
    logging.info(f"Resolving DNS for {len(unique_hosts)} unique hosts in parallel...")
    resolved_ips_map = await resolve_dns_parallel(unique_hosts)

    sem_test = asyncio.Semaphore(CONCURRENT_TESTS)
    valid_configs = []

    async def test_worker(config, details):
        async with sem_test:
            host = details["host"]
            ip = resolved_ips_map.get(host)
            if not ip:
                # اگر آی‌پی حل نشود، از ابتدا به عنوان سرور آفلاین رد می‌شود و معطل تایم‌اوت شبکه نمی‌شویم
                return None
            is_alive = await validate_config(details, ip)
            if is_alive:
                return (config, details)
            return None

    test_tasks = [test_worker(cfg, det) for cfg, det in candidate_configs]
    test_results = await asyncio.gather(*test_tasks)
    valid_configs = [res for res in test_results if res is not None]

    logging.info(f"Validation finished. Healthy configs: {len(valid_configs)}/{len(candidate_configs)}")

    # ۴. دریافت گروهی موقعیت جغرافیایی IPهای سالم (Batch Lookup)
    unique_ips = set()
    for _, details in valid_configs:
        host = details["host"]
        ip = resolved_ips_map.get(host)
        if ip:
            unique_ips.add(ip)

    logging.info(f"Querying location for {len(unique_ips)} resolved IPs in batch mode...")
    async with aiohttp.ClientSession() as session:
        await batch_geolocate_ips(session, unique_ips)

    # ۵. دسته‌بندی پروتکل و شناسایی جغرافیایی بدون مکث شبکه
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}
    final_configs_by_country = {cat: set() for cat in country_keywords_for_naming.keys()}

    for config, details in valid_configs:
        # ذخیره بر اساس پروتکل
        for proto in PROTOCOL_CATEGORIES:
            if config.lower().startswith(proto.lower() + "://"):
                final_all_protocols[proto].add(config)
                break
        
        # مکان‌یابی هوشمند بدون مکث شبکه (Instant classification)
        detected_ctr = detect_country_sync(resolved_ips_map, details["host"], details["name"], country_keywords_for_naming)
        if detected_ctr:
            final_configs_by_country[detected_ctr].add(config)

    # ۶. ساختاردهی و نوشتن فایل‌های خروجی
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    protocol_counts = {}
    country_counts = {}

    for category, items in final_all_protocols.items():
        saved, count = save_to_file(OUTPUT_DIR, category, items)
        if saved:
            protocol_counts[category] = count
    for category, items in final_configs_by_country.items():
        saved, count = save_to_file(OUTPUT_DIR, category, items)
        if saved:
            country_counts[category] = count

    generate_simple_readme(protocol_counts, country_counts, categories_data,
                          github_repo_path="Argh94/V2RayAutoConfig",
                          github_branch="main")

    logging.info("--- Script Finished Successfully ---")

if __name__ == "__main__":
    asyncio.run(main())
