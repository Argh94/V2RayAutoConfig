import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os
import shutil
from datetime import datetime
import pytz
import base64
from urllib.parse import parse_qs, unquote
import jdatetime  

URLS_FILE = 'Files/urls.txt'
KEYWORDS_FILE = 'Files/key.json'
OUTPUT_DIR = 'configs'
README_FILE = 'README.md'
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

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
        data = data.replace('_', '/').replace('-', '+')
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return None

def get_vmess_name(vmess_link):
    if not vmess_link.startswith("vmess://"):
        return None
    try:
        b64_part = vmess_link[8:]
        decoded_str = decode_base64(b64_part)
        if decoded_str:
            vmess_json = json.loads(decoded_str)
            return vmess_json.get('ps')
    except Exception as e:
        logging.warning(f"Failed to parse Vmess name from {vmess_link[:30]}...: {e}")
    return None

def get_ssr_name(ssr_link):
    if not ssr_link.startswith("ssr://"):
        return None
    try:
        b64_part = ssr_link[6:]
        decoded_str = decode_base64(b64_part)
        if not decoded_str:
            return None
        parts = decoded_str.split('/?')
        if len(parts) < 2:
            return None
        params_str = parts[1]
        params = parse_qs(params_str)
        if 'remarks' in params and params['remarks']:
            remarks_b64 = params['remarks'][0]
            return decode_base64(remarks_b64)
    except Exception as e:
        logging.warning(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}")
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

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            text_content = ""
            for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td']):
                text_content += element.get_text(separator='\n', strip=True) + "\n"
            if not text_content:
                text_content = soup.get_text(separator=' ', strip=True)
            logging.info(f"Successfully fetched: {url}")
            return url, text_content
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories_data):
    matches = {category: set() for category in categories_data}
    for category, patterns in categories_data.items():
        for pattern_str in patterns:
            if not isinstance(pattern_str, str):
                continue
            try:
                is_protocol_pattern = any(proto_prefix in pattern_str for proto_prefix in [p.lower() + "://" for p in PROTOCOL_CATEGORIES])
                if category in PROTOCOL_CATEGORIES or is_protocol_pattern:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    if found:
                        cleaned_found = {item.strip() for item in found if item.strip()}
                        matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}' in category '{category}': {e}")
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
این پروژه به‌صورت خودکار کانفیگ‌های VPN (پروتکل‌های مختلف مانند V2Ray، Trojan و Shadowsocks) را از منابع مختلف جمع‌آوری و دسته‌بندی می‌کند. هدف ما ارائه کانفیگ‌های به‌روز و قابل اعتماد برای کاربران است.

> **نکته:** کانفیگ‌هایی که بیش از حد طولانی یا حاوی کاراکترهای غیرضروری (مانند تعداد زیاد `%25`) باشند، برای اطمینان از کیفیت، فیلتر می‌شوند.

---

## 📁 کانفیگ‌های پروتکل‌ها
{f'در حال حاضر {total_configs} کانفیگ در دسترس است.' if total_configs else 'هیچ کانفیگ پروتکلی یافت نشد.'}

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
1. **دانلود کانفیگ‌ها**: از جدول‌های بالا، فایل موردنظر خود (بر اساس پروتکل یا کشور) را دانلود کنید.
2. **کلاینت‌های پیشنهادی**:
   - **V2Ray**: [v2rayNG](https://github.com/2dust/v2rayNG) (اندروید)، [Hiddify](https://github.com/hiddify/hiddify-app/releases) (مک)، [V2RayN](https://github.com/2dust/v2rayN/releases) (ویندوز)
   - **NekoRey_pro**: [NekoRey](https://github.com/Mahdi-zarei/nekoray/releases) (مک)، [Karing](https://github.com/KaringX/karing/releases)
   - **sing-box**: [Sing-Box](https://github.com/SagerNet/sing-box/releases)
3. فایل کانفیگ را در کلاینت خود وارد کنید و اتصال را تست کنید.

> **توصیه**: برای بهترین عملکرد، کانفیگ‌ها را به‌صورت دوره‌ای بررسی و به‌روزرسانی کنید.

---

## 🤝 مشارکت
اگر مایل به مشارکت در پروژه هستید، می‌توانید:
- منابع جدید برای جمع‌آوری کانفیگ‌ها پیشنهاد دهید (فایل `urls.txt`).
- الگوهای جدید برای پروتکل‌ها یا کشورها اضافه کنید (فایل `key.json`).
- با ارسال Pull Request یا Issue در [گیت‌هاب](https://github.com/Argh94/V2RayAutoConfig) به بهبود پروژه کمک کنید.

---

## 📢 توجه
- این پروژه صرفاً برای اهداف آموزشی و تحقیقاتی ارائه شده است.
- لطفاً از کانفیگ‌ها به‌صورت مسئولانه و مطابق با قوانین کشور خود استفاده کنید.
- برای گزارش مشکلات یا پیشنهادات، از بخش [Issues](https://github.com/Argh94/V2RayAutoConfig/issues) استفاده کنید.
"""

    try:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")

async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories_data = json.load(f)

    protocol_patterns_for_matching = {
        cat: patterns for cat, patterns in categories_data.items() if cat in PROTOCOL_CATEGORIES
    }
    country_keywords_for_naming = {
        cat: patterns for cat, patterns in categories_data.items() if cat not in PROTOCOL_CATEGORIES
    }
    country_category_names = list(country_keywords_for_naming.keys())

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories_data)} total categories from key.json.")

    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url_to_fetch):
        async with sem:
            return await fetch_url(session, url_to_fetch)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}

    logging.info("Processing pages for config name association...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_protocol_matches = find_matches(text, protocol_patterns_for_matching)
        all_page_configs_after_filter = set()
        for protocol_cat_name, configs_found in page_protocol_matches.items():
            if protocol_cat_name in PROTOCOL_CATEGORIES:
                for config in configs_found:
                    if should_filter_config(config):
                        continue
                    all_page_configs_after_filter.add(config)
                    final_all_protocols[protocol_cat_name].add(config)

        for config in all_page_configs_after_filter:
            name_to_check = None
            if '#' in config:
                try:
                    potential_name = config.split('#', 1)[1]
                    name_to_check = unquote(potential_name).strip()
                    if not name_to_check:
                        name_to_check = None
                except IndexError:
                    pass

            if not name_to_check:
                if config.startswith('ssr://'):
                    name_to_check = get_ssr_name(config)
                elif config.startswith('vmess://'):
                    name_to_check = get_vmess_name(config)

            if not name_to_check:
                continue

            current_name_to_check_str = name_to_check if isinstance(name_to_check, str) else ""

            for country_name_key, keywords_for_country_list in country_keywords_for_naming.items():
                text_keywords_for_country = []
                if isinstance(keywords_for_country_list, list):
                    for kw in keywords_for_country_list:
                        if isinstance(kw, str):
                            is_potential_emoji_or_short_code = (1 <= len(kw) <= 7)
                            is_alphanumeric = kw.isalnum()
                            if not (is_potential_emoji_or_short_code and not is_alphanumeric):
                                if not is_persian_like(kw):
                                    text_keywords_for_country.append(kw)
                                elif kw.lower() == country_name_key.lower():
                                    if kw not in text_keywords_for_country:
                                        text_keywords_for_country.append(kw)
                for keyword in text_keywords_for_country:
                    match_found = False
                    if not isinstance(keyword, str):
                        continue
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)
                    if is_abbr:
                        pattern = r'\b' + re.escape(keyword) + r'\b'
                        if re.search(pattern, current_name_to_check_str, re.IGNORECASE):
                            match_found = True
                    else:
                        if keyword.lower() in current_name_to_check_str.lower():
                            match_found = True
                    if match_found:
                        final_configs_by_country[country_name_key].add(config)
                        break
                if match_found:
                    break

    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving files to directory: {OUTPUT_DIR}")

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

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
