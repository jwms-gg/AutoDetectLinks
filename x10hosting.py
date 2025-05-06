import requests
import os
import random
from loguru import logger

session = requests.Session()

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

headers = {
    "User-Agent": user_agent,
    "Referer": "https://x10hosting.com/login",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1"
}

cookies_str = os.environ.get('X10HOSTING_COOKIES', '')
if not cookies_str:
    logger.error("未找到环境变量X10HOSTING_COOKIES")
    raise ValueError("请设置环境变量X10HOSTING_COOKIES")

cookies_list = [c.strip() for c in cookies_str.split(';') if c.strip()]
if len(cookies_list) < 2:
    logger.error("cookie格式错误：至少需要两个非空值")
    raise ValueError("cookie格式错误：格式应为'value1;value2;...'")

groups = [cookies_list[i:i+2] for i in range(0, len(cookies_list), 2)]
valid_groups = [g for g in groups if len(g) == 2]
if not valid_groups:
    logger.error("未找到有效的cookie组（每组需包含两个值）")
    raise ValueError("cookie格式错误：每组需包含两个值")

selected_group = random.choice(valid_groups)

if len(selected_group) < 2:
    logger.error("cookie组必须包含两个值")
    raise ValueError("cookie组必须包含两个值")

cookies = {
    "XSRF-TOKEN": selected_group[0].strip(),
    "x10hosting_session": selected_group[1].strip()
}

try:
    response = session.get("https://x10hosting.com/panel", headers=headers, cookies=cookies, timeout=10)
    response.raise_for_status()
    logger.info("登录成功")
except requests.exceptions.Timeout:
    logger.error("请求超时（10秒）")
except requests.exceptions.ConnectionError:
    logger.error("网络连接异常")
except requests.exceptions.HTTPError as e:
    logger.error(f"HTTP错误: {e.response.status_code} - {e}")
except Exception as e:
    logger.exception(f"未知错误: {str(e)}")
