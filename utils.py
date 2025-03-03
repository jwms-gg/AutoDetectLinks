import base64
import binascii
import random
import re

import requests
import yaml

from config import settings


def b64encodes(s: str):
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def b64encodes_safe(s: str):
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8")


def b64decodes(s: str):
    ss = s + "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(ss.encode("utf-8")).decode("utf-8")
    except UnicodeDecodeError:
        raise
    except binascii.Error:
        raise


def b64decodes_safe(s: str):
    ss = s + "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(ss.encode("utf-8")).decode("utf-8")
    except UnicodeDecodeError:
        raise
    except binascii.Error:
        raise


def read_yaml(file_path: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError:
        raise


def is_base64(s):
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

    if base64_pattern.match(s):
        return True
    else:
        return False


def generate_user_agents():
    user_agents = []
    bases = [
        "Mozilla/5.0 ({system}) AppleWebKit/537.36 (KHTML, like Gecko) {browser}/{version} Safari/537.36 clash-verge/v2.1.1",
        "Mozilla/5.0 ({system}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Mobile/15E148 Safari/604.1 clash-verge/v2.1.1",
    ]
    systems = [
        "Windows NT 10.0; Win64; x64",
        "Macintosh; Intel Mac OS X 10_15_7",
        "Linux; Android 8.0.0; Plume L2",
        "iPhone; CPU iPhone OS 16_0 like Mac OS X",
    ]
    browsers = [
        ("Chrome", [99, 100, 110, 116]),
        ("Safari", [12, 13, 14, 15]),
        ("Opera", [50, 60, 70, 80]),
        ("Brave", [1, 1.2, 1.3, 1.5]),
    ]

    for _ in range(100):
        system = random.choice(systems)
        browser, versions = random.choice(browsers)
        version = random.choice(versions)
        base = random.choice(bases)
        user_agents.append(base.format(system=system, browser=browser, version=version))

    return user_agents


def extra_headers(extra: dict = {}):
    return {
        "User-Agent": random.choice(generate_user_agents()),
    }.update(**extra)


def get_region_from_ip(ip):
    api_endpoints = [
        f"https://ipapi.co/{ip}/json/",
        f"https://ipwhois.app/json/{ip}",
        f"http://www.geoplugin.net/json.gp?ip={ip}",
        f"https://api.ipbase.com/v1/json/{ip}",
    ]

    for endpoint in api_endpoints:
        try:
            response = requests.get(
                endpoint,
                headers={"User-Agent": random.choice(generate_user_agents())},
                timeout=settings.request_timeout,
            )
            if response.status_code == 200:
                data = response.json()
                if "country" in data:
                    return data["country"]
        except Exception as e:
            print(f"Error retrieving region from {endpoint}: {e}")
    return None
