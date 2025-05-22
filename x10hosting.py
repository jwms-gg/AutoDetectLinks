import requests
import os
import random
from loguru import logger
from utils import generate_user_agents


def get_cookies():
    """Retrieve cookies from environment variable and validate format."""
    # Retrieve X10HOSTING_COOKIES environment variable
    cookies_str = os.environ.get("X10HOSTING_COOKIES", "")
    # Validate environment variable exists
    if not cookies_str:
        logger.error("X10HOSTING_COOKIES environment variable not found")
        raise ValueError("Please set the X10HOSTING_COOKIES environment variable")

    # Split cookie string into individual values, stripping whitespace and filtering empty entries
    cookies_list = [c.strip() for c in cookies_str.split(";") if c.strip()]
    # Ensure at least two non-empty cookie values exist (minimum for a valid group)
    if len(cookies_list) < 2:
        logger.error("Invalid cookie format: at least two non-empty values required")
        raise ValueError("Invalid cookie format: expected format 'value1;value2;...'")

    # Group cookie values into pairs (each group contains two related cookies)
    groups = [cookies_list[i : i + 2] for i in range(0, len(cookies_list), 2)]
    # Filter to keep only groups with exactly two values (valid cookie pairs)
    valid_groups = [g for g in groups if len(g) == 2]
    # Validate at least one valid cookie group exists
    if not valid_groups:
        logger.error(
            "No valid cookie groups found (each group must contain two values)"
        )
        raise ValueError("Invalid cookie format: each group must contain two values")

    # Randomly select a valid cookie group (supports rotation if multiple groups exist)
    selected_group = random.choice(valid_groups)
    # Final validation to ensure selected group has both required cookies
    if len(selected_group) < 2:
        logger.error("Cookie group must contain two values")
        raise ValueError("Cookie group must contain two values")

    # Return formatted cookie dictionary with stripped values
    return {
        "XSRF-TOKEN": selected_group[0].strip(),
        "x10hosting_session": selected_group[1].strip(),
    }


def get_headers():
    """Generate random user agent and headers for X10hosting login."""
    user_agent = random.choice(generate_user_agents())
    return {
        "User-Agent": user_agent,
        "Referer": "https://x10hosting.com/login",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }


def main():
    session = requests.Session()
    headers = get_headers()
    cookies = get_cookies()

    try:
        response = session.get(
            "https://x10hosting.com/panel", headers=headers, cookies=cookies, timeout=10
        )
        response.raise_for_status()
        logger.info("Login successful")
    except requests.exceptions.Timeout as e:
        logger.error(f"Request timed out: {e}")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Network connection error: {e}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e}")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
