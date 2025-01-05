import base64
import binascii

import yaml


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
