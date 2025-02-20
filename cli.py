from itertools import chain
import pathlib
import re
import time
import yaml
import json
from typing import Union, Any, Optional
import requests
import datetime
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, urlparse
from clash import check_nodes_on_mihomo
from utils import b64encodes_safe, b64decodes, b64decodes_safe, b64encodes, read_yaml
from bs4 import BeautifulSoup

from loguru import logger
from config import settings


class UnsupportedType(Exception):
    pass


class NotANode(Exception):
    pass


session = requests.Session()
session.trust_env = False
session.headers["User-Agent"] = settings.user_agent


def safe_request(url: str) -> str:
    try:
        if pathlib.Path(url).exists():
            with open(url, "r") as f:
                return f.read()
        with session.get(url, timeout=settings.request_timeout) as r:
            if (r.status_code // 100) == 2:
                return r.text.strip().replace("\ufeff", "")
    except Exception as e:
        logger.warning(f"Cannot get {url}: \n{e}")
    return ""


def clean_div(content: str):
    soup = BeautifulSoup(content, "lxml")
    div = soup.find("div")
    return div.get_text() if div else content


def from_telegram(content: str):
    soup = BeautifulSoup(content, "html.parser")

    divs = soup.find_all("div", class_="tgme_widget_message_text")
    divs2 = soup.find_all(
        "div", class_="tgme_widget_message_text js-message_text before_footer"
    )
    spans = soup.find_all("span", class_="tgme_widget_message_text")
    codes = soup.find_all("code")
    span = soup.find_all("span")
    main = soup.find_all("div")

    all_tags = divs + spans + codes + divs2 + span + main

    v2ray_subs: list[str] = []
    pattern = r"(vless:\/\/|vmess:\/\/|ss:\/\/|trojan:\/\/|tuic:\/\/|hysteria2:\/\/)(.+?)(?=(?: |\n|\1))"
    for tag in all_tags:
        text: str = tag.get_text("\n")
        unquoted_text = unquote(text)
        matches = re.findall(
            pattern,
            unquoted_text,
            re.MULTILINE,
        )
        if matches:
            for group in matches:
                v2ray_subs.append("".join(group))

    return v2ray_subs


def parse_proxies(content: str, method: str, type: str) -> list[dict[str, Any]]:
    proxies = []
    try:
        if type == "clash":
            config = yaml.full_load(content.replace("!<str>", "!!str"))
            for p in config["proxies"]:
                if "password" in p and not isinstance(p["password"], str):
                    p["password"] = str(p["password"])
                proxies.append(p)
        elif type == "v2ray":
            v2ray_proxies = []
            if method == "base64":
                v2ray_proxies = (
                    b64decodes(clean_div(content).strip()).strip().splitlines()
                )
            elif method == "telegram":
                v2ray_proxies = from_telegram(content)
            else:
                v2ray_proxies = content.strip().splitlines()
            for v in v2ray_proxies:
                if "://" not in v:
                    continue

                if " " in v:
                    v = v.split(" ")[0]

                try:
                    proxies.append(v2ray2clash(v))
                except Exception as e:
                    logger.warning(
                        f"Cannot convert v2ray to clash from {v}, error: {e}"
                    )
    except Exception:
        pass
    return proxies


class Source:
    def __init__(self, source: dict[str, Any]) -> None:
        self._source = source
        self.proxies: list[dict[str, Any]] = []
        self.unique_proxies: list[dict[str, Any]] = []
        self.unsupported_proxies: list[dict[str, Any]] = []

    def parse(self) -> None:
        """Parse proxies from source."""
        redirect = self._source.get("redirect", None)
        method = self._source.get("method", None)
        url: str = self._source.url
        type: str = self._source.type

        if redirect == "date":
            url = datetime.datetime.now().strftime(url)

        content = safe_request(url)
        if not content:
            return

        if redirect == "https":
            # search for all https url in content
            urls = re.findall(r"https?://[^\s<*]+", content)
            if urls:
                unique_urls = []
                [unique_urls.append(item) for item in urls if item not in unique_urls]
                for url in unique_urls:
                    redirect_content = safe_request(url)
                    if not redirect_content:
                        continue
                    self.proxies = parse_proxies(redirect_content, method, type)
                    if self.proxies:
                        break
        else:
            self.proxies = parse_proxies(content, method, type)

        if len(self.proxies) != 0:
            if "max" in self._source:
                logger.info(
                    f"Get only {self._source.max} subs of {len(self.proxies)} from {url} "
                )
                self.proxies = self.proxies[: self._source.max]


class DomainTree:
    """
    A Trie tree for fast domain lookup.
    """

    def __init__(self) -> None:
        """
        Initialize DomainTree.
        """
        self.children: dict[str, DomainTree] = {}
        self.here: bool = False  # Whether there is a domain here

    def insert(self, domain: str) -> None:
        """
        Insert a domain.
        """
        segs = domain.split(".")
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: list[str]) -> None:
        """
        Insert a domain, recursive implementation.
        """
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = DomainTree()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def remove(self, domain: str) -> None:
        """
        Remove a domain.
        """
        segs = domain.split(".")
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: list[str]) -> None:
        """
        Remove a domain, recursive implementation.
        """
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            child = self.children[segs[0]]
            del segs[0]
            child._remove(segs)

    def get(self) -> list[str]:
        """
        Get all domains.
        """
        all_domain: list[str] = []
        for name, child in self.children.items():
            if child.here:
                all_domain.append(name)
            else:
                all_domain.extend([_ + "." + name for _ in child.get()])
        return all_domain


def is_fake(proxy: dict[str, Any]) -> bool:
    try:
        if "server" not in proxy:
            return True
        if "." not in proxy["server"]:
            return True
        if int(str(proxy["port"])) < 20:
            return True
        if "sni" in proxy and "google.com" in proxy["sni"].lower():
            # That's not designed for China
            proxy["sni"] = "www.bing.com"
        return any(
            [
                proxy["server"].endswith(_)
                for _ in chain(settings.fake_domains, settings.fake_ips)
            ]
        )
    except Exception:
        logger.info("Check fake node failed")
    return False


def clash_data(proxy: dict[str, Any]) -> dict[str, Any]:
    ret = proxy.copy()
    if "password" in ret and ret["password"].isdigit():
        ret["password"] = "!!str " + ret["password"]
    if "uuid" in ret and len(ret["uuid"]) != len(settings.default_uuid):
        ret["uuid"] = settings.default_uuid
    if "group" in ret:
        del ret["group"]
    if "cipher" in ret and not ret["cipher"]:
        ret["cipher"] = "auto"
    if proxy["type"] == "vless" and "flow" in ret:
        if ret["flow"].endswith("-udp443"):
            ret["flow"] = ret["flow"][:-7]
        elif ret["flow"].endswith("!"):
            ret["flow"] = ret["flow"][:-1]
    if "alpn" in ret and isinstance(ret["alpn"], str):
        # 'alpn' is not a slice
        ret["alpn"] = ret["alpn"].replace(" ", "").split(",")
    return ret


def v2ray2clash(proxy: str) -> dict[str, Any]:
    try:
        type, uri = proxy.split("://", 1)
    except ValueError:
        raise NotANode(proxy)

    # === Fix begin ===
    if not type.isascii():
        type = "".join([_ for _ in type if _.isascii()])
        proxy = type + "://" + proxy.split("://")[1]
    if type == "hy2":
        type = "hysteria2"
    # === Fix end ===

    data: dict[str, Any] = {}
    if type == "vmess":
        v = settings.vmess_example.copy()
        try:
            v.update(json.loads(b64decodes(uri)))
        except Exception:
            raise UnsupportedType("vmess", "SP")
        data = {}
        vmess2clash = {v: k for k, v in settings.clash2vmess.items()}
        for key, val in v.items():
            if key in vmess2clash:
                data[vmess2clash[key]] = val
        data["tls"] = v["tls"] == "tls"
        data["alterId"] = int(data["alterId"])
        if v["net"] == "ws":
            opts = {}
            if "path" in v:
                opts["path"] = v["path"]
            if "host" in v:
                opts["headers"] = {"Host": v["host"]}
            data["ws-opts"] = opts
        elif v["net"] == "h2":
            opts = {}
            if "path" in v:
                opts["path"] = v["path"]
            if "host" in v:
                opts["host"] = v["host"].split(",")
            data["h2-opts"] = opts
        elif v["net"] == "grpc" and "path" in v:
            data["grpc-opts"] = {"grpc-service-name": v["path"]}

    elif type == "ss":
        if "#" in uri:
            config_part, name = uri.rsplit("#", 1)
        else:
            config_part, name = uri, ""
        decoded = b64decodes_safe(config_part.split("@")[0])
        if decoded.startswith("ss://"):
            decoded = b64decodes_safe(decoded.lstrip("ss://"))
        method_passwd = (
            decoded.split(":")
            if "@" in config_part
            else decoded.split("@")[0].split(":")
        )
        cipher, password = (
            method_passwd if len(method_passwd) == 2 else (method_passwd[0], "")
        )
        if "@" in config_part:
            server_info = config_part.split("@")[1]
        else:
            server_info = b64decodes_safe(config_part).split("@")[1]
        if "?" in server_info:
            server_info = server_info.split("?")[0]
        server, port = (
            server_info.split(":") if ":" in server_info else (server_info, "")
        )
        if port.endswith("/"):
            port = port[:-1]
        data = {
            "name": unquote(name),
            "server": server,
            "port": port,
            "type": "ss",
            "password": password,
            "cipher": cipher,
        }

    elif type == "ssr":
        if "?" in proxy:
            parts = uri.split(":")
        else:
            parts = b64decodes_safe(uri).split(":")
        try:
            passwd, info = parts[-1].split("/?")
        except Exception:
            raise
        passwd = b64decodes_safe(passwd)
        data = {
            "type": "ssr",
            "server": parts[0],
            "port": parts[1],
            "protocol": parts[2],
            "cipher": parts[3],
            "obfs": parts[4],
            "password": passwd,
            "name": "",
        }
        for kv in info.split("&"):
            k_v = kv.split("=")
            if len(k_v) != 2:
                k = k_v[0]
                v = ""
            else:
                k, v = k_v
            if k == "remarks":
                data["name"] = v
            elif k == "group":
                data["group"] = v
            elif k == "obfsparam":
                data["obfs-param"] = v
            elif k == "protoparam":
                data["protocol-param"] = v

    elif type == "trojan":
        parsed = urlparse(proxy)
        data = {
            "name": unquote(parsed.fragment),
            "server": parsed.hostname,
            "port": parsed.port,
            "type": "trojan",
            "password": unquote(parsed.username),
        }
        if parsed.query:
            for kv in parsed.query.split("&"):
                k, v = kv.split("=", 1)
                if k in ("allowInsecure", "insecure"):
                    data["skip-cert-verify"] = v != "0"
                elif k == "sni":
                    data["sni"] = v
                elif k == "alpn":
                    data["alpn"] = unquote(v).split(",")
                elif k == "type":
                    data["network"] = v
                elif k == "serviceName":
                    if "grpc-opts" not in data:
                        data["grpc-opts"] = {}
                    data["grpc-opts"]["grpc-service-name"] = v
                elif k == "host":
                    if "ws-opts" not in data:
                        data["ws-opts"] = {}
                    if "headers" not in data["ws-opts"]:
                        data["ws-opts"]["headers"] = {}
                    data["ws-opts"]["headers"]["Host"] = v
                elif k == "path":
                    if "ws-opts" not in data:
                        data["ws-opts"] = {}
                    data["ws-opts"]["path"] = v

    elif type == "vless":
        parsed = urlparse(proxy)
        data = {
            "name": unquote(parsed.fragment),
            "server": parsed.hostname,
            "port": parsed.port,
            "type": "vless",
            "uuid": unquote(parsed.username),
        }
        data["tls"] = False
        if parsed.query:
            for kv in parsed.query.split("&"):
                k, v = kv.split("=", 1)
                if k in ("allowInsecure", "insecure"):
                    data["skip-cert-verify"] = v != "0"
                elif k == "sni":
                    data["servername"] = v
                elif k == "alpn":
                    data["alpn"] = unquote(v).split(",")
                elif k == "type":
                    data["network"] = v
                elif k == "serviceName":
                    if "grpc-opts" not in data:
                        data["grpc-opts"] = {}
                    data["grpc-opts"]["grpc-service-name"] = v
                elif k == "host":
                    if "ws-opts" not in data:
                        data["ws-opts"] = {}
                    if "headers" not in data["ws-opts"]:
                        data["ws-opts"]["headers"] = {}
                    data["ws-opts"]["headers"]["Host"] = v
                elif k == "path":
                    if "ws-opts" not in data:
                        data["ws-opts"] = {}
                    data["ws-opts"]["path"] = v
                elif k == "flow":
                    if v.endswith("-udp443"):
                        data["flow"] = v
                    else:
                        data["flow"] = v + "!"
                elif k == "fp":
                    data["client-fingerprint"] = v
                elif k == "security" and v == "tls":
                    data["tls"] = True
                elif k == "pbk":
                    if "reality-opts" not in data:
                        data["reality-opts"] = {}
                    data["reality-opts"]["public-key"] = v
                elif k == "sid":
                    if "reality-opts" not in data:
                        data["reality-opts"] = {}
                    data["reality-opts"]["short-id"] = v

    elif type == "hysteria2":
        parsed = urlparse(proxy)
        data = {
            "name": unquote(parsed.fragment),
            "server": parsed.hostname,
            "type": "hysteria2",
            "password": unquote(parsed.username),
        }
        if ":" in parsed.netloc:
            ports = parsed.netloc.split(":")[-1]
            if "," in ports:
                data["port"], data["ports"] = ports.split(",", 1)
            else:
                data["port"] = ports
            try:
                data["port"] = int(data["port"])
            except ValueError:
                data["port"] = 443
        else:
            data["port"] = 443
        if parsed.query:
            k = v = ""
            for kv in parsed.query.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                else:
                    v += "&" + kv
                if k == "insecure":
                    data["skip-cert-verify"] = v != "0"
                elif k == "alpn":
                    data["alpn"] = unquote(v).split(",")
                elif k in ("sni", "obfs", "obfs-password"):
                    data[k] = v
                elif k == "fp":
                    data["fingerprint"] = v

    elif type == "http":
        ...

    elif type == "hysteria":
        ...

    elif type == "socks5":
        ...

    else:
        raise UnsupportedType(type)

    data["type"] = type

    if not data["name"]:
        data["name"] = "unnamed"

    return data


def clash2v2ray(proxy: dict[str, Any]) -> str:
    data = proxy

    type = data["type"]

    if type == "vmess":
        v = settings.vmess_example.copy()
        for key, val in data.items():
            if key in settings.clash2vmess:
                v[settings.clash2vmess[key]] = val
        if v["net"] == "ws":
            if "ws-opts" in data:
                try:
                    v["host"] = data["ws-opts"]["headers"]["Host"]
                except KeyError:
                    pass
                if "path" in data["ws-opts"]:
                    v["path"] = data["ws-opts"]["path"]
        elif v["net"] == "h2":
            if "h2-opts" in data:
                if "host" in data["h2-opts"]:
                    v["host"] = ",".join(data["h2-opts"]["host"])
                if "path" in data["h2-opts"]:
                    v["path"] = data["h2-opts"]["path"]
        elif v["net"] == "grpc":
            if "grpc-opts" in data:
                if "grpc-service-name" in data["grpc-opts"]:
                    v["path"] = data["grpc-opts"]["grpc-service-name"]
        if ("tls" in data) and data["tls"]:
            v["tls"] = "tls"
        return "vmess://" + b64encodes(json.dumps(v, ensure_ascii=False))

    if type == "ss":
        passwd = b64encodes_safe(data["cipher"] + ":" + data["password"])
        return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

    if type == "ssr":
        ret = (
            ":".join(
                [str(data[_]) for _ in ("server", "port", "protocol", "cipher", "obfs")]
            )
            + b64encodes_safe(data["password"])
            + f"remarks={b64encodes_safe(data['name'])}"
        )
        for k, urlk in (
            ("obfs-param", "obfsparam"),
            ("protocol-param", "protoparam"),
            ("group", "group"),
        ):
            if k in data:
                ret += "&" + urlk + "=" + b64encodes_safe(data[k])
        return "ssr://" + ret

    if type == "trojan":
        passwd = quote(data["password"])
        name = quote(data["name"])
        ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
        if "skip-cert-verify" in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if "sni" in data:
            ret += f"sni={data['sni']}&"
        if "alpn" in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if "network" in data:
            if data["network"] == "grpc":
                ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
            elif data["network"] == "ws":
                ret += "type=ws&"
                if "ws-opts" in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError:
                        pass
                    if "path" in data["ws-opts"]:
                        ret += f"path={data['ws-opts']['path']}"
        ret = ret.rstrip("&") + "#" + name
        return ret

    if type == "vless":
        passwd = quote(data["uuid"])
        name = quote(data["name"])
        ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
        if "skip-cert-verify" in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if "servername" in data:
            ret += f"sni={data['servername']}&"
        if "alpn" in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if "network" in data:
            if data["network"] == "grpc":
                ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
            elif data["network"] == "ws":
                ret += "type=ws&"
                if "ws-opts" in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError:
                        pass
                    if "path" in data["ws-opts"]:
                        ret += f"path={data['ws-opts']['path']}"
        if "flow" in data:
            flow: str = data["flow"]
            if flow.endswith("!"):
                ret += f"flow={flow[:-1]}&"
            else:
                ret += f"flow={flow}-udp443&"
        if "client-fingerprint" in data:
            ret += f"fp={data['client-fingerprint']}&"
        if "tls" in data and data["tls"]:
            ret += "security=tls&"
        elif "reality-opts" in data:
            opts: dict[str, str] = data["reality-opts"]
            ret += f"security=reality&pbk={opts.get('public-key','')}&sid={opts.get('short-id','')}&"
        ret = ret.rstrip("&") + "#" + name
        return ret

    if type == "hysteria2":
        passwd = quote(data["password"])
        name = quote(data["name"])
        ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
        if "ports" in data:
            ret += "," + data["ports"]
        ret += "?"
        if "skip-cert-verify" in data:
            ret += f"insecure={int(data['skip-cert-verify'])}&"
        if "alpn" in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if "fingerprint" in data:
            ret += f"fp={data['fingerprint']}&"
        for k in ("sni", "obfs", "obfs-password"):
            if k in data:
                ret += f"{k}={data[k]}&"
        ret = ret.rstrip("&") + "#" + name
        return ret

    if type == "http":
        name = quote(data["name"])
        tls = True if data["tls"] else False
        return f"http://{data['server']}:{data['port']}?tls={tls}&name={name}"

    if type == "socks5":
        username = quote(data["username"])
        password = quote(data["password"])
        return f"socks5://{username}:{password}@{data['server']}:{data['port']}"

    if type == "hysteria":
        name = quote(data["name"])
        ret = f"${data['server']}:${data['port']}?"
        ret += "?"
        if "up" in data:
            ret += f"upmbps={data['up']}&"
        if "down" in data:
            ret += f"downmbps={data['down']}&"
        if "skip-cert-verify" in data:
            ret += f"insecure={int(data['skip-cert-verify'])}&"
        if "sni" in data:
            ret += f"peer={data['sni']}&"
        if "auth_str" in data:
            ret += f"auth={data['auth_str']}&"
        if "fast_open" in data:
            ret += f"fast_open={int(data['fast_open'])}&"
        if "obfs" in data:
            ret += f"obfs={data['obfs']}&"
        if "alpn" in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if "ports" in data:
            ret += f"mport={data['ports']}&"
        ret = ret.rstrip("&") + "#" + name
        return ret

    raise UnsupportedType(type)


def unique_sources(sources: list[Source]):
    seen = set()
    name_set: set[str] = set()

    def unique_name(data: dict[str, Any], max_len=30) -> None:
        for word in [w for ws in settings.banned_words for w in b64decodes(ws).split()]:
            data["name"] = data["name"].replace(word, "*" * len(word))

        if len(data["name"]) > max_len:
            data["name"] = data["name"][:max_len] + "..."

        for disp, disp_name in settings.categories_disp.items():
            if data["name"] == disp_name:
                data["name"] = disp

        if data["name"] in name_set:
            i = 0
            new_name: str = data["name"]
            while new_name in name_set:
                i += 1
                new_name = f"{data['name']} #{i}"
            data["name"] = new_name

        name_set.add(data["name"])

    def hash_proxy(data: dict[str, Any]) -> str:
        type = data["type"]
        path = ""
        if type == "vmess":
            net: str = data.get("network", "")
            path = net + ":"
            if not net:
                pass
            elif net == "ws":
                opts: dict[str, Any] = data.get("ws-opts", {})
                path += opts.get("headers", {}).get("Host", "")
                path += "/" + opts.get("path", "")
            elif net == "h2":
                opts: dict[str, Any] = data.get("h2-opts", {})
                path += ",".join(opts.get("host", []))
                path += "/" + opts.get("path", "")
            elif net == "grpc":
                path += data.get("grpc-opts", {}).get("grpc-service-name", "")
        elif type == "ss":
            opts: dict[str, Any] = data.get("plugin-opts", {})
            path = opts.get("host", "")
            path += "/" + opts.get("path", "")
        elif type == "ssr":
            path = data.get("obfs-param", "")
        elif type == "trojan":
            path = data.get("sni", "") + ":"
            net: str = data.get("network", "")
            if not net:
                pass
            elif net == "ws":
                opts: dict[str, Any] = data.get("ws-opts", {})
                path += opts.get("headers", {}).get("Host", "")
                path += "/" + opts.get("path", "")
            elif net == "grpc":
                path += data.get("grpc-opts", {}).get("grpc-service-name", "")
        elif type == "vless":
            path = data.get("sni", "") + ":"
            net: str = data.get("network", "")
            if not net:
                pass
            elif net == "ws":
                opts: dict[str, Any] = data.get("ws-opts", {})
                path += opts.get("headers", {}).get("Host", "")
                path += "/" + opts.get("path", "")
            elif net == "grpc":
                path += data.get("grpc-opts", {}).get("grpc-service-name", "")
        elif type == "hysteria2":
            path = data.get("sni", "") + ":"
            path += data.get("obfs-password", "") + ":"
        path += (
            "@"
            + ",".join(data.get("alpn", []))
            + "@"
            + data.get("password", "")
            + data.get("uuid", "")
        )
        return hash(f"{type}:{data['server']}:{data['port']}:{path}")

    for source in sources:
        logger.info(f"Merging proxies {len(source.proxies)} from '{source._source}'...")
        if not source.proxies:
            logger.info(f"Empty proxies in source {source._source}, skipping...")
            continue

        for proxy in source.proxies:
            unique_name(proxy)
            unique_hash = hash_proxy(proxy)
            if unique_hash not in seen:
                seen.add(unique_hash)
                if is_fake(proxy):
                    source.unsupported_proxies.append(proxy)
                    continue
                source.unique_proxies.append(proxy)

        logger.info(
            f"There're {len(source.proxies)-len(source.unique_proxies)} duplicate nodes, "
            f"{len(source.unsupported_proxies)} unsupported nodes by V2ray, {len(source.unique_proxies)} "
            f"normal nodes from '{source._source}'"
        )

    statistics_sources(sources)


def merge_adblock(adblock_name: str) -> dict[str, str]:
    logger.info("Parsing Adblock list ...", end="", flush=True)
    blocked: set[str] = set()
    unblock: set[str] = set()
    for item in settings.adbfurls:
        content = safe_request(item)
        for line in content.splitlines():
            line = line.strip()
            if not line or line[0] in "!#":
                continue
            elif line[:2] == "@@":
                unblock.add(line.split("^")[0].strip("@|^"))
            elif (
                line[:2] == "||"
                and ("/" not in line)
                and ("?" not in line)
                and (line[-1] == "^" or line.endswith("$all"))
            ):
                blocked.add(line.strip("al").strip("|^$"))

    for item in settings.abfwhite.urls:
        content = safe_request(item)
        for line in content.splitlines():
            line = line.strip()
            if not line or line[0] == "!":
                continue
            else:
                unblock.add(line.split("^")[0].strip("|^"))
    unblock.update(settings.abfwhite.extras)

    rules: dict[str, str] = {}

    domain_root = DomainTree()
    domain_keys: set[str] = set()
    for domain in blocked:
        if "/" in domain:
            continue
        if "*" in domain:
            domain = domain.strip("*")
            if "*" not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split(".")
        if len(segs) == 4 and domain.replace(".", "").isdigit():  # IP
            for seg in segs:  # '223.73.212.020' is not valid
                if not seg:
                    break
                if seg[0] == "0" and seg != "0":
                    break
            else:
                rules[f"IP-CIDR,{domain}/32"] = adblock_name
        else:
            domain_root.insert(domain)
    for domain in unblock:
        domain_root.remove(domain)

    for domain in domain_keys:
        rules[f"DOMAIN-KEYWORD,{domain}"] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain:
                break
        else:
            rules[f"DOMAIN-SUFFIX,{domain}"] = adblock_name

    logger.info(f"There are {len(rules)} rules in Adblock list.")
    return rules


def fetch_sources(
    sources: list[Source],
    threads: int = 10,
) -> list[Source]:
    with ThreadPoolExecutor(max_workers=threads) as executor:
        f2s = {executor.submit(s.parse): s for s in sources}
        for f in as_completed(f2s):
            s = f2s[f]
            try:
                f.result()
                logger.info(
                    f"Fetching '{s._source.url}' succeeded with subs {len(s.proxies)}",
                    end="",
                    flush=True,
                )
            except Exception as e:
                logger.warning(
                    f"Fetching '{s._source.url}' failed with exception: {e}",
                    backtrace=True,
                )
    unique_sources(sources)
    return sources


def get_region_from_ip(ip):
    api_endpoints = [
        f"https://ipapi.co/{ip}/json/",
        f"https://ipwhois.app/json/{ip}",
        f"http://www.geoplugin.net/json.gp?ip={ip}",
        f"https://api.ipbase.com/v1/json/{ip}",
    ]

    for endpoint in api_endpoints:
        try:
            response = session.get(endpoint)
            if response.status_code == 200:
                data = response.json()
                if "country" in data:
                    return data["country"]
        except Exception as e:
            print(f"Error retrieving region from {endpoint}: {e}")
    return None


def statistics_sources(sources: list[Source]):
    out = "index, link, normal/unsupported/fetched\n"
    unique_total = 0
    unsupported_total = 0
    all = 0
    for i, s in enumerate(sources):
        out += f"{i},{s._source.url},{len(s.unique_proxies)}/{len(s.unsupported_proxies)}/{len(s.proxies)}\n"
        unique_total += len(s.unique_proxies)
        unsupported_total += len(s.unsupported_proxies)
        all += len(s.proxies)
    out += f"\nTotal,,{unique_total}/{unsupported_total}/{all}\n"

    logger.info(f"Writing out statistics of sources fetched:\n{out}")


def write_rules_fragments(rules: dict):
    snippets: dict[str, list[str]] = {}
    name_map = settings.name_map
    for rpolicy in name_map.values():
        snippets[rpolicy] = []
    for config_rule, rpolicy in rules.items():
        if "," in rpolicy:
            rpolicy = rpolicy.split(",")[0]
        if rpolicy in name_map:
            snippets[name_map[rpolicy]].append(config_rule)
    for name, payload in snippets.items():
        with open("snippets/" + name + ".yml", "w", encoding="utf-8") as f:
            yaml.dump({"payload": payload}, f, allow_unicode=True)


def check_nodes_in_batches(nodes: list[dict[str, Any]]):
    all_alive_nodes = []
    if len(nodes) > settings.delay_batch:
        for i in range(0, len(nodes), settings.delay_batch):
            batch_nodes = nodes[i : i + settings.delay_batch]
            logger.info(
                f"Processing batch nodes: {len(batch_nodes)}/{len(batch_nodes)+i}/{len(nodes)}"
            )
            alives = check_nodes_on_mihomo(batch_nodes)
            logger.info(
                f"Processed batch and result: {len(alives)}/{len(batch_nodes)}/{len(batch_nodes)+i}/{len(nodes)}"
            )
            all_alive_nodes.extend(alives)
            time.sleep(1)
        time.sleep(10)
    else:
        all_alive_nodes = nodes[:]

    logger.info(f"Test final alive nodes {len(all_alive_nodes)}")
    return check_nodes_on_mihomo(all_alive_nodes)


def main():
    logger.info("Fetching proxies sources...")
    sources = fetch_sources(
        [Source(_) for _ in settings.sources],
        settings.source_fetch_threads,
    )

    logger.info("Checking alive nodes in batches...")
    all_nodes = [n for s in sources for n in s.unique_proxies]
    alive_nodes = check_nodes_in_batches(all_nodes)
    if not alive_nodes:
        raise RuntimeError("No alive nodes found, exit. And try again later.")

    logger.info(f"Found {len(alive_nodes)} alive nodes from {len(all_nodes)} nodes.")

    logger.info("Classifying nodes by region...")
    ctg_nodes_meta: dict[str, list[dict[str, Any]]] = {}
    categories: dict[str, list[str]] = settings.categories
    for ctg in categories:
        ctg_nodes_meta[ctg] = []
    for n in alive_nodes:
        ctgs: list[str] = []
        for ctg, keys in categories.items():
            for key in keys:
                if key in n["name"]:
                    ctgs.append(ctg)
                    break
            if ctgs and keys[-1] == "OVERALL":
                break
        if len(ctgs) == 1:
            ctg_nodes_meta[ctgs[0]].append(clash_data(n))
    for ctg, proxies in ctg_nodes_meta.items():
        with open("snippets/nodes_" + ctg + ".meta.yml", "w", encoding="utf-8") as f:
            yaml.dump({"proxies": proxies}, f, allow_unicode=True)

    logger.info("Read clash config template...")
    config: dict[str, Any] = read_yaml("template/config.yml")

    logger.info("Generating Adblock rules...")
    rules = merge_adblock(config["proxy-groups"][-2]["name"])

    logger.info("Writing the Clash.Meta subscription...")
    keywords: list[str] = []
    suffixes: list[str] = []
    match_rule = None
    for config_rule in config["rules"]:
        config_rule: str
        tmp = config_rule.strip().split(",")
        if len(tmp) == 2 and tmp[0] == "MATCH":
            match_rule = config_rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
            if rtype == "DOMAIN-KEYWORD":
                keywords.append(rargument)
            elif rtype == "DOMAIN-SUFFIX":
                suffixes.append(rargument)
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += "," + rresolve
        else:
            logger.info(f"规则 {config_rule} 无法被解析！")
            continue

        for kwd in keywords:
            if kwd in rargument and kwd != rargument:
                logger.info(f"{rargument} 已被 KEYWORD {kwd} 命中")
                break
        else:
            for sfx in suffixes:
                if ("." + rargument).endswith("." + sfx) and sfx != rargument:
                    logger.info(f"{rargument} 已被 SUFFIX {sfx} 命中")
                    break
            else:
                k = rtype + "," + rargument
                if k not in rules:
                    rules[k] = rpolicy
    config["rules"] = [",".join(_) for _ in rules.items()] + [match_rule]

    # Clash Meta
    proxies_meta: list[dict[str, Any]] = []
    ctg_base: dict[str, Any] = config["proxy-groups"][3].copy()
    names_clash_meta: Union[set[str], list[str]] = set()
    for n in alive_nodes:
        proxies_meta.append(clash_data(n))
        names_clash_meta.add(n["name"])
    names_clash_meta = list(names_clash_meta)
    conf_meta = copy.deepcopy(config)

    try:
        dns_mode: Optional[str] = config["dns"]["enhanced-mode"]
    except Exception:
        dns_mode: Optional[str] = None
    else:
        config["dns"]["enhanced-mode"] = "fake-ip"

    # Meta
    config = conf_meta
    config["proxies"] = proxies_meta
    for group in config["proxy-groups"]:
        if not group["proxies"]:
            group["proxies"] = names_clash_meta

    config["proxy-groups"][-1]["proxies"] = []
    ctg_selects: list[str] = config["proxy-groups"][-1]["proxies"]
    for ctg, payload in ctg_nodes_meta.items():
        if ctg in settings.categories_disp:
            disp = ctg_base.copy()
            disp["name"] = settings.categories_disp[ctg]
            if not payload:
                disp["proxies"] = ["REJECT"]
            else:
                disp["proxies"] = [_["name"] for _ in payload]
            config["proxy-groups"].append(disp)
            ctg_selects.append(disp["name"])
    if dns_mode:
        config["dns"]["enhanced-mode"] = dns_mode
    with open("list.meta.yml", "w", encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime("# Update: %Y-%m-%d %H:%M\n"))
        f.write(yaml.dump(config, allow_unicode=True).replace("!!str ", ""))
    with open("snippets/nodes.meta.yml", "w", encoding="utf-8") as f:
        f.write(
            yaml.dump({"proxies": proxies_meta}, allow_unicode=True).replace(
                "!!str ", ""
            )
        )

    write_rules_fragments(rules)


if __name__ == "__main__":
    main()
