from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlparse

from utils import b64decodes, b64decodes_safe, b64encodes, b64encodes_safe
from config import settings


class UnsupportedType(Exception):
    """Exception raised when an unsupported proxy type is encountered."""
    def __init__(self, proxy_type: str, message: str = ""):
        super().__init__(f"Unsupported proxy type: {proxy_type}. {message}")
        self.proxy_type = proxy_type


class NotANode(Exception):
    """Exception raised when the input is not a valid proxy node."""
    def __init__(self, proxy: str):
        super().__init__(f"Invalid proxy format: {proxy}")
        self.proxy = proxy


def _parse_proxy_uri(proxy: str) -> Tuple[str, str]:
    """Parse proxy URI into type and URI components.

    Args:
        proxy: The proxy URI string

    Returns:
        Tuple of (proxy_type, uri)

    Raises:
        NotANode: If the proxy URI is invalid
    """
    try:
        proxy_type, uri = proxy.split("://", 1)
    except ValueError as e:
        raise NotANode(proxy) from e

    # Normalize proxy type
    if not proxy_type.isascii():
        proxy_type = "".join([_ for _ in proxy_type if _.isascii()])
    if proxy_type == "hy2":
        proxy_type = "hysteria2"

    try:
        uri = unquote(uri)
    except Exception:
        pass

    return proxy_type, uri


def v2ray_to_clash(proxy: str) -> Dict[str, Any]:
    """Convert V2Ray proxy configuration to Clash format.

    Args:
        proxy: The V2Ray proxy URI string

    Returns:
        Dictionary containing Clash-compatible proxy configuration

    Raises:
        UnsupportedType: If the proxy type is not supported
        NotANode: If the proxy URI is invalid
    """
    proxy_type, uri = _parse_proxy_uri(proxy)
    data: Dict[str, Any] = {}
    if proxy_type == "vmess":
        v = settings.vmess_example.copy()
        try:
            decode_uri = json.loads(b64decodes(uri))
            v.update(decode_uri)
            if 'host' in v and not v["host"] and "add" in v:
                if not v["add"].replace(".", "").isdigit():
                    v["host"] = v["add"]
            if not v["scy"]:
                v["scy"] = settings.vmess_example["scy"]
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
            if "host" in v and v["host"]:
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

    elif proxy_type == "ss":
        # https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme
        if "#" in uri:
            config_part, name = uri.split("#", 1)
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
            server_info.rsplit(":", 1) if ":" in server_info else (server_info, "")
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

    elif proxy_type == "ssr":
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

    elif proxy_type == "trojan":
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

    elif proxy_type == "vless":
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
                    data["ws-opts"]["path"] = unquote(v)
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

    elif proxy_type == "hysteria2":
        # https://v2.hysteria.network/docs/developers/URI-Scheme/
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

    elif proxy_type.startswith("http"):
        # http://username:password@host:port?tls=1#name
        parsed = urlparse(proxy)
        data = {
            "name": unquote(parsed.fragment),
            "server": parsed.hostname,
            "port": parsed.port,
            "type": "http",
            # "username": unquote(parsed.username),
            # "password": unquote(parsed.password),
        }
        if proxy_type.startswith("https"):
            data["tls"] = True
            data["skip-cert-verify"] = False
            proxy_type = "http"
        if data["name"] == "":
            data["name"] = proxy
        if parsed.query:
            for kv in parsed.query.split("&"):
                k, v = kv.split("=", 1)
                if k == "tls":
                    data["tls"] = v != "0"

    elif proxy_type == "hysteria":
        # https://v1.hysteria.network/docs/uri-scheme/
        # hysteria://host:port?protocol=udp&auth=123456&peer=sni.domain&insecure=1&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=123456#remarks
        parsed = urlparse(proxy)
        data = {
            "name": unquote(parsed.fragment),
            "server": parsed.hostname,
            "type": "hysteria",
            # "password": unquote(parsed.username),
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
                elif k == "peer":
                    data["sni"] = v
                elif k == "auth":
                    data["auth_str"] = v
                elif k == "upmbps":
                    data["up"] = v
                elif k == "downmbps":
                    data["down"] = v
                elif k == "fast_open":
                    data["fast_open"] = v != "0"
                elif k == "alpn":
                    data["alpn"] = unquote(v).split(",")
                elif k in ("obfs", "obfsParam"):
                    data["obfs"] = v
                elif k == "mport":
                    data["ports"] = v
                elif k == "fp":
                    data["fingerprint"] = v

    elif proxy_type == "socks5":
        # socks5://username:password@host:port
        parsed = urlparse(proxy)
        data = {
            "name": unquote(parsed.fragment),
            "server": parsed.hostname,
            "port": parsed.port,
            "type": "socks5",
        }
        if data["name"] == "":
            data["name"] = proxy

    else:
        raise UnsupportedType(proxy_type)

    data["type"] = proxy_type

    if not data["name"]:
        data["name"] = "unnamed"

    return data


def clash_to_v2ray(proxy: Dict[str, Any]) -> str:
    """Convert Clash proxy configuration to V2Ray format.

    Args:
        proxy: Dictionary containing Clash proxy configuration

    Returns:
        V2Ray-compatible proxy URI string

    Raises:
        UnsupportedType: If the proxy type is not supported
    """
    data = proxy
    proxy_type = data["type"]

    if proxy_type == "vmess":
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

    if proxy_type == "ss":
        passwd = b64encodes_safe(data["cipher"] + ":" + data["password"])
        return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

    if proxy_type == "ssr":
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

    if proxy_type == "trojan":
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

    if proxy_type == "vless":
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

    if proxy_type == "hysteria2":
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

    if proxy_type == "http":
        name = quote(data["name"])
        tls = True if data["tls"] else False
        return f"http://{data['server']}:{data['port']}?tls={tls}&name={name}"

    if proxy_type == "socks5":
        username = quote(data["username"])
        password = quote(data["password"])
        return f"socks5://{username}:{password}@{data['server']}:{data['port']}"

    if proxy_type == "hysteria":
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

    raise UnsupportedType(proxy_type)


if __name__ == "__main__":
    v2ray_to_clash("")
