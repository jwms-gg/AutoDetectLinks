import json
from typing import Any
from urllib.parse import quote, unquote, urlparse

from utils import b64decodes, b64decodes_safe, b64encodes, b64encodes_safe
from config import settings


class UnsupportedType(Exception):
    pass


class NotANode(Exception):
    pass


def v2ray_to_clash(proxy: str) -> dict[str, Any]:
    try:
        type, uri = proxy.split("://", 1)
    except ValueError:
        raise NotANode(proxy)

    try:
        uri = unquote(uri)
    except Exception:
        pass

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


def clash_to_v2ray(proxy: dict[str, Any]) -> str:
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
