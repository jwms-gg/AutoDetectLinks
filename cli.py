from itertools import chain
import os
import pathlib
import re
import ssl
import yaml
from typing import Union, Any, Optional
import requests
import datetime
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote
from clash import ClashDelayChecker
from convert import v2ray_to_clash
from model import average_delay
from utils import b64decodes, extra_headers, read_yaml
from bs4 import BeautifulSoup

from loguru import logger
from config import settings

ssl._create_default_https_context = ssl._create_unverified_context


def safe_request(url: str) -> str:
    try:
        if pathlib.Path(url).exists():
            with open(url, "r") as f:
                return f.read()
        with requests.get(
            url,
            timeout=settings.request_timeout,
            headers=extra_headers(),
        ) as r:
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
    main_div = soup.find_all("div")

    all_tags = divs + spans + codes + divs2 + span + main_div

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


def parse_proxies(
    url: str,
    content: str,
    method: str,
    type: str,
) -> list[dict[str, Any]]:
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

                try:
                    proxies.append(v2ray_to_clash(v))
                except Exception as e:
                    logger.warning(f"Convert v2ray {v} from {url}, error: {e}")
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
                url_set = set(urls)
                for url in url_set:
                    redirect_content = safe_request(url)
                    if not redirect_content:
                        continue
                    self.proxies = parse_proxies(
                        url,
                        redirect_content,
                        method,
                        type,
                    )
                    if self.proxies:
                        break
        else:
            self.proxies = parse_proxies(
                self._source.url,
                content,
                method,
                type,
            )

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
        ) or any(k in proxy["name"] for k in settings.ban)
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


def statistics_sources(sources: list[Source]):
    out = "index, link, unique/unsupported/fetched\n"
    unique_total = 0
    unsupported_total = 0
    all = 0
    source_path = "results/sources"
    if not os.path.exists(source_path):
        os.makedirs(source_path)

    for i, s in enumerate(sources):
        out += f"{i},{s._source.url},{len(s.unique_proxies)}/{len(s.unsupported_proxies)}/{len(s.proxies)}\n"
        write_result(
            f"{source_path}/{i}_unique.yml",
            {"proxies": s.unique_proxies},
            comment=f"Source {i} ({s._source.url}), {len(s.unique_proxies)}",
        )
        write_result(
            f"{source_path}/{i}_unsupported.yml",
            {"proxies": s.unsupported_proxies},
            comment=f"Source {i} ({s._source.url}), {len(s.unsupported_proxies)}",
        )
        write_result(
            f"{source_path}/{i}_fetched.yml",
            {"proxies": s.proxies},
            comment=f"Source {i} ({s._source.url}), {len(s.proxies)}",
        )
        unique_total += len(s.unique_proxies)
        unsupported_total += len(s.unsupported_proxies)
        all += len(s.proxies)

    out += f"\nTotal,,{unique_total}/{unsupported_total}/{all}\n"
    with open("results/sources.csv", "w", encoding="utf-8") as f:
        f.write(out)

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
        with open("results/" + name + ".yml", "w", encoding="utf-8") as f:
            yaml.dump({"payload": payload}, f, allow_unicode=True)


def check_nodes(save_name_prefix: str, nodes: list[dict[str, Any]]):
    logger.info(f"Checking {len(nodes)} nodes for {save_name_prefix}...")
    write_result(
        f"results/{save_name_prefix}_fetch.yml",
        {"proxies": nodes},
        comment=f"Checking proxies of {save_name_prefix}, {len(nodes)}",
    )
    delay_checker = ClashDelayChecker()
    delay_checker.check_nodes(nodes)
    alive_proxies = delay_checker.get_nodes()
    logger.info(f"Alive proxies: {len(alive_proxies)}, Delay:")
    [
        logger.info(
            f"Proxy {i+1} - {p['name']}: {average_delay(delay_checker.proxy_delay_dict[p['name']].history)}ms"
        )
        for i, p in enumerate(alive_proxies)
    ]
    write_result(
        f"results/{save_name_prefix}_alive.yml",
        {"proxies": alive_proxies},
        comment=f"Alive proxies of {save_name_prefix}, {len(alive_proxies)}",
    )
    write_result(
        "results/problem.yml",
        {"proxies": delay_checker.problem_proxies},
        comment=f"Problem proxies, {len(delay_checker.problem_proxies)}",
    )
    logger.info(f"Checking done, alive proxies: {len(alive_proxies)}")
    return alive_proxies


def main():
    logger.info("Fetching proxies sources...")
    sources = fetch_sources(
        [Source(_) for _ in settings.sources],
        settings.max_threads,
    )

    all_alives = check_nodes(
        "all",
        [n for s in sources for n in s.unique_proxies],
    )

    logger.info(f"Total alive proxies: {len(all_alives)}")
    write_all("results/all.yml", all_alives)

    # Split to 3 parts
    part_size = len(all_alives) // 3
    for i, part in enumerate(
        [all_alives[i : i + part_size] for i in range(0, part_size * 3, part_size)]
    ):
        write_all(f"results/all_{i}.yml", part)


def write_all(file_name: str, nodes: list[dict[str, Any]]):
    logger.info("Writing out all proxies...")

    logger.info("Classifying nodes by region...")
    category_nodes: dict[str, list[dict[str, Any]]] = {}
    categories: dict[str, list[str]] = settings.categories
    for ctg in categories:
        category_nodes[ctg] = []
    for n in nodes:
        ctgs: list[str] = []
        for ctg, keys in categories.items():
            for key in keys:
                if key in n["name"]:
                    ctgs.append(ctg)
                    break
            if ctgs and keys[-1] == "OVERALL":
                break
        if len(ctgs) == 1:
            category_nodes[ctgs[0]].append(clash_data(n))

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
    for n in nodes:
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
    for ctg, payload in category_nodes.items():
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
    write_result(
        file_name,
        config,
        comment=f"Proxies number: {len(nodes)}",
    )


def write_result(save_path: str, config, comment: str = None):
    logger.info(f"Writing out proxies to {save_path}...")
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime("# Update: %Y-%m-%d %H:%M\n"))
        if comment:
            f.write(f"# {comment}\n")
        f.write(yaml.dump(config, allow_unicode=True).replace("!!str ", ""))


if __name__ == "__main__":
    main()
