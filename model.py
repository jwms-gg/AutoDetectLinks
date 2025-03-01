from typing import List, Dict, Optional
from pydantic import BaseModel
from datetime import datetime


# 定义模型
class HistoryItem(BaseModel):
    time: datetime
    delay: int


class UrlStatus(BaseModel):
    alive: bool
    history: List[HistoryItem]


class ProxyItem(BaseModel):
    alive: bool = False
    dialer_proxy: str = ""
    extra: Optional[Dict[str, UrlStatus]] = None
    history: Optional[List[HistoryItem]] = None
    id: str = ""
    interface: str = ""
    mptcp: bool = False
    name: str = ""
    routing_mark: int = 0
    smux: bool = False
    tfo: bool = False
    type: str = ""
    udp: bool = False
    uot: bool = False
    xudp: bool = False


class Proxies(BaseModel):
    proxies: Dict[str, ProxyItem]


def calculate_average_delay(history: List[HistoryItem]) -> Optional[float]:
    """计算代理节点的平均延迟"""
    delays = [item.delay for item in history if item.delay > 0]
    if not delays:
        return None  # 排除所有延迟为0的情况
    return sum(delays) / len(delays)


def sort_proxies(proxies_data: dict) -> List[ProxyItem]:
    """对代理节点排序，并排除延迟为0的节点"""
    proxies = Proxies.model_validate(proxies_data).proxies
    proxy_list = list(proxies.values())

    # 计算每个代理的有效延迟
    proxies_with_delay = []
    for proxy in proxy_list:
        if not proxy.history:
            continue  # 跳过没有历史记录的代理
        avg_delay = calculate_average_delay(proxy.history)
        if avg_delay is not None:
            proxies_with_delay.append({"proxy": proxy, "avg_delay": avg_delay})

    # 按平均延迟从小到大排序
    sorted_proxies = sorted(proxies_with_delay, key=lambda x: x["avg_delay"])

    # 提取排序后的代理节点
    return [item["proxy"] for item in sorted_proxies]
