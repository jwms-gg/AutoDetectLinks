from typing import List, Dict, Optional
from pydantic import BaseModel
from datetime import datetime


class HistoryItem(BaseModel):
    time: datetime
    delay: int


class UrlStatus(BaseModel):
    alive: bool
    history: List[HistoryItem]


class ProxyDelayItem(BaseModel):
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


class ProxyDelayList(BaseModel):
    proxies: Dict[str, ProxyDelayItem]


def average_delay(history: List[HistoryItem]) -> float:
    delays = [item.delay for item in history if item.delay > 0]
    return sum(delays) / len(delays)
