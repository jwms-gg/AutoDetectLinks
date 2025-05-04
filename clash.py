import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
import subprocess
import tempfile
import threading
import time
import urllib.parse
import json
import re
import yaml
import httpx
import asyncio
from typing import Any, Optional
import sys
import requests
from pathlib import Path
import platform
import os
from datetime import datetime

from model import ProxyDelayList, ProxyDelayItem, average_delay
from ports import PortPool
from utils import b64decodes_safe, extra_headers
from config import settings
from loguru import logger
from requests_html import HTMLSession

# Clash 配置文件的基础结构
clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "tcp-concurrent": True,
    "unified-delay": True,
    "geodata-mode": True,
    "geox-url": {
        "geoip": settings.geoip,
        "geosite": settings.geosite,
        "mmdb": settings.mmdb,
        "asn": settings.asn
    },
    "dns": {
        "enable": True,
        "ipv6": False,
        "default-nameserver": [
            "223.5.5.5",
            "223.6.6.6",
            "1.1.1.1",
            "8.8.8.8",
        ],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": [
            "https://223.5.5.5/dns-query",
            "https://223.6.6.6/dns-query",
        ],
        "fallback": [
            "1.1.1.1",
            "8.8.8.8",
        ],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "CN",
            "ipcidr": [
                "240.0.0.0/4",
                "127.0.0.1/8",
                "0.0.0.0/32",
            ],
        },
    },
    "proxies": [],
    "proxy-groups": [
        {
            "name": "节点选择",
            "type": "select",
            "proxies": ["自动选择", "故障转移", "DIRECT", "手动选择"],
        },
        {
            "name": "自动选择",
            "type": "url-test",
            "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
            "proxies": [],
            "url": f"{settings.delay_url_test}",
            "interval": 300,
            "tolerance": 50,
        },
        {
            "name": "故障转移",
            "type": "fallback",
            "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
            "proxies": [],
            "url": f"{settings.delay_url_test}",
            "interval": 300,
        },
        {"name": "手动选择", "type": "select", "proxies": []},
    ],
    "rules": [
        "DOMAIN,app.adjust.com,DIRECT",
        "DOMAIN,bdtj.tagtic.cn,DIRECT",
        "DOMAIN,log.mmstat.com,DIRECT",
        "DOMAIN,sycm.mmstat.com,DIRECT",
        "DOMAIN-SUFFIX,blog.google,DIRECT",
        "DOMAIN-SUFFIX,googletraveladservices.com,DIRECT",
        "DOMAIN,dl.google.com,DIRECT",
        "DOMAIN,dl.l.google.com,DIRECT",
        "DOMAIN,fonts.googleapis.com,DIRECT",
        "DOMAIN,fonts.gstatic.com,DIRECT",
        "DOMAIN,mtalk.google.com,DIRECT",
        "DOMAIN,alt1-mtalk.google.com,DIRECT",
        "DOMAIN,alt2-mtalk.google.com,DIRECT",
        "DOMAIN,alt3-mtalk.google.com,DIRECT",
        "DOMAIN,alt4-mtalk.google.com,DIRECT",
        "DOMAIN,alt5-mtalk.google.com,DIRECT",
        "DOMAIN,alt6-mtalk.google.com,DIRECT",
        "DOMAIN,alt7-mtalk.google.com,DIRECT",
        "DOMAIN,alt8-mtalk.google.com,DIRECT",
        "DOMAIN,fairplay.l.qq.com,DIRECT",
        "DOMAIN,livew.l.qq.com,DIRECT",
        "DOMAIN,vd.l.qq.com,DIRECT",
        "DOMAIN,analytics.strava.com,DIRECT",
        "DOMAIN,msg.umeng.com,DIRECT",
        "DOMAIN,msg.umengcloud.com,DIRECT",
        "PROCESS-NAME,com.ximalaya.ting.himalaya,节点选择",
        "DOMAIN-SUFFIX,himalaya.com,节点选择",
        "PROCESS-NAME,deezer.android.app,节点选择",
        "DOMAIN-SUFFIX,deezer.com,节点选择",
        "DOMAIN-SUFFIX,dzcdn.net,节点选择",
        "PROCESS-NAME,com.tencent.ibg.joox,节点选择",
        "PROCESS-NAME,com.tencent.ibg.jooxtv,节点选择",
        "DOMAIN-SUFFIX,joox.com,节点选择",
        "DOMAIN-KEYWORD,jooxweb-api,节点选择",
        "PROCESS-NAME,com.skysoft.kkbox.android,节点选择",
        "DOMAIN-SUFFIX,kkbox.com,节点选择",
        "DOMAIN-SUFFIX,kkbox.com.tw,节点选择",
        "DOMAIN-SUFFIX,kfs.io,节点选择",
        "PROCESS-NAME,com.pandora.android,节点选择",
        "DOMAIN-SUFFIX,pandora.com,节点选择",
        "PROCESS-NAME,com.soundcloud.android,节点选择",
        "DOMAIN-SUFFIX,p-cdn.us,节点选择",
        "DOMAIN-SUFFIX,sndcdn.com,节点选择",
        "DOMAIN-SUFFIX,soundcloud.com,节点选择",
        "PROCESS-NAME,com.spotify.music,节点选择",
        "DOMAIN-SUFFIX,pscdn.co,节点选择",
        "DOMAIN-SUFFIX,scdn.co,节点选择",
        "DOMAIN-SUFFIX,spotify.com,节点选择",
        "DOMAIN-SUFFIX,spoti.fi,节点选择",
        "DOMAIN-KEYWORD,spotify.com,节点选择",
        "DOMAIN-KEYWORD,-spotify-com,节点选择",
        "PROCESS-NAME,com.aspiro.tidal,节点选择",
        "DOMAIN-SUFFIX,tidal.com,节点选择",
        "PROCESS-NAME,com.google.android.apps.youtube.music,节点选择",
        "PROCESS-NAME,com.google.android.youtube.tvmusic,节点选择",
        "PROCESS-NAME,tv.abema,节点选择",
        "DOMAIN-SUFFIX,abema.io,节点选择",
        "DOMAIN-SUFFIX,abema.tv,节点选择",
        "DOMAIN-SUFFIX,ameba.jp,节点选择",
        "DOMAIN-SUFFIX,hayabusa.io,节点选择",
        "DOMAIN-KEYWORD,abematv.akamaized.net,节点选择",
        "PROCESS-NAME,com.channel4.ondemand,节点选择",
        "DOMAIN-SUFFIX,c4assets.com,节点选择",
        "DOMAIN-SUFFIX,channel4.com,节点选择",
        "PROCESS-NAME,com.amazon.avod.thirdp,节点选择",
        "DOMAIN-SUFFIX,aiv-cdn.net,节点选择",
        "DOMAIN-SUFFIX,aiv-delivery.net,节点选择",
        "DOMAIN-SUFFIX,amazonvideo.com,节点选择",
        "DOMAIN-SUFFIX,primevideo.com,节点选择",
        "DOMAIN-SUFFIX,media-amazon.com,节点选择",
        "DOMAIN,atv-ps.amazon.com,节点选择",
        "DOMAIN,fls-na.amazon.com,节点选择",
        "DOMAIN,avodmp4s3ww-a.akamaihd.net,节点选择",
        "DOMAIN,d25xi40x97liuc.cloudfront.net,节点选择",
        "DOMAIN,dmqdd6hw24ucf.cloudfront.net,节点选择",
        "DOMAIN,dmqdd6hw24ucf.cloudfront.net,节点选择",
        "DOMAIN,d22qjgkvxw22r6.cloudfront.net,节点选择",
        "DOMAIN,d1v5ir2lpwr8os.cloudfront.net,节点选择",
        "DOMAIN,d27xxe7juh1us6.cloudfront.net,节点选择",
        "DOMAIN-KEYWORD,avoddashs,节点选择",
        "DOMAIN,linear.tv.apple.com,节点选择",
        "DOMAIN,play-edge.itunes.apple.com,节点选择",
        "PROCESS-NAME,tw.com.gamer.android.animad,节点选择",
        "DOMAIN-SUFFIX,bahamut.com.tw,节点选择",
        "DOMAIN-SUFFIX,gamer.com.tw,节点选择",
        "DOMAIN,gamer-cds.cdn.hinet.net,节点选择",
        "DOMAIN,gamer2-cds.cdn.hinet.net,节点选择",
        "PROCESS-NAME,bbc.iplayer.android,节点选择",
        "DOMAIN-SUFFIX,bbc.co.uk,节点选择",
        "DOMAIN-SUFFIX,bbci.co.uk,节点选择",
        "DOMAIN-KEYWORD,bbcfmt,节点选择",
        "DOMAIN-KEYWORD,uk-live,节点选择",
        "PROCESS-NAME,com.dazn,节点选择",
        "DOMAIN-SUFFIX,dazn.com,节点选择",
        "DOMAIN-SUFFIX,dazn-api.com,节点选择",
        "DOMAIN,d151l6v8er5bdm.cloudfront.net,节点选择",
        "DOMAIN-KEYWORD,voddazn,节点选择",
        "PROCESS-NAME,com.disney.disneyplus,节点选择",
        "DOMAIN-SUFFIX,bamgrid.com,节点选择",
        "DOMAIN-SUFFIX,disneyplus.com,节点选择",
        "DOMAIN-SUFFIX,disney-plus.net,节点选择",
        "DOMAIN-SUFFIX,disney自动选择.com,节点选择",
        "DOMAIN-SUFFIX,dssott.com,节点选择",
        "DOMAIN,cdn.registerdisney.go.com,节点选择",
        "PROCESS-NAME,com.dmm.app.movieplayer,节点选择",
        "DOMAIN-SUFFIX,dmm.co.jp,节点选择",
        "DOMAIN-SUFFIX,dmm.com,节点选择",
        "DOMAIN-SUFFIX,dmm-extension.com,节点选择",
        "PROCESS-NAME,com.tvbusa.encore,节点选择",
        "DOMAIN-SUFFIX,encoretvb.com,节点选择",
        "DOMAIN,edge.api.brightcove.com,节点选择",
        "DOMAIN,bcbolt446c5271-a.akamaihd.net,节点选择",
        "PROCESS-NAME,com.fox.now,节点选择",
        "DOMAIN-SUFFIX,fox.com,节点选择",
        "DOMAIN-SUFFIX,foxdcg.com,节点选择",
        "DOMAIN-SUFFIX,theplatform.com,节点选择",
        "DOMAIN-SUFFIX,uplynk.com,节点选择",
        "DOMAIN-SUFFIX,foxplus.com,节点选择",
        "DOMAIN,cdn-fox-networks-group-green.akamaized.net,节点选择",
        "DOMAIN,d3cv4a9a9wh0bt.cloudfront.net,节点选择",
        "DOMAIN,foxsports01-i.akamaihd.net,节点选择",
        "DOMAIN,foxsports02-i.akamaihd.net,节点选择",
        "DOMAIN,foxsports03-i.akamaihd.net,节点选择",
        "DOMAIN,staticasiafox.akamaized.net,节点选择",
        "PROCESS-NAME,com.hbo.hbonow,节点选择",
        "DOMAIN-SUFFIX,hbo.com,节点选择",
        "DOMAIN-SUFFIX,hbogo.com,节点选择",
        "DOMAIN-SUFFIX,hbonow.com,节点选择",
        "DOMAIN-SUFFIX,hbomax.com,节点选择",
        "PROCESS-NAME,hk.hbo.hbogo,节点选择",
        "DOMAIN-SUFFIX,hbogoasia.com,节点选择",
        "DOMAIN-SUFFIX,hbogoasia.hk,节点选择",
        "DOMAIN,bcbolthboa-a.akamaihd.net,节点选择",
        "DOMAIN,players.brightcove.net,节点选择",
        "DOMAIN,s3-ap-southeast-1.amazonaws.com,节点选择",
        "DOMAIN,dai3fd1oh325y.cloudfront.net,节点选择",
        "DOMAIN,44wilhpljf.execute-api.ap-southeast-1.amazonaws.com,节点选择",
        "DOMAIN,hboasia1-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia2-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia3-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia4-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia5-i.akamaihd.net,节点选择",
        "DOMAIN,cf-images.ap-southeast-1.prod.boltdns.net,节点选择",
        "DOMAIN-SUFFIX,5itv.tv,节点选择",
        "DOMAIN-SUFFIX,ocnttv.com,节点选择",
        "PROCESS-NAME,com.hulu.plus,节点选择",
        "DOMAIN-SUFFIX,hulu.com,节点选择",
        "DOMAIN-SUFFIX,huluim.com,节点选择",
        "DOMAIN-SUFFIX,hulustream.com,节点选择",
        "PROCESS-NAME,jp.happyon.android,节点选择",
        "DOMAIN-SUFFIX,happyon.jp,节点选择",
        "DOMAIN-SUFFIX,hjholdings.jp,节点选择",
        "DOMAIN-SUFFIX,hulu.jp,节点选择",
        "PROCESS-NAME,air.ITVMobilePlayer,节点选择",
        "DOMAIN-SUFFIX,itv.com,节点选择",
        "DOMAIN-SUFFIX,itvstatic.com,节点选择",
        "DOMAIN,itvpnpmobile-a.akamaihd.net,节点选择",
        "PROCESS-NAME,com.kktv.kktv,节点选择",
        "DOMAIN-SUFFIX,kktv.com.tw,节点选择",
        "DOMAIN-SUFFIX,kktv.me,节点选择",
        "DOMAIN,kktv-theater.kk.stream,节点选择",
        "PROCESS-NAME,com.linecorp.linetv,节点选择",
        "DOMAIN-SUFFIX,linetv.tw,节点选择",
        "DOMAIN,d3c7rimkq79yfu.cloudfront.net,节点选择",
        "PROCESS-NAME,com.litv.mobile.gp.litv,节点选择",
        "DOMAIN-SUFFIX,litv.tv,节点选择",
        "DOMAIN,litvfreemobile-hichannel.cdn.hinet.net,节点选择",
        "PROCESS-NAME,com.mobileiq.demand5,节点选择",
        "DOMAIN-SUFFIX,channel5.com,节点选择",
        "DOMAIN-SUFFIX,my5.tv,节点选择",
        "DOMAIN,d349g9zuie06uo.cloudfront.net,节点选择",
        "PROCESS-NAME,com.tvb.mytvsuper,节点选择",
        "DOMAIN-SUFFIX,mytvsuper.com,节点选择",
        "DOMAIN-SUFFIX,tvb.com,节点选择",
        "PROCESS-NAME,com.netflix.mediaclient,节点选择",
        "DOMAIN-SUFFIX,netflix.com,节点选择",
        "DOMAIN-SUFFIX,netflix.net,节点选择",
        "DOMAIN-SUFFIX,nflxext.com,节点选择",
        "DOMAIN-SUFFIX,nflximg.com,节点选择",
        "DOMAIN-SUFFIX,nflximg.net,节点选择",
        "DOMAIN-SUFFIX,nflxso.net,节点选择",
        "DOMAIN-SUFFIX,nflxvideo.net,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest0.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest1.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest2.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest3.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest4.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest5.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest6.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest7.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest8.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest9.com,节点选择",
        "DOMAIN-KEYWORD,dualstack.api自动选择-device-prod-nlb-,节点选择",
        "DOMAIN-KEYWORD,dualstack.ichnaea-web-,节点选择",
        "IP-CIDR,23.246.0.0/18,节点选择,no-resolve",
        "IP-CIDR,37.77.184.0/21,节点选择,no-resolve",
        "IP-CIDR,45.57.0.0/17,节点选择,no-resolve",
        "IP-CIDR,64.120.128.0/17,节点选择,no-resolve",
        "IP-CIDR,66.197.128.0/17,节点选择,no-resolve",
        "IP-CIDR,108.175.32.0/20,节点选择,no-resolve",
        "IP-CIDR,192.173.64.0/18,节点选择,no-resolve",
        "IP-CIDR,198.38.96.0/19,节点选择,no-resolve",
        "IP-CIDR,198.45.48.0/20,节点选择,no-resolve",
        "IP-CIDR,34.210.42.111/32,节点选择,no-resolve",
        "IP-CIDR,52.89.124.203/32,节点选择,no-resolve",
        "IP-CIDR,54.148.37.5/32,节点选择,no-resolve",
        "PROCESS-NAME,jp.nicovideo.android,节点选择",
        "DOMAIN-SUFFIX,dmc.nico,节点选择",
        "DOMAIN-SUFFIX,nicovideo.jp,节点选择",
        "DOMAIN-SUFFIX,nimg.jp,节点选择",
        "PROCESS-NAME,com.pccw.nowemobile,节点选择",
        "DOMAIN-SUFFIX,nowe.com,节点选择",
        "DOMAIN-SUFFIX,nowestatic.com,节点选择",
        "PROCESS-NAME,com.pbs.video,节点选择",
        "DOMAIN-SUFFIX,pbs.org,节点选择",
        "DOMAIN-SUFFIX,phncdn.com,节点选择",
        "DOMAIN-SUFFIX,phprcdn.com,节点选择",
        "DOMAIN-SUFFIX,pornhub.com,节点选择",
        "DOMAIN-SUFFIX,pornhubpremium.com,节点选择",
        "PROCESS-NAME,com.twgood.android,节点选择",
        "DOMAIN-SUFFIX,skyking.com.tw,节点选择",
        "DOMAIN,hamifans.emome.net,节点选择",
        "PROCESS-NAME,com.ss.android.ugc.trill,节点选择",
        "DOMAIN-SUFFIX,byteoversea.com,节点选择",
        "DOMAIN-SUFFIX,ibytedtos.com,节点选择",
        "DOMAIN-SUFFIX,muscdn.com,节点选择",
        "DOMAIN-SUFFIX,musical.ly,节点选择",
        "DOMAIN-SUFFIX,tiktok.com,节点选择",
        "DOMAIN-SUFFIX,tik-tokapi.com,节点选择",
        "DOMAIN-SUFFIX,tiktokcdn.com,节点选择",
        "DOMAIN-SUFFIX,tiktokv.com,节点选择",
        "DOMAIN-KEYWORD,-tiktokcdn-com,节点选择",
        "PROCESS-NAME,tv.twitch.android.app,节点选择",
        "DOMAIN-SUFFIX,jtvnw.net,节点选择",
        "DOMAIN-SUFFIX,ttvnw.net,节点选择",
        "DOMAIN-SUFFIX,twitch.tv,节点选择",
        "DOMAIN-SUFFIX,twitchcdn.net,节点选择",
        "PROCESS-NAME,com.hktve.viutv,节点选择",
        "DOMAIN-SUFFIX,viu.com,节点选择",
        "DOMAIN-SUFFIX,viu.tv,节点选择",
        "DOMAIN,api.viu.now.com,节点选择",
        "DOMAIN,d1k2us671qcoau.cloudfront.net,节点选择",
        "DOMAIN,d2anahhhmp1ffz.cloudfront.net,节点选择",
        "DOMAIN,dfp6rglgjqszk.cloudfront.net,节点选择",
        "PROCESS-NAME,com.google.android.youtube,节点选择",
        "PROCESS-NAME,com.google.android.youtube.tv,节点选择",
        "DOMAIN-SUFFIX,googlevideo.com,节点选择",
        "DOMAIN-SUFFIX,youtube.com,节点选择",
        "DOMAIN,youtubei.googleapis.com,节点选择",
        "DOMAIN-SUFFIX,biliapi.net,节点选择",
        "DOMAIN-SUFFIX,bilibili.com,节点选择",
        "DOMAIN,upos-hz-mirrorakam.akamaized.net,节点选择",
        "DOMAIN-SUFFIX,iq.com,节点选择",
        "DOMAIN,cache.video.iqiyi.com,节点选择",
        "DOMAIN,cache-video.iq.com,节点选择",
        "DOMAIN,intl.iqiyi.com,节点选择",
        "DOMAIN,intl-rcd.iqiyi.com,节点选择",
        "DOMAIN,intl-subscription.iqiyi.com,节点选择",
        "DOMAIN-KEYWORD,oversea-tw.inter.iqiyi.com,节点选择",
        "DOMAIN-KEYWORD,oversea-tw.inter.ptqy.gitv.tv,节点选择",
        "IP-CIDR,103.44.56.0/22,节点选择,no-resolve",
        "IP-CIDR,118.26.32.0/23,节点选择,no-resolve",
        "IP-CIDR,118.26.120.0/24,节点选择,no-resolve",
        "IP-CIDR,223.119.62.225/28,节点选择,no-resolve",
        "IP-CIDR,23.40.242.10/32,节点选择,no-resolve",
        "IP-CIDR,23.40.241.251/32,节点选择,no-resolve",
        "DOMAIN-SUFFIX,api.mgtv.com,节点选择",
        "DOMAIN-SUFFIX,wetv.vip,节点选择",
        "DOMAIN-SUFFIX,wetvinfo.com,节点选择",
        "DOMAIN,testflight.apple.com,节点选择",
        "DOMAIN-SUFFIX,appspot.com,节点选择",
        "DOMAIN-SUFFIX,blogger.com,节点选择",
        "DOMAIN-SUFFIX,getoutline.org,节点选择",
        "DOMAIN-SUFFIX,gvt0.com,节点选择",
        "DOMAIN-SUFFIX,gvt3.com,节点选择",
        "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,节点选择",
        "DOMAIN-SUFFIX,ytimg.com,节点选择",
        "DOMAIN-KEYWORD,google,节点选择",
        "DOMAIN-KEYWORD,.blogspot.,节点选择",
        "DOMAIN-SUFFIX,aka.ms,节点选择",
        "DOMAIN-SUFFIX,onedrive.live.com,节点选择",
        "DOMAIN,az416426.vo.msecnd.net,节点选择",
        "DOMAIN,az668014.vo.msecnd.net,节点选择",
        "DOMAIN-SUFFIX,cdninstagram.com,节点选择",
        "DOMAIN-SUFFIX,facebook.com,节点选择",
        "DOMAIN-SUFFIX,facebook.net,节点选择",
        "DOMAIN-SUFFIX,fb.com,节点选择",
        "DOMAIN-SUFFIX,fb.me,节点选择",
        "DOMAIN-SUFFIX,fbaddins.com,节点选择",
        "DOMAIN-SUFFIX,fbcdn.net,节点选择",
        "DOMAIN-SUFFIX,fbsbx.com,节点选择",
        "DOMAIN-SUFFIX,fbworkmail.com,节点选择",
        "DOMAIN-SUFFIX,instagram.com,节点选择",
        "DOMAIN-SUFFIX,m.me,节点选择",
        "DOMAIN-SUFFIX,messenger.com,节点选择",
        "DOMAIN-SUFFIX,oculus.com,节点选择",
        "DOMAIN-SUFFIX,oculuscdn.com,节点选择",
        "DOMAIN-SUFFIX,rocksdb.org,节点选择",
        "DOMAIN-SUFFIX,whatsapp.com,节点选择",
        "DOMAIN-SUFFIX,whatsapp.net,节点选择",
        "DOMAIN-SUFFIX,pscp.tv,节点选择",
        "DOMAIN-SUFFIX,periscope.tv,节点选择",
        "DOMAIN-SUFFIX,t.co,节点选择",
        "DOMAIN-SUFFIX,twimg.co,节点选择",
        "DOMAIN-SUFFIX,twimg.com,节点选择",
        "DOMAIN-SUFFIX,twitpic.com,节点选择",
        "DOMAIN-SUFFIX,twitter.com,节点选择",
        "DOMAIN-SUFFIX,x.com,节点选择",
        "DOMAIN-SUFFIX,vine.co,节点选择",
        "DOMAIN-SUFFIX,telegra.ph,节点选择",
        "DOMAIN-SUFFIX,telegram.org,节点选择",
        "IP-CIDR,91.108.4.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.8.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.12.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.16.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.20.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.56.0/22,节点选择,no-resolve",
        "IP-CIDR,149.154.160.0/20,节点选择,no-resolve",
        "IP-CIDR,2001:b28:f23d::/48,节点选择,no-resolve",
        "IP-CIDR,2001:b28:f23f::/48,节点选择,no-resolve",
        "IP-CIDR,2001:67c:4e8::/48,节点选择,no-resolve",
        "DOMAIN-SUFFIX,line.me,节点选择",
        "DOMAIN-SUFFIX,line-apps.com,节点选择",
        "DOMAIN-SUFFIX,line-scdn.net,节点选择",
        "DOMAIN-SUFFIX,naver.jp,节点选择",
        "IP-CIDR,103.2.30.0/23,节点选择,no-resolve",
        "IP-CIDR,125.209.208.0/20,节点选择,no-resolve",
        "IP-CIDR,147.92.128.0/17,节点选择,no-resolve",
        "IP-CIDR,203.104.144.0/21,节点选择,no-resolve",
        "DOMAIN-SUFFIX,amazon.co.jp,节点选择",
        "DOMAIN,d3c33hcgiwev3.cloudfront.net,节点选择",
        "DOMAIN,payments-jp.amazon.com,节点选择",
        "DOMAIN,s3-ap-northeast-1.amazonaws.com,节点选择",
        "DOMAIN,s3-ap-southeast-2.amazonaws.com,节点选择",
        "DOMAIN,a248.e.akamai.net,节点选择",
        "DOMAIN,a771.dscq.akamai.net,节点选择",
        "DOMAIN-SUFFIX,4shared.com,节点选择",
        "DOMAIN-SUFFIX,9cache.com,节点选择",
        "DOMAIN-SUFFIX,9gag.com,节点选择",
        "DOMAIN-SUFFIX,abc.com,节点选择",
        "DOMAIN-SUFFIX,abc.net.au,节点选择",
        "DOMAIN-SUFFIX,abebooks.com,节点选择",
        "DOMAIN-SUFFIX,ao3.org,节点选择",
        "DOMAIN-SUFFIX,apigee.com,节点选择",
        "DOMAIN-SUFFIX,apkcombo.com,节点选择",
        "DOMAIN-SUFFIX,apk-dl.com,节点选择",
        "DOMAIN-SUFFIX,apkfind.com,节点选择",
        "DOMAIN-SUFFIX,apkmirror.com,节点选择",
        "DOMAIN-SUFFIX,apkmonk.com,节点选择",
        "DOMAIN-SUFFIX,apkpure.com,节点选择",
        "DOMAIN-SUFFIX,aptoide.com,节点选择",
        "DOMAIN-SUFFIX,archive.is,节点选择",
        "DOMAIN-SUFFIX,archive.org,节点选择",
        "DOMAIN-SUFFIX,archiveofourown.com,节点选择",
        "DOMAIN-SUFFIX,archiveofourown.org,节点选择",
        "DOMAIN-SUFFIX,arte.tv,节点选择",
        "DOMAIN-SUFFIX,artstation.com,节点选择",
        "DOMAIN-SUFFIX,arukas.io,节点选择",
        "DOMAIN-SUFFIX,ask.com,节点选择",
        "DOMAIN-SUFFIX,avg.com,节点选择",
        "DOMAIN-SUFFIX,avgle.com,节点选择",
        "DOMAIN-SUFFIX,badoo.com,节点选择",
        "DOMAIN-SUFFIX,bandwagonhost.com,节点选择",
        "DOMAIN-SUFFIX,bangkokpost.com,节点选择",
        "DOMAIN-SUFFIX,bbc.com,节点选择",
        "DOMAIN-SUFFIX,behance.net,节点选择",
        "DOMAIN-SUFFIX,bibox.com,节点选择",
        "DOMAIN-SUFFIX,biggo.com.tw,节点选择",
        "DOMAIN-SUFFIX,binance.com,节点选择",
        "DOMAIN-SUFFIX,bit.ly,节点选择",
        "DOMAIN-SUFFIX,bitcointalk.org,节点选择",
        "DOMAIN-SUFFIX,bitfinex.com,节点选择",
        "DOMAIN-SUFFIX,bitmex.com,节点选择",
        "DOMAIN-SUFFIX,bit-z.com,节点选择",
        "DOMAIN-SUFFIX,bloglovin.com,节点选择",
        "DOMAIN-SUFFIX,bloomberg.cn,节点选择",
        "DOMAIN-SUFFIX,bloomberg.com,节点选择",
        "DOMAIN-SUFFIX,blubrry.com,节点选择",
        "DOMAIN-SUFFIX,book.com.tw,节点选择",
        "DOMAIN-SUFFIX,booklive.jp,节点选择",
        "DOMAIN-SUFFIX,books.com.tw,节点选择",
        "DOMAIN-SUFFIX,boslife.net,节点选择",
        "DOMAIN-SUFFIX,box.com,节点选择",
        "DOMAIN-SUFFIX,brave.com,节点选择",
        "DOMAIN-SUFFIX,businessinsider.com,节点选择",
        "DOMAIN-SUFFIX,buzzfeed.com,节点选择",
        "DOMAIN-SUFFIX,bwh1.net,节点选择",
        "DOMAIN-SUFFIX,castbox.fm,节点选择",
        "DOMAIN-SUFFIX,cbc.ca,节点选择",
        "DOMAIN-SUFFIX,cdw.com,节点选择",
        "DOMAIN-SUFFIX,change.org,节点选择",
        "DOMAIN-SUFFIX,channelnewsasia.com,节点选择",
        "DOMAIN-SUFFIX,ck101.com,节点选择",
        "DOMAIN-SUFFIX,clarionproject.org,节点选择",
        "DOMAIN-SUFFIX,cloudcone.com,节点选择",
        "DOMAIN-SUFFIX,clyp.it,节点选择",
        "DOMAIN-SUFFIX,cna.com.tw,节点选择",
        "DOMAIN-SUFFIX,comparitech.com,节点选择",
        "DOMAIN-SUFFIX,conoha.jp,节点选择",
        "DOMAIN-SUFFIX,crucial.com,节点选择",
        "DOMAIN-SUFFIX,cts.com.tw,节点选择",
        "DOMAIN-SUFFIX,cw.com.tw,节点选择",
        "DOMAIN-SUFFIX,cyberctm.com,节点选择",
        "DOMAIN-SUFFIX,dailymotion.com,节点选择",
        "DOMAIN-SUFFIX,dailyview.tw,节点选择",
        "DOMAIN-SUFFIX,daum.net,节点选择",
        "DOMAIN-SUFFIX,daumcdn.net,节点选择",
        "DOMAIN-SUFFIX,dcard.tw,节点选择",
        "DOMAIN-SUFFIX,deadline.com,节点选择",
        "DOMAIN-SUFFIX,deepdiscount.com,节点选择",
        "DOMAIN-SUFFIX,depositphotos.com,节点选择",
        "DOMAIN-SUFFIX,deviantart.com,节点选择",
        "DOMAIN-SUFFIX,disconnect.me,节点选择",
        "DOMAIN-SUFFIX,discordapp.com,节点选择",
        "DOMAIN-SUFFIX,discordapp.net,节点选择",
        "DOMAIN-SUFFIX,disqus.com,节点选择",
        "DOMAIN-SUFFIX,dlercloud.com,节点选择",
        "DOMAIN-SUFFIX,dmhy.org,节点选择",
        "DOMAIN-SUFFIX,dns2go.com,节点选择",
        "DOMAIN-SUFFIX,dowjones.com,节点选择",
        "DOMAIN-SUFFIX,dropbox.com,节点选择",
        "DOMAIN-SUFFIX,dropboxapi.com,节点选择",
        "DOMAIN-SUFFIX,dropboxusercontent.com,节点选择",
        "DOMAIN-SUFFIX,duckduckgo.com,节点选择",
        "DOMAIN-SUFFIX,duyaoss.com,节点选择",
        "DOMAIN-SUFFIX,dw.com,节点选择",
        "DOMAIN-SUFFIX,dynu.com,节点选择",
        "DOMAIN-SUFFIX,earthcam.com,节点选择",
        "DOMAIN-SUFFIX,ebookservice.tw,节点选择",
        "DOMAIN-SUFFIX,economist.com,节点选择",
        "DOMAIN-SUFFIX,edgecastcdn.net,节点选择",
        "DOMAIN-SUFFIX,edx-cdn.org,节点选择",
        "DOMAIN-SUFFIX,elpais.com,节点选择",
        "DOMAIN-SUFFIX,enanyang.my,节点选择",
        "DOMAIN-SUFFIX,encyclopedia.com,节点选择",
        "DOMAIN-SUFFIX,esoir.be,节点选择",
        "DOMAIN-SUFFIX,etherscan.io,节点选择",
        "DOMAIN-SUFFIX,euronews.com,节点选择",
        "DOMAIN-SUFFIX,evozi.com,节点选择",
        "DOMAIN-SUFFIX,exblog.jp,节点选择",
        "DOMAIN-SUFFIX,feeder.co,节点选择",
        "DOMAIN-SUFFIX,feedly.com,节点选择",
        "DOMAIN-SUFFIX,feedx.net,节点选择",
        "DOMAIN-SUFFIX,firech.at,节点选择",
        "DOMAIN-SUFFIX,flickr.com,节点选择",
        "DOMAIN-SUFFIX,flipboard.com,节点选择",
        "DOMAIN-SUFFIX,flitto.com,节点选择",
        "DOMAIN-SUFFIX,foreignpolicy.com,节点选择",
        "DOMAIN-SUFFIX,fortawesome.com,节点选择",
        "DOMAIN-SUFFIX,freetls.fastly.net,节点选择",
        "DOMAIN-SUFFIX,friday.tw,节点选择",
        "DOMAIN-SUFFIX,ft.com,节点选择",
        "DOMAIN-SUFFIX,ftchinese.com,节点选择",
        "DOMAIN-SUFFIX,ftimg.net,节点选择",
        "DOMAIN-SUFFIX,gate.io,节点选择",
        "DOMAIN-SUFFIX,genius.com,节点选择",
        "DOMAIN-SUFFIX,getlantern.org,节点选择",
        "DOMAIN-SUFFIX,getsync.com,节点选择",
        "DOMAIN-SUFFIX,github.com,节点选择",
        "DOMAIN-SUFFIX,github.io,节点选择",
        "DOMAIN-SUFFIX,githubusercontent.com,节点选择",
        "DOMAIN-SUFFIX,globalvoices.org,节点选择",
        "DOMAIN-SUFFIX,goo.ne.jp,节点选择",
        "DOMAIN-SUFFIX,goodreads.com,节点选择",
        "DOMAIN-SUFFIX,gov.tw,节点选择",
        "DOMAIN-SUFFIX,greatfire.org,节点选择",
        "DOMAIN-SUFFIX,gumroad.com,节点选择",
        "DOMAIN-SUFFIX,hbg.com,节点选择",
        "DOMAIN-SUFFIX,heroku.com,节点选择",
        "DOMAIN-SUFFIX,hightail.com,节点选择",
        "DOMAIN-SUFFIX,hk01.com,节点选择",
        "DOMAIN-SUFFIX,hkbf.org,节点选择",
        "DOMAIN-SUFFIX,hkbookcity.com,节点选择",
        "DOMAIN-SUFFIX,hkej.com,节点选择",
        "DOMAIN-SUFFIX,hket.com,节点选择",
        "DOMAIN-SUFFIX,hootsuite.com,节点选择",
        "DOMAIN-SUFFIX,hudson.org,节点选择",
        "DOMAIN-SUFFIX,huffpost.com,节点选择",
        "DOMAIN-SUFFIX,hyread.com.tw,节点选择",
        "DOMAIN-SUFFIX,ibtimes.com,节点选择",
        "DOMAIN-SUFFIX,i-cable.com,节点选择",
        "DOMAIN-SUFFIX,icij.org,节点选择",
        "DOMAIN-SUFFIX,icoco.com,节点选择",
        "DOMAIN-SUFFIX,imgur.com,节点选择",
        "DOMAIN-SUFFIX,independent.co.uk,节点选择",
        "DOMAIN-SUFFIX,initiummall.com,节点选择",
        "DOMAIN-SUFFIX,inoreader.com,节点选择",
        "DOMAIN-SUFFIX,insecam.org,节点选择",
        "DOMAIN-SUFFIX,ipfs.io,节点选择",
        "DOMAIN-SUFFIX,issuu.com,节点选择",
        "DOMAIN-SUFFIX,istockphoto.com,节点选择",
        "DOMAIN-SUFFIX,japantimes.co.jp,节点选择",
        "DOMAIN-SUFFIX,jiji.com,节点选择",
        "DOMAIN-SUFFIX,jinx.com,节点选择",
        "DOMAIN-SUFFIX,jkforum.net,节点选择",
        "DOMAIN-SUFFIX,joinmastodon.org,节点选择",
        "DOMAIN-SUFFIX,justmysocks.net,节点选择",
        "DOMAIN-SUFFIX,justpaste.it,节点选择",
        "DOMAIN-SUFFIX,kadokawa.co.jp,节点选择",
        "DOMAIN-SUFFIX,kakao.com,节点选择",
        "DOMAIN-SUFFIX,kakaocorp.com,节点选择",
        "DOMAIN-SUFFIX,kik.com,节点选择",
        "DOMAIN-SUFFIX,kingkong.com.tw,节点选择",
        "DOMAIN-SUFFIX,knowyourmeme.com,节点选择",
        "DOMAIN-SUFFIX,kobo.com,节点选择",
        "DOMAIN-SUFFIX,kobobooks.com,节点选择",
        "DOMAIN-SUFFIX,kodingen.com,节点选择",
        "DOMAIN-SUFFIX,lemonde.fr,节点选择",
        "DOMAIN-SUFFIX,lepoint.fr,节点选择",
        "DOMAIN-SUFFIX,lihkg.com,节点选择",
        "DOMAIN-SUFFIX,linkedin.com,节点选择",
        "DOMAIN-SUFFIX,limbopro.xyz,节点选择",
        "DOMAIN-SUFFIX,listennotes.com,节点选择",
        "DOMAIN-SUFFIX,livestream.com,节点选择",
        "DOMAIN-SUFFIX,logimg.jp,节点选择",
        "DOMAIN-SUFFIX,logmein.com,节点选择",
        "DOMAIN-SUFFIX,mail.ru,节点选择",
        "DOMAIN-SUFFIX,mailchimp.com,节点选择",
        "DOMAIN-SUFFIX,marc.info,节点选择",
        "DOMAIN-SUFFIX,matters.news,节点选择",
        "DOMAIN-SUFFIX,maying.co,节点选择",
        "DOMAIN-SUFFIX,medium.com,节点选择",
        "DOMAIN-SUFFIX,mega.nz,节点选择",
        "DOMAIN-SUFFIX,mergersandinquisitions.com,节点选择",
        "DOMAIN-SUFFIX,mingpao.com,节点选择",
        "DOMAIN-SUFFIX,mixi.jp,节点选择",
        "DOMAIN-SUFFIX,mobile01.com,节点选择",
        "DOMAIN-SUFFIX,mubi.com,节点选择",
        "DOMAIN-SUFFIX,myspace.com,节点选择",
        "DOMAIN-SUFFIX,myspacecdn.com,节点选择",
        "DOMAIN-SUFFIX,nanyang.com,节点选择",
        "DOMAIN-SUFFIX,nationalinterest.org,节点选择",
        "DOMAIN-SUFFIX,naver.com,节点选择",
        "DOMAIN-SUFFIX,nbcnews.com,节点选择",
        "DOMAIN-SUFFIX,ndr.de,节点选择",
        "DOMAIN-SUFFIX,neowin.net,节点选择",
        "DOMAIN-SUFFIX,newstapa.org,节点选择",
        "DOMAIN-SUFFIX,nexitally.com,节点选择",
        "DOMAIN-SUFFIX,nhk.or.jp,节点选择",
        "DOMAIN-SUFFIX,nii.ac.jp,节点选择",
        "DOMAIN-SUFFIX,nikkei.com,节点选择",
        "DOMAIN-SUFFIX,nitter.net,节点选择",
        "DOMAIN-SUFFIX,nofile.io,节点选择",
        "DOMAIN-SUFFIX,notion.so,节点选择",
        "DOMAIN-SUFFIX,now.com,节点选择",
        "DOMAIN-SUFFIX,nrk.no,节点选择",
        "DOMAIN-SUFFIX,nuget.org,节点选择",
        "DOMAIN-SUFFIX,nyaa.si,节点选择",
        "DOMAIN-SUFFIX,nyt.com,节点选择",
        "DOMAIN-SUFFIX,nytchina.com,节点选择",
        "DOMAIN-SUFFIX,nytcn.me,节点选择",
        "DOMAIN-SUFFIX,nytco.com,节点选择",
        "DOMAIN-SUFFIX,nytimes.com,节点选择",
        "DOMAIN-SUFFIX,nytimg.com,节点选择",
        "DOMAIN-SUFFIX,nytlog.com,节点选择",
        "DOMAIN-SUFFIX,nytstyle.com,节点选择",
        "DOMAIN-SUFFIX,ok.ru,节点选择",
        "DOMAIN-SUFFIX,okex.com,节点选择",
        "DOMAIN-SUFFIX,on.cc,节点选择",
        "DOMAIN-SUFFIX,orientaldaily.com.my,节点选择",
        "DOMAIN-SUFFIX,overcast.fm,节点选择",
        "DOMAIN-SUFFIX,paltalk.com,节点选择",
        "DOMAIN-SUFFIX,parsevideo.com,节点选择",
        "DOMAIN-SUFFIX,pawoo.net,节点选择",
        "DOMAIN-SUFFIX,pbxes.com,节点选择",
        "DOMAIN-SUFFIX,pcdvd.com.tw,节点选择",
        "DOMAIN-SUFFIX,pchome.com.tw,节点选择",
        "DOMAIN-SUFFIX,pcloud.com,节点选择",
        "DOMAIN-SUFFIX,peing.net,节点选择",
        "DOMAIN-SUFFIX,picacomic.com,节点选择",
        "DOMAIN-SUFFIX,pinimg.com,节点选择",
        "DOMAIN-SUFFIX,pixiv.net,节点选择",
        "DOMAIN-SUFFIX,player.fm,节点选择",
        "DOMAIN-SUFFIX,plurk.com,节点选择",
        "DOMAIN-SUFFIX,po18.tw,节点选择",
        "DOMAIN-SUFFIX,potato.im,节点选择",
        "DOMAIN-SUFFIX,potatso.com,节点选择",
        "DOMAIN-SUFFIX,prism-break.org,节点选择",
        "DOMAIN-SUFFIX,proxifier.com,节点选择",
        "DOMAIN-SUFFIX,pt.im,节点选择",
        "DOMAIN-SUFFIX,pts.org.tw,节点选择",
        "DOMAIN-SUFFIX,pubu.com.tw,节点选择",
        "DOMAIN-SUFFIX,pubu.tw,节点选择",
        "DOMAIN-SUFFIX,pureapk.com,节点选择",
        "DOMAIN-SUFFIX,quora.com,节点选择",
        "DOMAIN-SUFFIX,quoracdn.net,节点选择",
        "DOMAIN-SUFFIX,qz.com,节点选择",
        "DOMAIN-SUFFIX,radio.garden,节点选择",
        "DOMAIN-SUFFIX,rakuten.co.jp,节点选择",
        "DOMAIN-SUFFIX,rarbgprx.org,节点选择",
        "DOMAIN-SUFFIX,reabble.com,节点选择",
        "DOMAIN-SUFFIX,readingtimes.com.tw,节点选择",
        "DOMAIN-SUFFIX,readmoo.com,节点选择",
        "DOMAIN-SUFFIX,redbubble.com,节点选择",
        "DOMAIN-SUFFIX,redd.it,节点选择",
        "DOMAIN-SUFFIX,reddit.com,节点选择",
        "DOMAIN-SUFFIX,redditmedia.com,节点选择",
        "DOMAIN-SUFFIX,resilio.com,节点选择",
        "DOMAIN-SUFFIX,reuters.com,节点选择",
        "DOMAIN-SUFFIX,reutersmedia.net,节点选择",
        "DOMAIN-SUFFIX,rfi.fr,节点选择",
        "DOMAIN-SUFFIX,rixcloud.com,节点选择",
        "DOMAIN-SUFFIX,roadshow.hk,节点选择",
        "DOMAIN-SUFFIX,rsshub.app,节点选择",
        "DOMAIN-SUFFIX,scmp.com,节点选择",
        "DOMAIN-SUFFIX,scribd.com,节点选择",
        "DOMAIN-SUFFIX,seatguru.com,节点选择",
        "DOMAIN-SUFFIX,shadowsocks.org,节点选择",
        "DOMAIN-SUFFIX,shindanmaker.com,节点选择",
        "DOMAIN-SUFFIX,shopee.tw,节点选择",
        "DOMAIN-SUFFIX,sina.com.hk,节点选择",
        "DOMAIN-SUFFIX,slideshare.net,节点选择",
        "DOMAIN-SUFFIX,softfamous.com,节点选择",
        "DOMAIN-SUFFIX,spiegel.de,节点选择",
        "DOMAIN-SUFFIX,ssrcloud.org,节点选择",
        "DOMAIN-SUFFIX,startpage.com,节点选择",
        "DOMAIN-SUFFIX,steamcommunity.com,节点选择",
        "DOMAIN-SUFFIX,steemit.com,节点选择",
        "DOMAIN-SUFFIX,steemitwallet.com,节点选择",
        "DOMAIN-SUFFIX,straitstimes.com,节点选择",
        "DOMAIN-SUFFIX,streamable.com,节点选择",
        "DOMAIN-SUFFIX,streema.com,节点选择",
        "DOMAIN-SUFFIX,t66y.com,节点选择",
        "DOMAIN-SUFFIX,tapatalk.com,节点选择",
        "DOMAIN-SUFFIX,teco-hk.org,节点选择",
        "DOMAIN-SUFFIX,teco-mo.org,节点选择",
        "DOMAIN-SUFFIX,teddysun.com,节点选择",
        "DOMAIN-SUFFIX,textnow.me,节点选择",
        "DOMAIN-SUFFIX,theguardian.com,节点选择",
        "DOMAIN-SUFFIX,theinitium.com,节点选择",
        "DOMAIN-SUFFIX,themoviedb.org,节点选择",
        "DOMAIN-SUFFIX,thetvdb.com,节点选择",
        "DOMAIN-SUFFIX,time.com,节点选择",
        "DOMAIN-SUFFIX,tineye.com,节点选择",
        "DOMAIN-SUFFIX,tiny.cc,节点选择",
        "DOMAIN-SUFFIX,tinyurl.com,节点选择",
        "DOMAIN-SUFFIX,torproject.org,节点选择",
        "DOMAIN-SUFFIX,tumblr.com,节点选择",
        "DOMAIN-SUFFIX,turbobit.net,节点选择",
        "DOMAIN-SUFFIX,tutanota.com,节点选择",
        "DOMAIN-SUFFIX,tvboxnow.com,节点选择",
        "DOMAIN-SUFFIX,udn.com,节点选择",
        "DOMAIN-SUFFIX,unseen.is,节点选择",
        "DOMAIN-SUFFIX,upmedia.mg,节点选择",
        "DOMAIN-SUFFIX,uptodown.com,节点选择",
        "DOMAIN-SUFFIX,urbandictionary.com,节点选择",
        "DOMAIN-SUFFIX,ustream.tv,节点选择",
        "DOMAIN-SUFFIX,uwants.com,节点选择",
        "DOMAIN-SUFFIX,v2fly.org,节点选择",
        "DOMAIN-SUFFIX,v2ray.com,节点选择",
        "DOMAIN-SUFFIX,viber.com,节点选择",
        "DOMAIN-SUFFIX,videopress.com,节点选择",
        "DOMAIN-SUFFIX,vimeo.com,节点选择",
        "DOMAIN-SUFFIX,voachinese.com,节点选择",
        "DOMAIN-SUFFIX,voanews.com,节点选择",
        "DOMAIN-SUFFIX,voxer.com,节点选择",
        "DOMAIN-SUFFIX,vzw.com,节点选择",
        "DOMAIN-SUFFIX,w3schools.com,节点选择",
        "DOMAIN-SUFFIX,washingtonpost.com,节点选择",
        "DOMAIN-SUFFIX,wattpad.com,节点选择",
        "DOMAIN-SUFFIX,whoer.net,节点选择",
        "DOMAIN-SUFFIX,wikileaks.org,节点选择",
        "DOMAIN-SUFFIX,wikimapia.org,节点选择",
        "DOMAIN-SUFFIX,wikimedia.org,节点选择",
        "DOMAIN-SUFFIX,wikinews.org,节点选择",
        "DOMAIN-SUFFIX,wikipedia.org,节点选择",
        "DOMAIN-SUFFIX,wikiquote.org,节点选择",
        "DOMAIN-SUFFIX,wikiwand.com,节点选择",
        "DOMAIN-SUFFIX,winudf.com,节点选择",
        "DOMAIN-SUFFIX,wire.com,节点选择",
        "DOMAIN-SUFFIX,wn.com,节点选择",
        "DOMAIN-SUFFIX,wordpress.com,节点选择",
        "DOMAIN-SUFFIX,workflow.is,节点选择",
        "DOMAIN-SUFFIX,worldcat.org,节点选择",
        "DOMAIN-SUFFIX,wsj.com,节点选择",
        "DOMAIN-SUFFIX,wsj.net,节点选择",
        "DOMAIN-SUFFIX,xhamster.com,节点选择",
        "DOMAIN-SUFFIX,xn--90wwvt03e.com,节点选择",
        "DOMAIN-SUFFIX,xn--i2ru8q2qg.com,节点选择",
        "DOMAIN-SUFFIX,xnxx.com,节点选择",
        "DOMAIN-SUFFIX,xvideos.com,节点选择",
        "DOMAIN-SUFFIX,yahoo.com,节点选择",
        "DOMAIN-SUFFIX,yandex.ru,节点选择",
        "DOMAIN-SUFFIX,ycombinator.com,节点选择",
        "DOMAIN-SUFFIX,yesasia.com,节点选择",
        "DOMAIN-SUFFIX,yes-news.com,节点选择",
        "DOMAIN-SUFFIX,yomiuri.co.jp,节点选择",
        "DOMAIN-SUFFIX,you-get.org,节点选择",
        "DOMAIN-SUFFIX,zaobao.com,节点选择",
        "DOMAIN-SUFFIX,zb.com,节点选择",
        "DOMAIN-SUFFIX,zello.com,节点选择",
        "DOMAIN-SUFFIX,zeronet.io,节点选择",
        "DOMAIN-SUFFIX,zoom.us,节点选择",
        "DOMAIN,cc.tvbs.com.tw,节点选择",
        "DOMAIN,ocsp.int-x3.letsencrypt.org,节点选择",
        "DOMAIN,search.avira.com,节点选择",
        "DOMAIN,us.weibo.com,节点选择",
        "DOMAIN-KEYWORD,.pinterest.,节点选择",
        "DOMAIN-SUFFIX,edu,节点选择",
        "DOMAIN-SUFFIX,gov,节点选择",
        "DOMAIN-SUFFIX,mil,节点选择",
        "DOMAIN-SUFFIX,google,节点选择",
        "DOMAIN-SUFFIX,abc.xyz,节点选择",
        "DOMAIN-SUFFIX,advertisercommunity.com,节点选择",
        "DOMAIN-SUFFIX,ampproject.org,节点选择",
        "DOMAIN-SUFFIX,android.com,节点选择",
        "DOMAIN-SUFFIX,androidify.com,节点选择",
        "DOMAIN-SUFFIX,autodraw.com,节点选择",
        "DOMAIN-SUFFIX,capitalg.com,节点选择",
        "DOMAIN-SUFFIX,certificate-transparency.org,节点选择",
        "DOMAIN-SUFFIX,chrome.com,节点选择",
        "DOMAIN-SUFFIX,chromeexperiments.com,节点选择",
        "DOMAIN-SUFFIX,chromestatus.com,节点选择",
        "DOMAIN-SUFFIX,chromium.org,节点选择",
        "DOMAIN-SUFFIX,creativelab5.com,节点选择",
        "DOMAIN-SUFFIX,debug.com,节点选择",
        "DOMAIN-SUFFIX,deepmind.com,节点选择",
        "DOMAIN-SUFFIX,dialogflow.com,节点选择",
        "DOMAIN-SUFFIX,firebaseio.com,节点选择",
        "DOMAIN-SUFFIX,getmdl.io,节点选择",
        "DOMAIN-SUFFIX,ggpht.com,节点选择",
        "DOMAIN-SUFFIX,googleapis.cn,节点选择",
        "DOMAIN-SUFFIX,gmail.com,节点选择",
        "DOMAIN-SUFFIX,gmodules.com,节点选择",
        "DOMAIN-SUFFIX,godoc.org,节点选择",
        "DOMAIN-SUFFIX,golang.org,节点选择",
        "DOMAIN-SUFFIX,gstatic.com,节点选择",
        "DOMAIN-SUFFIX,gv.com,节点选择",
        "DOMAIN-SUFFIX,gwtproject.org,节点选择",
        "DOMAIN-SUFFIX,itasoftware.com,节点选择",
        "DOMAIN-SUFFIX,madewithcode.com,节点选择",
        "DOMAIN-SUFFIX,material.io,节点选择",
        "DOMAIN-SUFFIX,page.link,节点选择",
        "DOMAIN-SUFFIX,polymer-project.org,节点选择",
        "DOMAIN-SUFFIX,recaptcha.net,节点选择",
        "DOMAIN-SUFFIX,shattered.io,节点选择",
        "DOMAIN-SUFFIX,synergyse.com,节点选择",
        "DOMAIN-SUFFIX,telephony.goog,节点选择",
        "DOMAIN-SUFFIX,tensorflow.org,节点选择",
        "DOMAIN-SUFFIX,tfhub.dev,节点选择",
        "DOMAIN-SUFFIX,tiltbrush.com,节点选择",
        "DOMAIN-SUFFIX,waveprotocol.org,节点选择",
        "DOMAIN-SUFFIX,waymo.com,节点选择",
        "DOMAIN-SUFFIX,webmproject.org,节点选择",
        "DOMAIN-SUFFIX,webrtc.org,节点选择",
        "DOMAIN-SUFFIX,whatbrowser.org,节点选择",
        "DOMAIN-SUFFIX,widevine.com,节点选择",
        "DOMAIN-SUFFIX,x.company,节点选择",
        "DOMAIN-SUFFIX,youtu.be,节点选择",
        "DOMAIN-SUFFIX,yt.be,节点选择",
        "DOMAIN-SUFFIX,ytimg.com,节点选择",
        "DOMAIN-SUFFIX,t.me,节点选择",
        "DOMAIN-SUFFIX,tdesktop.com,节点选择",
        "DOMAIN-SUFFIX,telegram.me,节点选择",
        "DOMAIN-SUFFIX,telesco.pe,节点选择",
        "DOMAIN-KEYWORD,.facebook.,节点选择",
        "DOMAIN-SUFFIX,facebookmail.com,节点选择",
        "DOMAIN-SUFFIX,noxinfluencer.com,节点选择",
        "DOMAIN-SUFFIX,smartmailcloud.com,节点选择",
        "DOMAIN-SUFFIX,weebly.com,节点选择",
        "DOMAIN-SUFFIX,twitter.jp,节点选择",
        "DOMAIN-SUFFIX,appsto.re,节点选择",
        "DOMAIN,books.itunes.apple.com,节点选择",
        "DOMAIN,apps.apple.com,节点选择",
        "DOMAIN,itunes.apple.com,节点选择",
        "DOMAIN,api-glb-sea.smoot.apple.com,节点选择",
        "DOMAIN-SUFFIX,smoot.apple.com,节点选择",
        "DOMAIN,lookup-api.apple.com,节点选择",
        "DOMAIN,beta.music.apple.com,节点选择",
        "DOMAIN-SUFFIX,bing.com,节点选择",
        "DOMAIN-SUFFIX,cccat.io,节点选择",
        "DOMAIN-SUFFIX,dubox.com,节点选择",
        "DOMAIN-SUFFIX,duboxcdn.com,节点选择",
        "DOMAIN-SUFFIX,ifixit.com,节点选择",
        "DOMAIN-SUFFIX,mangakakalot.com,节点选择",
        "DOMAIN-SUFFIX,shopeemobile.com,节点选择",
        "DOMAIN-SUFFIX,cloudcone.com.cn,节点选择",
        "DOMAIN-SUFFIX,inkbunny.net,节点选择",
        "DOMAIN-SUFFIX,metapix.net,节点选择",
        "DOMAIN-SUFFIX,s3.amazonaws.com,节点选择",
        "DOMAIN-SUFFIX,zaobao.com.sg,节点选择",
        "DOMAIN,international-gfe.download.nvidia.com,节点选择",
        "DOMAIN,ocsp.apple.com,节点选择",
        "DOMAIN,store-images.s-microsoft.com,节点选择",
        "DOMAIN-SUFFIX,qhres.com,DIRECT",
        "DOMAIN-SUFFIX,qhimg.com,DIRECT",
        "DOMAIN-SUFFIX,alibaba.com,DIRECT",
        "DOMAIN-SUFFIX,alibabausercontent.com,DIRECT",
        "DOMAIN-SUFFIX,alicdn.com,DIRECT",
        "DOMAIN-SUFFIX,alikunlun.com,DIRECT",
        "DOMAIN-SUFFIX,alipay.com,DIRECT",
        "DOMAIN-SUFFIX,amap.com,DIRECT",
        "DOMAIN-SUFFIX,autonavi.com,DIRECT",
        "DOMAIN-SUFFIX,dingtalk.com,DIRECT",
        "DOMAIN-SUFFIX,mxhichina.com,DIRECT",
        "DOMAIN-SUFFIX,soku.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.hk,DIRECT",
        "DOMAIN-SUFFIX,ykimg.com,DIRECT",
        "DOMAIN-SUFFIX,youku.com,DIRECT",
        "DOMAIN-SUFFIX,xiami.com,DIRECT",
        "DOMAIN-SUFFIX,xiami.net,DIRECT",
        "DOMAIN-SUFFIX,aaplimg.com,DIRECT",
        "DOMAIN-SUFFIX,apple.co,DIRECT",
        "DOMAIN-SUFFIX,apple.com,DIRECT",
        "DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT",
        "DOMAIN-SUFFIX,appstore.com,DIRECT",
        "DOMAIN-SUFFIX,cdn-apple.com,DIRECT",
        "DOMAIN-SUFFIX,icloud.com,DIRECT",
        "DOMAIN-SUFFIX,icloud-content.com,DIRECT",
        "DOMAIN-SUFFIX,me.com,DIRECT",
        "DOMAIN-SUFFIX,mzstatic.com,DIRECT",
        "DOMAIN-KEYWORD,apple.com.akadns.net,DIRECT",
        "DOMAIN-KEYWORD,icloud.com.akadns.net,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,baidubcr.com,DIRECT",
        "DOMAIN-SUFFIX,baidupan.com,DIRECT",
        "DOMAIN-SUFFIX,baidupcs.com,DIRECT",
        "DOMAIN-SUFFIX,bdimg.com,DIRECT",
        "DOMAIN-SUFFIX,bdstatic.com,DIRECT",
        "DOMAIN-SUFFIX,yunjiasu-cdn.net,DIRECT",
        "DOMAIN-SUFFIX,acgvideo.com,DIRECT",
        "DOMAIN-SUFFIX,biliapi.com,DIRECT",
        "DOMAIN-SUFFIX,biliapi.net,DIRECT",
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,bilibili.tv,DIRECT",
        "DOMAIN-SUFFIX,hdslb.com,DIRECT",
        "DOMAIN-SUFFIX,feiliao.com,DIRECT",
        "DOMAIN-SUFFIX,pstatp.com,DIRECT",
        "DOMAIN-SUFFIX,snssdk.com,DIRECT",
        "DOMAIN-SUFFIX,iesdouyin.com,DIRECT",
        "DOMAIN-SUFFIX,toutiao.com,DIRECT",
        "DOMAIN-SUFFIX,cctv.com,DIRECT",
        "DOMAIN-SUFFIX,cctvpic.com,DIRECT",
        "DOMAIN-SUFFIX,livechina.com,DIRECT",
        "DOMAIN-SUFFIX,didialift.com,DIRECT",
        "DOMAIN-SUFFIX,didiglobal.com,DIRECT",
        "DOMAIN-SUFFIX,udache.com,DIRECT",
        "DOMAIN-SUFFIX,21cn.com,DIRECT",
        "DOMAIN-SUFFIX,hitv.com,DIRECT",
        "DOMAIN-SUFFIX,mgtv.com,DIRECT",
        "DOMAIN-SUFFIX,iqiyi.com,DIRECT",
        "DOMAIN-SUFFIX,iqiyipic.com,DIRECT",
        "DOMAIN-SUFFIX,71.am,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,jd.hk,DIRECT",
        "DOMAIN-SUFFIX,jdpay.com,DIRECT",
        "DOMAIN-SUFFIX,360buyimg.com,DIRECT",
        "DOMAIN-SUFFIX,iciba.com,DIRECT",
        "DOMAIN-SUFFIX,ksosoft.com,DIRECT",
        "DOMAIN-SUFFIX,meitu.com,DIRECT",
        "DOMAIN-SUFFIX,meitudata.com,DIRECT",
        "DOMAIN-SUFFIX,meitustat.com,DIRECT",
        "DOMAIN-SUFFIX,meipai.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        "DOMAIN-SUFFIX,dpfile.com,DIRECT",
        "DOMAIN-SUFFIX,meituan.com,DIRECT",
        "DOMAIN-SUFFIX,meituan.net,DIRECT",
        "DOMAIN-SUFFIX,duokan.com,DIRECT",
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,mi-img.com,DIRECT",
        "DOMAIN-SUFFIX,miui.com,DIRECT",
        "DOMAIN-SUFFIX,miwifi.com,DIRECT",
        "DOMAIN-SUFFIX,xiaomi.com,DIRECT",
        "DOMAIN-SUFFIX,xiaomi.net,DIRECT",
        "DOMAIN-SUFFIX,hotmail.com,DIRECT",
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,msecnd.net,DIRECT",
        "DOMAIN-SUFFIX,office365.com,DIRECT",
        "DOMAIN-SUFFIX,outlook.com,DIRECT",
        "DOMAIN-SUFFIX,s-microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,visualstudio.com,DIRECT",
        "DOMAIN-SUFFIX,windows.com,DIRECT",
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,126.net,DIRECT",
        "DOMAIN-SUFFIX,127.net,DIRECT",
        "DOMAIN-SUFFIX,163yun.com,DIRECT",
        "DOMAIN-SUFFIX,lofter.com,DIRECT",
        "DOMAIN-SUFFIX,netease.com,DIRECT",
        "DOMAIN-SUFFIX,ydstatic.com,DIRECT",
        "DOMAIN-SUFFIX,paypal.com,DIRECT",
        "DOMAIN-SUFFIX,paypal.me,DIRECT",
        "DOMAIN-SUFFIX,paypalobjects.com,DIRECT",
        "DOMAIN-SUFFIX,sina.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,weibocdn.com,DIRECT",
        "DOMAIN-SUFFIX,sohu.com,DIRECT",
        "DOMAIN-SUFFIX,sohucs.com,DIRECT",
        "DOMAIN-SUFFIX,sohu-inc.com,DIRECT",
        "DOMAIN-SUFFIX,v-56.com,DIRECT",
        "DOMAIN-SUFFIX,sogo.com,DIRECT",
        "DOMAIN-SUFFIX,sogou.com,DIRECT",
        "DOMAIN-SUFFIX,sogoucdn.com,DIRECT",
        "DOMAIN-SUFFIX,steamcontent.com,DIRECT",
        "DOMAIN-SUFFIX,steampowered.com,DIRECT",
        "DOMAIN-SUFFIX,steamstatic.com,DIRECT",
        "DOMAIN-SUFFIX,gtimg.com,DIRECT",
        "DOMAIN-SUFFIX,idqqimg.com,DIRECT",
        "DOMAIN-SUFFIX,igamecj.com,DIRECT",
        "DOMAIN-SUFFIX,myapp.com,DIRECT",
        "DOMAIN-SUFFIX,myqcloud.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,qqmail.com,DIRECT",
        "DOMAIN-SUFFIX,servicewechat.com,DIRECT",
        "DOMAIN-SUFFIX,tencent.com,DIRECT",
        "DOMAIN-SUFFIX,tencent-cloud.net,DIRECT",
        "DOMAIN-SUFFIX,tenpay.com,DIRECT",
        "DOMAIN-SUFFIX,wechat.com,DIRECT",
        "DOMAIN,file-igamecj.akamaized.net,DIRECT",
        "DOMAIN-SUFFIX,ccgslb.com,DIRECT",
        "DOMAIN-SUFFIX,ccgslb.net,DIRECT",
        "DOMAIN-SUFFIX,chinanetcenter.com,DIRECT",
        "DOMAIN-SUFFIX,meixincdn.com,DIRECT",
        "DOMAIN-SUFFIX,ourdvs.com,DIRECT",
        "DOMAIN-SUFFIX,staticdn.net,DIRECT",
        "DOMAIN-SUFFIX,wangsu.com,DIRECT",
        "DOMAIN-SUFFIX,ipip.net,DIRECT",
        "DOMAIN-SUFFIX,ip.la,DIRECT",
        "DOMAIN-SUFFIX,ip.sb,DIRECT",
        "DOMAIN-SUFFIX,ip-cdn.com,DIRECT",
        "DOMAIN-SUFFIX,ipv6-test.com,DIRECT",
        "DOMAIN-SUFFIX,myip.la,DIRECT",
        "DOMAIN-SUFFIX,test-ipv6.com,DIRECT",
        "DOMAIN-SUFFIX,whatismyip.com,DIRECT",
        "DOMAIN,ip.istatmenus.app,DIRECT",
        "DOMAIN,sms.imagetasks.com,DIRECT",
        "DOMAIN-SUFFIX,netspeedtestmaster.com,DIRECT",
        "DOMAIN,speedtest.macpaw.com,DIRECT",
        "DOMAIN-SUFFIX,acg.rip,DIRECT",
        "DOMAIN-SUFFIX,animebytes.tv,DIRECT",
        "DOMAIN-SUFFIX,awesome-hd.me,DIRECT",
        "DOMAIN-SUFFIX,broadcasthe.net,DIRECT",
        "DOMAIN-SUFFIX,chdbits.co,DIRECT",
        "DOMAIN-SUFFIX,classix-unlimited.co.uk,DIRECT",
        "DOMAIN-SUFFIX,comicat.org,DIRECT",
        "DOMAIN-SUFFIX,empornium.me,DIRECT",
        "DOMAIN-SUFFIX,gazellegames.net,DIRECT",
        "DOMAIN-SUFFIX,hdbits.org,DIRECT",
        "DOMAIN-SUFFIX,hdchina.org,DIRECT",
        "DOMAIN-SUFFIX,hddolby.com,DIRECT",
        "DOMAIN-SUFFIX,hdhome.org,DIRECT",
        "DOMAIN-SUFFIX,hdsky.me,DIRECT",
        "DOMAIN-SUFFIX,icetorrent.org,DIRECT",
        "DOMAIN-SUFFIX,jpopsuki.eu,DIRECT",
        "DOMAIN-SUFFIX,keepfrds.com,DIRECT",
        "DOMAIN-SUFFIX,madsrevolution.net,DIRECT",
        "DOMAIN-SUFFIX,morethan.tv,DIRECT",
        "DOMAIN-SUFFIX,m-team.cc,DIRECT",
        "DOMAIN-SUFFIX,myanonamouse.net,DIRECT",
        "DOMAIN-SUFFIX,nanyangpt.com,DIRECT",
        "DOMAIN-SUFFIX,ncore.cc,DIRECT",
        "DOMAIN-SUFFIX,open.cd,DIRECT",
        "DOMAIN-SUFFIX,ourbits.club,DIRECT",
        "DOMAIN-SUFFIX,passthepopcorn.me,DIRECT",
        "DOMAIN-SUFFIX,privatehd.to,DIRECT",
        "DOMAIN-SUFFIX,pterclub.com,DIRECT",
        "DOMAIN-SUFFIX,redacted.ch,DIRECT",
        "DOMAIN-SUFFIX,springsunday.net,DIRECT",
        "DOMAIN-SUFFIX,tjupt.org,DIRECT",
        "DOMAIN-SUFFIX,totheglory.im,DIRECT",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,115.com,DIRECT",
        "DOMAIN-SUFFIX,360in.com,DIRECT",
        "DOMAIN-SUFFIX,51ym.me,DIRECT",
        "DOMAIN-SUFFIX,8686c.com,DIRECT",
        "DOMAIN-SUFFIX,99.com,DIRECT",
        "DOMAIN-SUFFIX,abchina.com,DIRECT",
        "DOMAIN-SUFFIX,accuweather.com,DIRECT",
        "DOMAIN-SUFFIX,aicoinstorge.com,DIRECT",
        "DOMAIN-SUFFIX,air-matters.com,DIRECT",
        "DOMAIN-SUFFIX,air-matters.io,DIRECT",
        "DOMAIN-SUFFIX,aixifan.com,DIRECT",
        "DOMAIN-SUFFIX,amd.com,DIRECT",
        "DOMAIN-SUFFIX,b612.net,DIRECT",
        "DOMAIN-SUFFIX,bdatu.com,DIRECT",
        "DOMAIN-SUFFIX,beitaichufang.com,DIRECT",
        "DOMAIN-SUFFIX,booking.com,DIRECT",
        "DOMAIN-SUFFIX,bstatic.com,DIRECT",
        "DOMAIN-SUFFIX,cailianpress.com,DIRECT",
        "DOMAIN-SUFFIX,camera360.com,DIRECT",
        "DOMAIN-SUFFIX,chaoxing.com,DIRECT",
        "DOMAIN-SUFFIX,chaoxing.com,DIRECT",
        "DOMAIN-SUFFIX,chinaso.com,DIRECT",
        "DOMAIN-SUFFIX,chuimg.com,DIRECT",
        "DOMAIN-SUFFIX,chunyu.mobi,DIRECT",
        "DOMAIN-SUFFIX,cmbchina.com,DIRECT",
        "DOMAIN-SUFFIX,cmbimg.com,DIRECT",
        "DOMAIN-SUFFIX,ctrip.com,DIRECT",
        "DOMAIN-SUFFIX,dfcfw.com,DIRECT",
        "DOMAIN-SUFFIX,dji.net,DIRECT",
        "DOMAIN-SUFFIX,docschina.org,DIRECT",
        "DOMAIN-SUFFIX,douban.com,DIRECT",
        "DOMAIN-SUFFIX,doubanio.com,DIRECT",
        "DOMAIN-SUFFIX,douyu.com,DIRECT",
        "DOMAIN-SUFFIX,dxycdn.com,DIRECT",
        "DOMAIN-SUFFIX,dytt8.net,DIRECT",
        "DOMAIN-SUFFIX,eastmoney.com,DIRECT",
        "DOMAIN-SUFFIX,eudic.net,DIRECT",
        "DOMAIN-SUFFIX,feng.com,DIRECT",
        "DOMAIN-SUFFIX,fengkongcloud.com,DIRECT",
        "DOMAIN-SUFFIX,frdic.com,DIRECT",
        "DOMAIN-SUFFIX,futu5.com,DIRECT",
        "DOMAIN-SUFFIX,futunn.com,DIRECT",
        "DOMAIN-SUFFIX,gandi.net,DIRECT",
        "DOMAIN-SUFFIX,gcores.com,DIRECT",
        "DOMAIN-SUFFIX,geilicdn.com,DIRECT",
        "DOMAIN-SUFFIX,getpricetag.com,DIRECT",
        "DOMAIN-SUFFIX,gifshow.com,DIRECT",
        "DOMAIN-SUFFIX,godic.net,DIRECT",
        "DOMAIN-SUFFIX,hicloud.com,DIRECT",
        "DOMAIN-SUFFIX,hongxiu.com,DIRECT",
        "DOMAIN-SUFFIX,hostbuf.com,DIRECT",
        "DOMAIN-SUFFIX,huxiucdn.com,DIRECT",
        "DOMAIN-SUFFIX,huya.com,DIRECT",
        "DOMAIN-SUFFIX,ibm.com,DIRECT",
        "DOMAIN-SUFFIX,infinitynewtab.com,DIRECT",
        "DOMAIN-SUFFIX,ithome.com,DIRECT",
        "DOMAIN-SUFFIX,java.com,DIRECT",
        "DOMAIN-SUFFIX,jianguoyun.com,DIRECT",
        "DOMAIN-SUFFIX,jianshu.com,DIRECT",
        "DOMAIN-SUFFIX,jianshu.io,DIRECT",
        "DOMAIN-SUFFIX,jidian.im,DIRECT",
        "DOMAIN-SUFFIX,kaiyanapp.com,DIRECT",
        "DOMAIN-SUFFIX,kaspersky-labs.com,DIRECT",
        "DOMAIN-SUFFIX,keepcdn.com,DIRECT",
        "DOMAIN-SUFFIX,kkmh.com,DIRECT",
        "DOMAIN-SUFFIX,lanzous.com,DIRECT",
        "DOMAIN-SUFFIX,licdn.com,DIRECT",
        "DOMAIN-SUFFIX,luojilab.com,DIRECT",
        "DOMAIN-SUFFIX,maoyan.com,DIRECT",
        "DOMAIN-SUFFIX,maoyun.tv,DIRECT",
        "DOMAIN-SUFFIX,mls-cdn.com,DIRECT",
        "DOMAIN-SUFFIX,mobike.com,DIRECT",
        "DOMAIN-SUFFIX,moke.com,DIRECT",
        "DOMAIN-SUFFIX,mubu.com,DIRECT",
        "DOMAIN-SUFFIX,myzaker.com,DIRECT",
        "DOMAIN-SUFFIX,nim-lang-cn.org,DIRECT",
        "DOMAIN-SUFFIX,nvidia.com,DIRECT",
        "DOMAIN-SUFFIX,oracle.com,DIRECT",
        "DOMAIN-SUFFIX,originlab.com,DIRECT",
        "DOMAIN-SUFFIX,qdaily.com,DIRECT",
        "DOMAIN-SUFFIX,qidian.com,DIRECT",
        "DOMAIN-SUFFIX,qyer.com,DIRECT",
        "DOMAIN-SUFFIX,qyerstatic.com,DIRECT",
        "DOMAIN-SUFFIX,raychase.net,DIRECT",
        "DOMAIN-SUFFIX,ronghub.com,DIRECT",
        "DOMAIN-SUFFIX,ruguoapp.com,DIRECT",
        "DOMAIN-SUFFIX,sankuai.com,DIRECT",
        "DOMAIN-SUFFIX,scomper.me,DIRECT",
        "DOMAIN-SUFFIX,seafile.com,DIRECT",
        "DOMAIN-SUFFIX,sm.ms,DIRECT",
        "DOMAIN-SUFFIX,smzdm.com,DIRECT",
        "DOMAIN-SUFFIX,snapdrop.net,DIRECT",
        "DOMAIN-SUFFIX,snwx.com,DIRECT",
        "DOMAIN-SUFFIX,s-reader.com,DIRECT",
        "DOMAIN-SUFFIX,sspai.com,DIRECT",
        "DOMAIN-SUFFIX,subhd.tv,DIRECT",
        "DOMAIN-SUFFIX,takungpao.com,DIRECT",
        "DOMAIN-SUFFIX,teamviewer.com,DIRECT",
        "DOMAIN-SUFFIX,tianyancha.com,DIRECT",
        "DOMAIN-SUFFIX,tophub.today,DIRECT",
        "DOMAIN-SUFFIX,udacity.com,DIRECT",
        "DOMAIN-SUFFIX,uning.com,DIRECT",
        "DOMAIN-SUFFIX,weather.com,DIRECT",
        "DOMAIN-SUFFIX,weico.cc,DIRECT",
        "DOMAIN-SUFFIX,weidian.com,DIRECT",
        "DOMAIN-SUFFIX,xiachufang.com,DIRECT",
        "DOMAIN-SUFFIX,xiaoka.tv,DIRECT",
        "DOMAIN-SUFFIX,ximalaya.com,DIRECT",
        "DOMAIN-SUFFIX,xinhuanet.com,DIRECT",
        "DOMAIN-SUFFIX,xmcdn.com,DIRECT",
        "DOMAIN-SUFFIX,yangkeduo.com,DIRECT",
        "DOMAIN-SUFFIX,yizhibo.com,DIRECT",
        "DOMAIN-SUFFIX,zhangzishi.cc,DIRECT",
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "DOMAIN-SUFFIX,zhihuishu.com,DIRECT",
        "DOMAIN-SUFFIX,zhimg.com,DIRECT",
        "DOMAIN-SUFFIX,zhuihd.com,DIRECT",
        "DOMAIN,download.jetbrains.com,DIRECT",
        "DOMAIN,images-cn.ssl-images-amazon.com,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
        "IP-CIDR6,fd00::/8,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "MATCH,节点选择",
    ],
}


# 解析 Hysteria2 链接
def parse_hysteria2_link(link):
    link = link[14:]
    parts = link.split("@")
    uuid = parts[0]
    server_info = parts[1].split("?")
    server = server_info[0].split(":")[0]
    port = int(server_info[0].split(":")[1].split("/")[0].strip())
    query_params = urllib.parse.parse_qs(server_info[1] if len(server_info) > 1 else "")
    insecure = "1" in query_params.get("insecure", ["0"])
    sni = query_params.get("sni", [""])[0]
    name = urllib.parse.unquote(link.split("#")[-1].strip())

    return {
        "name": f"{name}",
        "server": server,
        "port": port,
        "type": "hysteria2",
        "password": uuid,
        "auth": uuid,
        "sni": sni,
        "skip-cert-verify": not insecure,
        "client-fingerprint": "chrome",
    }


# 解析 Shadowsocks 链接
def parse_ss_link(link: str):
    uri = link[5:]
    if "#" in uri:
        config_part, name = uri.split("#")
    else:
        config_part, name = uri, ""
    decoded = base64.urlsafe_b64decode(
        config_part.split("@")[0] + "=" * (-len(config_part.split("@")[0]) % 4)
    ).decode("utf-8")
    method_passwd = (
        decoded.split(":") if "@" in config_part else decoded.split("@")[0].split(":")
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
    server, port = server_info.split(":") if ":" in server_info else (server_info, "")
    if port.endswith("/"):
        port = port[:-1]

    return {
        "name": urllib.parse.unquote(name),
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": cipher,
        "password": password,
        "udp": False,
    }


# 解析 Trojan 链接
def parse_trojan_link(link):
    link = link[9:]
    config_part, name = link.split("#")
    user_info, host_info = config_part.split("@")
    username, password = user_info.split(":") if ":" in user_info else ("", user_info)
    host, port_and_query = host_info.split(":") if ":" in host_info else (host_info, "")
    port, query = (
        port_and_query.split("?", 1) if "?" in port_and_query else (port_and_query, "")
    )

    return {
        "name": urllib.parse.unquote(name),
        "type": "trojan",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get(
            "skip-cert-verify", ["false"]
        )[0]
        == "true",
    }


# 解析 VLESS 链接
def parse_vless_link(link):
    link = link[8:]
    links = link.split("#")
    config_part, name = links if len(links) == 2 else ("".join(links[:-1]), links[-1])
    parts = config_part.split("@")
    user_info, host_info = parts if len(parts) == 2 else (parts[0], "".join(parts[1:]))
    uuid = user_info
    host, query = host_info.split("?", 1) if "?" in host_info else (host_info, "")
    port = host.split(":")[-1] if ":" in host else ""
    host = host.split(":")[0] if ":" in host else ""

    return {
        "name": urllib.parse.unquote(name),
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "security": urllib.parse.parse_qs(query).get("security", ["none"])[0],
        "tls": urllib.parse.parse_qs(query).get("security", ["none"])[0] == "tls",
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get(
            "skip-cert-verify", ["false"]
        )[0]
        == "true",
        "network": urllib.parse.parse_qs(query).get("type", ["tcp"])[0],
        "ws-opts": {
            "path": urllib.parse.parse_qs(query).get("path", [""])[0],
            "headers": {"Host": urllib.parse.parse_qs(query).get("host", [""])[0]},
        }
        if urllib.parse.parse_qs(query).get("type", ["tcp"])[0] == "ws"
        else {},
    }


# 解析 VMESS 链接
def parse_vmess_link(link):
    link = link[8:]
    decoded_link = base64.urlsafe_b64decode(link + "=" * (-len(link) % 4)).decode(
        "utf-8"
    )
    vmess_info = json.loads(decoded_link)

    return {
        "name": urllib.parse.unquote(vmess_info.get("ps", "vmess")),
        "type": "vmess",
        "server": vmess_info["add"],
        "port": int(vmess_info["port"]),
        "uuid": vmess_info["id"],
        "alterId": int(vmess_info.get("aid", 0)),
        "cipher": "auto",
        "network": vmess_info.get("net", "tcp"),
        "tls": vmess_info.get("tls", "") == "tls",
        "sni": vmess_info.get("sni", ""),
        "ws-opts": {
            "path": vmess_info.get("path", ""),
            "headers": {"Host": vmess_info.get("host", "")},
        }
        if vmess_info.get("net", "tcp") == "ws"
        else {},
    }


def parse_md_link(link):
    """parse nodes from md url link"""
    try:
        # 发送请求并获取内容
        response = requests.get(link)
        response.raise_for_status()  # 检查请求是否成功
        content = response.text
        content = urllib.parse.unquote(content)
        # 定义正则表达式模式，匹配所需的协议链接
        pattern = r"(?:vless|vmess|trojan|hysteria2|ss):\/\/[^#\s]*(?:#[^\s]*)?"

        # 使用re.findall()提取所有匹配的链接
        matches = re.findall(pattern, content)
        return matches

    except requests.RequestException as e:
        logger.info(f"请求错误: {e}")
        return []


# js渲染页面
def js_render(url):
    timeout = 4
    if timeout > 15:
        timeout = 15
    browser_args = [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-setuid-sandbox",
    ]
    session = HTMLSession(browser_args=browser_args)
    r = session.get(
        url=f"{url}",
        headers=extra_headers(
            {
                "Accept-Charset": "utf-8",
                "Accept": "text/html,application/x-yaml,*/*",
            }
        ),
        timeout=timeout,
        verify=False,
    )
    # 等待页面加载完成，Requests-HTML 会自动等待 JavaScript 执行完成
    r.html.render(timeout=timeout)
    return r


# je_render返回的text没有缩进，通过正则表达式匹配proxies下的所有代理节点
def match_nodes(text):
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)

    # 将每个节点字符串转换为字典
    proxies_list = []
    for node in nodes:
        # 使用yaml.safe_load来加载每个节点
        node_dict = yaml.safe_load(node)
        proxies_list.append(node_dict)

    yaml_data = {"proxies": proxies_list}
    return yaml_data


# 解析不同的代理链接
def parse_proxy_link(link):
    if link.startswith("hysteria2://") or link.startswith("hy2://"):
        return parse_hysteria2_link(link)
    elif link.startswith("trojan://"):
        return parse_trojan_link(link)
    elif link.startswith("ss://"):
        return parse_ss_link(link)
    elif link.startswith("vless://"):
        return parse_vless_link(link)
    elif link.startswith("vmess://"):
        return parse_vmess_link(link)
    return None


def handle_links(new_links, resolve_name_conflicts):
    try:
        for new_link in new_links:
            if new_link.startswith(
                ("hysteria2://", "hy2://", "trojan://", "ss://", "vless://", "vmess://")
            ):
                node = parse_proxy_link(new_link)
                if node:
                    resolve_name_conflicts(node)
            else:
                logger.info(f"跳过无效或不支持的链接: {new_link}")
    except Exception:
        pass


def generate_clash_config(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now()
    logger.info(f"当前时间: {now}")
    config = deepcopy(clash_config_template)

    for node in nodes:
        name = str(node["name"])
        # 0节点选择 1 自动选择 2故障转移 3手动选择
        config["proxy-groups"][1]["proxies"].append(name)
        config["proxy-groups"][2]["proxies"].append(name)
        config["proxy-groups"][3]["proxies"].append(name)
    config["proxies"] = nodes
    return config


# 自定义 Clash API 异常
class ClashAPIException(Exception):
    """自定义 Clash API 异常"""

    pass


class ProxyDelayResult:
    """代理测试结果类"""

    def __init__(self, name: str, delay: Optional[float] = None):
        self.name = name
        self.delay = delay if delay is not None else float("inf")
        self.status = "ok" if delay is not None else "fail"
        self.tested_time = datetime.now()

    @property
    def is_valid(self) -> bool:
        return self.status == "ok"


class ClashConfigHelper:
    """Clash 配置管理类"""

    def __init__(self, config: dict[str, Any]):
        self.port = config["external-controller"].rsplit(":", 1)[-1]
        self.config = config
        self.host = settings.clash_host
        self.problem_proxies: list[dict[str, Any]] = []

    def get_api_url(self) -> str:
        """获取 Clash API 地址"""
        return f"http://{self.host}:{self.port}"

    def _get_proxy_groups(self) -> list[dict]:
        """获取所有代理组信息"""
        return self.config.get("proxy-groups", [])

    def get_group_names(self) -> list[str]:
        """获取所有代理组名称"""
        return [group["name"] for group in self._get_proxy_groups()]

    def get_group_proxies(self, group_name: str) -> list[str]:
        """获取指定组的所有代理"""
        for group in self._get_proxy_groups():
            if group["name"] == group_name:
                return group.get("proxies", [])
        return []

    def remove_invalid_proxies(self, invalid_proxies: list[str]):
        """从配置中完全移除失效的节点"""
        # 获取所有失效节点名称

        if not invalid_proxies:
            return

        # 从 proxies 部分移除失效节点
        valid_proxies = []
        if "proxies" in self.config:
            valid_proxies = [
                p
                for p in self.config["proxies"]
                if p.get("name") not in invalid_proxies
            ]
            self.config["proxies"] = valid_proxies

        # 从所有代理组中移除失效节点
        for group in self.config.get("proxy-groups", []):
            if "proxies" in group:
                group["proxies"] = [
                    p for p in group["proxies"] if p not in invalid_proxies
                ]
        logger.info(f"已从配置中移除 {len(invalid_proxies)} 个失效节点")

    def keep_proxies_by_limit(self, proxy_names):
        if "proxies" in self.config:
            self.config["proxies"] = [
                p for p in self.config["proxies"] if p["name"] in proxy_names
            ]

    def update_group_proxies(self, group_name: str, proxies: list[ProxyDelayItem]):
        """更新指定组的代理列表，仅保留有效节点并按延迟排序"""
        # 移除失效节点
        self.remove_invalid_proxies([p.name for p in proxies if not p.alive])

        # 获取有效节点并按延迟排序
        valid_results = [r for r in proxies if r.alive]
        valid_results = list(set(valid_results))
        valid_results.sort(key=lambda p: average_delay(p.history))

        # 更新代理组
        for group in self.config.get("proxy-groups", []):
            if group["name"] == group_name:
                group["proxies"] = [r.name for r in valid_results]
                break

    def save(self, config_file: str):
        """保存配置到文件"""
        try:
            with open(config_file, "w", encoding="utf-8") as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)
            logger.info(f"新配置已保存到: {config_file}")
        except Exception as e:
            logger.info(f"保存配置文件失败: {e}")
            sys.exit(1)

    def handle_clash_error(self, error_message):
        """处理 Clash 配置错误，解析错误信息并更新 config"""
        start_time = time.time()

        proxy_index_match = re.search(r"proxy (\d+):", error_message)
        if not proxy_index_match:
            return False

        problem_index = int(proxy_index_match.group(1))

        try:
            # 读取配置
            config = self.config
            # 获取要删除的节点的name
            problem_proxy = config["proxies"][problem_index]
            # 删除问题节点
            del config["proxies"][problem_index]

            # 从所有proxy-groups中删除该节点引用
            proxies: list = config["proxy-groups"][1]["proxies"]
            proxies.remove(problem_proxy["name"])
            for group in config["proxy-groups"][1:]:
                group["proxies"] = proxies

            logger.info(
                f"配置异常：{error_message}，修复配置异常，移除 proxy，"
                f"下标：{problem_index}，节点：{problem_proxy}，"
                f"完毕，耗时：{time.time() - start_time}s"
            )
            problem_proxy["_extra"] = {"error": error_message}
            self.problem_proxies.append(problem_proxy)
            return True
        except Exception as e:
            logger.info(f"处理配置文件时出错: {str(e)}")
            return False


def ensure_executable(file_path):
    """确保文件具有可执行权限（仅适用于 Linux 和 macOS）"""
    if platform.system().lower() in ["linux", "darwin"]:
        os.chmod(file_path, 0o755)  # 设置文件为可执行


def prepare_clash():
    os_type = platform.system().lower()
    targets = {
        "darwin": "mihomo-darwin-amd64",
        "linux": "mihomo-linux-amd64",
        "windows": "mihomo-windows-amd64",
    }

    # 确定下载链接和新名称
    new_name = f"mihomo-{os_type}"

    # 检查是否已存在二进制文件
    if os.path.exists(new_name):
        return

    url = f"https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/{settings.mihomo_version}"
    response = requests.get(url)

    if response.status_code != 200:
        raise RuntimeError("Failed to retrieve mohomo release information.")

    data = response.json()
    assets = data.get("assets", [])

    download_url = None
    for asset in assets:
        name = asset.get("name", "")
        if os_type == "darwin" and targets["darwin"] in name and name.endswith(".gz"):
            download_url = asset["browser_download_url"]
            break
        elif os_type == "linux" and targets["linux"] in name and name.endswith(".gz"):
            download_url = asset["browser_download_url"]
            break
        elif (
            os_type == "windows"
            and targets["windows"] in name
            and name.endswith(".zip")
        ):
            download_url = asset["browser_download_url"]
            break

    if download_url:
        download_url = f"{download_url}"
        logger.info(f"Downloading file from {download_url}")
        filename = Path(download_url.split("/")[-1])
        response = requests.get(download_url)

        # 保存下载的文件
        with open(filename, "wb") as f:
            f.write(response.content)

        # 解压文件并重命名
        import pybit7z

        with pybit7z.lib7zip_context() as lib:
            reader = pybit7z.BitArchiveReader(lib, str(filename))
            reader.extract_to(str(Path.cwd()))
            extract_filename = reader.item_at(0).name()

            if Path(extract_filename).exists():
                os.rename(extract_filename, new_name)
                if os_type in ["linux", "darwin"]:
                    ensure_executable(new_name)

        os.remove(filename)  # 删除下载的压缩文件
    else:
        raise RuntimeError(
            "No suitable release found for the current operating system."
        )


class ClashProcess:
    def __init__(self, config_helper: ClashConfigHelper):
        self.config_helper = config_helper

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.gracefully_end_clash()

    def read_output(self, pipe, output_lines):
        while True:
            try:
                line = pipe.readline()
                if line:
                    output_lines.append(line)
                else:
                    break
            except IOError:
                break

    def gracefully_end_clash(self):
        if self.clash_process:
            self.clash_process.terminate()
            self.clash_process.wait(10)
            if self.clash_process.poll() is None:
                self.clash_process.kill()

    def start(self):
        logger.info("===================启动clash并初始化配置===================")
        clash_bin = f"./mihomo-{platform.system().lower()}"
        not_started = True
        while not_started:
            with tempfile.TemporaryDirectory() as temp_dir:
                config_file = os.path.join(temp_dir, "clash.yaml")
                self.config_helper.save(config_file)
                self.clash_process = subprocess.Popen(
                    (
                        clash_bin,
                        "-f",
                        config_file,
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                )

                output_lines = []

                # 启动线程来读取标准输出和标准错误
                output_thread = threading.Thread(
                    target=self.read_output,
                    args=(self.clash_process.stdout, output_lines),
                )

                output_thread.start()

                timeout = 3
                start_time = time.time()
                while time.time() - start_time < timeout:
                    output_thread.join(timeout=0.5)
                    if output_lines:
                        # 检查输出是否包含错误信息
                        if "GeoIP.dat" in output_lines[-1]:
                            logger.info(output_lines[-1])
                            time.sleep(5)
                            if self.is_clash_api_running():
                                return

                        if "Parse config error" in output_lines[-1]:
                            if self.config_helper.handle_clash_error(output_lines[-1]):
                                self.gracefully_end_clash()
                                output_lines = []

                    if self.is_clash_api_running():
                        return

                if not_started:
                    self.gracefully_end_clash()
                    continue
                output_thread.join()
                return

    def is_clash_api_running(self) -> bool:
        try:
            response = requests.get(f"{self.config_helper.get_api_url()}/configs")
            logger.info("Clash API启动成功，开始批量检测")
            return response.status_code == 200
        except requests.exceptions.RequestException:
            # 捕获所有请求异常，包括连接错误等
            return False

    def switch_proxy(self, proxy_name="DIRECT"):
        """
        切换 Clash 中策略组的代理节点。

        Args:
            proxy_name: 要切换到的代理节点名称
        """

        try:
            response = requests.put(
                f"{self.config_helper.get_api_url()}/proxies/节点选择",
                json={"name": proxy_name},
            )
            if response.status_code == 204:  # Clash API 切换成功返回 204 No Content
                logger.info(f"切换到 '节点选择-{proxy_name}' successfully.")
                return {
                    "status": "success",
                    "message": f"Switched to proxy '{proxy_name}'.",
                }
            else:
                return response.json()
        except Exception as e:
            logger.info(f"Error occurred: {e}")
            return {"status": "error", "message": str(e)}


class ClashAPI:
    def __init__(self, host: str, ports: list[int], secret: str = ""):
        self.host = host
        self.ports = ports
        self.base_url = None  # 将在连接检查时设置
        self.headers = {
            "Authorization": f"Bearer {secret}" if secret else "",
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(timeout=1)
        self.test_results: dict[str, ProxyDelayResult] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def check_connection(self) -> bool:
        """检查与 Clash API 的连接状态，自动尝试不同端口"""
        for port in self.ports:
            try:
                test_url = f"http://{self.host}:{port}"
                response = await self.client.get(f"{test_url}/version")
                if response.status_code == 200:
                    version = response.json().get("version", "unknown")
                    logger.info(f"成功连接到 Clash API (端口 {port})，版本: {version}")
                    self.base_url = test_url
                    return True
            except httpx.RequestError:
                logger.info(f"端口 {port} 连接失败，尝试下一个端口...")
                continue

        logger.info("所有端口均连接失败")
        logger.info(
            f"请确保 Clash 正在运行，并且 External Controller 已启用于以下端口之一: {', '.join(map(str, self.ports))}"
        )
        return False

    async def get_proxies(self) -> dict:
        """获取所有代理节点信息"""
        if not self.base_url:
            raise ClashAPIException("未建立与 Clash API 的连接")

        try:
            response = await self.client.get(
                f"{self.base_url}/proxies",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.info("认证失败，请检查 API Secret 是否正确")
            raise ClashAPIException(f"HTTP 错误: {e}")
        except httpx.RequestError as e:
            raise ClashAPIException(f"请求错误: {e}")

    async def test_group_delay(self, group_name: str) -> None:
        """测试指定代理组下面节点的延迟，使用缓存避免重复测试"""
        if not self.base_url:
            raise ClashAPIException("未建立与 Clash API 的连接")

        try:
            delay_timeout = settings.delay_timeout_unit * 1000 * 2
            response = await self.client.get(
                f"{self.base_url}/group/{group_name}/delay",
                headers=self.headers,
                params={
                    "url": settings.delay_url_test,
                    "timeout": str(delay_timeout),
                },
                timeout=settings.delay_timeout_unit * 4,
            )
            response.raise_for_status()
        except httpx.TimeoutException as e:
            logger.error(
                f"测试策略组 {group_name} 超时: {e}. URL: {settings.delay_url_test}, 超时设置: {delay_timeout * 2} ms"
            )
        except Exception as e:
            logger.exception(f"测试策略组 {group_name} 失败: {e}")


# 获取当前时间的各个组成部分
def parse_datetime_variables():
    now = datetime.now()
    return {
        "Y": str(now.year),
        "m": str(now.month).zfill(2),
        "d": str(now.day).zfill(2),
        "H": str(now.hour).zfill(2),
        "M": str(now.minute).zfill(2),
        "S": str(now.second).zfill(2),
    }


# 移除URL中的代理前缀
def strip_proxy_prefix(url):
    proxy_pattern = r"^https?://[^/]+/https://"
    match = re.match(proxy_pattern, url)
    if match:
        real_url = re.sub(proxy_pattern, "https://", url)
        proxy_prefix = url[: match.end() - 8]
        return real_url, proxy_prefix
    return url, None


# 判断是否为GitHub raw URL
def is_github_raw_url(url):
    return "raw.githubusercontent.com" in url


# 从URL中提取文件模式，返回占位符前后的部分
def extract_file_pattern(url):
    # 查找形如 {x}<suffix> 的模式
    match = re.search(r"\{x\}(\.[a-zA-Z0-9]+)(?:/|$)", url)
    if match:
        return match.group(1)  # 返回文件后缀，如 '.yaml', '.txt', '.json'
    return None


# 从GitHub API获取匹配指定后缀的文件名
def get_github_filename(github_url, file_suffix):
    match = re.match(
        r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/[^/]+/([^/]+)",
        github_url,
    )
    if not match:
        raise ValueError("无法从URL中提取owner和repo信息")
    owner, repo, branch = match.groups()

    # 构建API URL
    path_part = github_url.split(f"/refs/heads/{branch}/")[-1]
    # 移除 {x}<suffix> 部分来获取目录路径
    path_part = re.sub(r"\{x\}" + re.escape(file_suffix) + "(?:/|$)", "", path_part)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path_part}"

    response = requests.get(api_url)
    if response.status_code != 200:
        raise Exception(f"GitHub API请求失败: {response.status_code}")

    files = response.json()
    matching_files = [f["name"] for f in files if f["name"].endswith(file_suffix)]

    if not matching_files:
        raise Exception(f"未找到匹配的{file_suffix}文件")

    return matching_files[0]


# 解析URL模板，支持任意组合的日期时间变量和分隔符
def parse_template(template_url, datetime_vars):
    def replace_template(match):
        """替换单个模板块的内容"""
        template_content = match.group(1)
        if template_content == "x":
            return "{x}"  # 保持 {x} 不变，供后续处理

        result = ""
        # 用于临时存储当前字符
        current_char = ""

        # 遍历模板内容中的每个字符
        for char in template_content:
            if char in datetime_vars:
                # 如果是日期时间变量，替换为对应值
                if current_char:
                    # 添加之前累积的非变量字符
                    result += current_char
                    current_char = ""
                result += datetime_vars[char]
            else:
                # 如果是其他字符（分隔符），直接保留
                current_char += char

        # 添加最后可能剩余的非变量字符
        if current_char:
            result += current_char

        return result

    # 使用正则表达式查找并替换所有模板块
    return re.sub(r"\{([^}]+)\}", replace_template, template_url)


# 完整解析模板URL
def resolve_template_url(template_url):
    # 先处理代理前缀
    url, proxy_prefix = strip_proxy_prefix(template_url)

    # 获取日期时间变量
    datetime_vars = parse_datetime_variables()

    # 替换日期时间变量
    resolved_url = parse_template(url, datetime_vars)

    # 如果是GitHub URL且包含{x}，则处理文件名
    if is_github_raw_url(resolved_url) and "{x}" in resolved_url:
        # 提取文件后缀
        file_suffix = extract_file_pattern(resolved_url)
        if file_suffix:
            filename = get_github_filename(resolved_url, file_suffix)
            # 替换 {x}<suffix> 为实际文件名
            resolved_url = re.sub(
                r"\{x\}" + re.escape(file_suffix), filename, resolved_url
            )

    # 如果有代理前缀，重新添加上
    if proxy_prefix:
        resolved_url = f"{proxy_prefix}{resolved_url}"

    return resolved_url


class ClashDelayChecker:
    _prepared = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.port_pool = PortPool()
        self.proxy_delay_dict: dict[str, ProxyDelayItem] = {}
        self.problem_proxies: list[dict[str, Any]] = []
        self.nodes: list[dict[str, Any]] = []

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        if not cls._prepared:
            prepare_clash()
            cls._prepared = True
        return instance

    def check_nodes(self, nodes: list[dict[str, Any]]):
        self.nodes.extend(nodes)
        for i in range(0, len(nodes), settings.delay_batch_test_size):
            batch_nodes = nodes[i : i + settings.delay_batch_test_size]
            batch_msg = f"{len(batch_nodes)}/{len(batch_nodes)+i}/{len(nodes)}"
            logger.info(f"batched nodes: {batch_msg}")
            self._check_nodes(batch_nodes)
            logger.info(f"batched finished: {batch_msg}")

    def _check_nodes(self, nodes: list[dict[str, Any]]):
        ports = [self.port_pool.get_port() for _ in range(4)]
        try:
            clash_config = generate_clash_config(nodes)
            (
                clash_config["external-controller"],
                clash_config["port"],
                clash_config["socks-port"],
                clash_config["redir-port"],
            ) = f"{settings.clash_host}:{ports[0]}", ports[1], ports[2], ports[3]

            config_helper = ClashConfigHelper(clash_config)
            with ClashProcess(config_helper):
                asyncio.run(self.nodes_clean(config_helper))

            with self._lock:
                self.problem_proxies.extend(config_helper.problem_proxies)
        except Exception as e:
            logger.warning(f"Failed to check nodes with error: {e}")
        finally:
            [self.port_pool.release_port(p) for p in ports]

    def clean_delay_results(self):
        self.proxy_delay_dict = {
            k: d
            for k, d in self.proxy_delay_dict.items()
            if k
            not in [
                "自动选择",
                "故障转移",
                "DIRECT",
                "手动选择",
                "节点选择",
                "COMPATIBLE",
                "GLOBAL",
                "DIRECT",
                "PASS",
                "REJECT",
                "REJECT-DROP",
            ]
        }

    def get_nodes(self):
        alive_delay_results = {}
        for k, d in self.proxy_delay_dict.items():
            if d.alive:
                if d.history is None or len(d.history) == 0:
                    logger.info(f"节点 {k} 延迟数据为空")
                    continue
                alive_delay_results[k] = d

        delay_nodes = [n for n in self.nodes if n["name"] in alive_delay_results]
        delay_nodes.sort(
            key=lambda n: average_delay(
                self.proxy_delay_dict[n["name"]].history,
            )
        )
        return delay_nodes

    async def nodes_clean(self, config_helper: ClashConfigHelper) -> None:
        # 更新全局配置
        logger.info("===================节点批量检测基本信息===================")
        logger.info(f"API: {config_helper.get_api_url()}")
        logger.info(f"URL_TEST: {settings.delay_url_test}")

        try:
            available_groups = config_helper.get_group_names()[1:]
            logger.info(f"可测试策略组: {', '.join(available_groups)}")
            # 测试策略组，只需要测试其中一个即可
            await self.run_clash_group_test(config_helper, available_groups[0])
        except Exception as e:
            logger.exception(f"错误: 测试策略组时发生异常: {e}")
        logger.info("批量检测完毕")

    async def run_clash_group_test(
        self,
        config_helper: ClashConfigHelper,
        test_group: str,
    ):
        logger.info(
            f"=================== 开始测试策略组: {test_group} ==================="
        )
        # 开始测试
        start_time = datetime.now()

        # 创建支持多端口的API实例
        async with ClashAPI(
            config_helper.host,
            [config_helper.port],
            settings.clash_secret,
        ) as clash_api:
            if not await clash_api.check_connection():
                return

            try:
                proxies = config_helper.get_group_proxies(test_group)
                if not proxies:
                    logger.info(f"策略组 '{test_group}' 中没有代理节点")
                    return

                # 测试该组的所有节点
                await self.test_group_proxies(
                    clash_api,
                    test_group,
                )

                # 显示总耗时
                total_time = (datetime.now() - start_time).total_seconds()
                logger.info(f"总耗时: {total_time:.2f} 秒")
            except Exception as e:
                logger.info(f"发生错误: {e}")
                raise

    # 打印测试结果摘要
    def print_test_summary(
        self,
        group_name: str,
    ):
        """打印测试结果摘要"""
        valid_proxies = [p for p in self.proxy_delay_dict if p.alive]
        valid = len(valid_proxies)
        invalid = len(self.proxy_delay_dict) - len(valid_proxies)

        logger.info(f"策略组 '{group_name}' 测试结果:")
        logger.info(f"总节点数: {len(self.proxy_delay_dict)}")
        logger.info(f"可用节点数: {valid}")
        logger.info(f"失效节点数: {invalid}")

        if valid > 0:
            avg_delay = sum(average_delay(p) for p in valid_proxies) / valid
            logger.info(f"平均延迟: {avg_delay:.2f}ms")

            logger.info("节点延迟统计:")
            sorted_proxies = sorted(
                valid_proxies, key=lambda p: average_delay(p.history)
            )
            for i, p in enumerate(sorted_proxies[: settings.limit], 1):
                logger.info(f"{i}. {p.name}: {average_delay(p.history):.2f}ms")

    async def test_group_proxies(
        self,
        clash_api: ClashAPI,
        group_name: str,
        task_times: int = 2,
    ) -> None:
        """测试策略组中的节点组"""
        # 创建所有测试任务
        logger.info(f"开始测试组 {group_name} (请求测试次数: {task_times})")

        # 使用进度显示执行所有任务
        for i in range(task_times):
            await clash_api.test_group_delay(group_name)
            # 显示进度
            done = i + 1
            total = task_times
            logger.info(f"进度: {done}/{total} ({done / total * 100:.1f}%)")

        try:
            clash_proxies = await clash_api.get_proxies()
            with self._lock:
                self.proxy_delay_dict.update(
                    ProxyDelayList.model_validate(
                        clash_proxies,
                    ).proxies
                )
        except Exception as e:
            logger.exception(f"获取策略组 {group_name} 节点延迟失败: {e}")


if __name__ == "__main__":
    prepare_clash()
