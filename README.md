# AutoDetectLinks


## Clash

- [clash](https://a76yyyy.github.io/clash/zh_CN/)


## 协议转换

- [v2ray to clash convert](https://blog.rezo.fun/protocol-uri-scheme-and-clash-sub-convert/)
- [subcocnverter 转换使用 naixi 教程](https://cdn.naixi.net/thread-2489-1-1.html)

## DNS 相关

- [clash dns leak](https://blog.rezo.fun/test-dns-leakage-caused-by-clash-rules/)
- [clash dns set stratege](https://blog.rezo.fun/combat-dns-pollution-and-leakage-through-reasonable-configuration-of-clash-dns-and-rules/)
- [openclash dns leak](https://clashx.cc/openclash-dns-leak/)
- [咸鱼 dns 防泄露 模板](https://blog.xianyu.one/2024/04/09/sub-server-re/)

可用的配置项

```yaml
  enhanced-mode: redir-host
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - tcp://223.5.5.5
    - tcp://223.6.6.6
  nameserver:
    - https://223.5.5.5/dns-query # 阿里云公共DNS
    - https://223.6.6.6/dns-query # 阿里云公共DNS
    - 114.114.114.114 # 国内运行商
    - 94.140.14.140 # AdGuard
  fallback:
    - https://1.1.1.1/dns-query # Cloudflare Public DNS
    - https://1.0.0.1/dns-query # Cloudflare Public DNS
    - https://8.8.8.8/dns-query # Google Public DNS
    - tls://1.1.1.1
    - https://9.9.9.11:5053/dns-query # Quad9 Public DNS
    - https://208.67.220.220/dns-query # OpenDNS
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
      - '+.github.com'
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '+.*'
    - '*.lan'
    - '*.local'
    - '*.localhost'
    - '*.localdomain'
    - 'stun.*.*'
    - 'stun.*.*.*'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - '+.stun.*.*.*.*'
    - '+.stun.*.*.*.*.*'
    - 'time.*.com'
    - 'time1.*.com'
    - 'time2.*.com'
    - 'time3.*.com'
    - 'time4.*.com'
    - 'time5.*.com'
    - 'time6.*.com'
    - 'time7.*.com'
    - 'ntp.*.com'
    - 'ntp1.*.com'
    - 'ntp2.*.com'
    - 'ntp3.*.com'
    - 'ntp4.*.com'
    - 'ntp5.*.com'
    - 'ntp6.*.com'
    - 'ntp7.*.com'
    - '*.msftconnecttest.com'
    - '*.msftncsi.com'
    - '*.steamcontent.com'
    - '*.*.xboxlive.com'
    - 'xbox.*.*.microsoft.com'
    - 'localhost.ptlogin2.qq.com'
    - 'localhost.sec.qq.com'
  nameserver-policy:
    '+.arpa': '10.0.0.1'
    'geosite:cn,private': '114.114.114.114'


dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - dns.msftncsi.com
    - www.msftncsi.com
    - www.msftconnecttest.com
    - stun.*.*.*
    - stun.*.*
    - miwifi.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - netis.cc
    - router.asus.com
    - repeater.asus.com
    - routerlogin.com
    - routerlogin.net
    - tendawifi.com
    - tendawifi.net
    - tplinklogin.net
    - tplinkwifi.net
    - tplinkrepeater.net
    - "*.ntp.org.cn"
    - "*.openwrt.pool.ntp.org"
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - localhost.ptlogin2.qq.com
    - "*.*.*.srv.nintendo.net"
    - "*.*.stun.playstation.net"
    - xbox.*.*.microsoft.com
    - "*.ipv6.microsoft.com"
    - "*.*.xboxlive.com"
    - speedtest.cros.wr.pvp.net
  default-nameserver:
    - 114.114.114.114
    - 9.9.9.9
  nameserver:
    - 1.2.4.8
    - 210.2.4.8
    - 223.5.5.5
    - 223.6.6.6
    - 52.80.52.52
    - 117.50.10.10
    - 180.76.76.76
    - 119.28.28.28
    - 119.29.29.29
    - 114.114.114.114
    - 114.114.115.115
    - 101.226.4.6
    - 218.30.118.6
    - 123.125.81.6
    - 140.207.198.6
    - 202.38.64.1
    - 202.112.20.131
    - 202.141.160.95
    - 202.141.160.99
    - 202.141.176.95
    - 202.141.176.99
    - tls://dot.pub:853
    - tls://1.12.12.12:853
    - tls://120.53.53.53:853
    - https://doh.pub/dns-query
    - https://sm2.doh.pub/dns-query
    - https://1.12.12.12/dns-query
    - https://120.53.53.53/dns-query
    - https://dns.alidns.com/dns-query
    - https://doh.dns.sb/dns-query
    - https://dns.rubyfish.cn/dns-query
  fallback:
    - 9.9.9.9
    - 149.112.112.112
    - 8.8.4.4
    - 8.8.8.8
    - 1.0.0.1
    - 1.1.1.1
    - 208.67.220.220
    - 208.67.220.222
    - 208.67.222.220
    - 208.67.222.222
    - 195.46.39.39
    - 195.46.39.40
    - 168.95.1.1
    - 203.80.96.10
    - 168.95.192.1
    - 164.124.101.2
    - 164.124.107.9
    - 203.248.252.2
    - 203.248.242.2
    - 80.80.80.80
    - 80.80.81.81
    - 199.85.126.10
    - 199.85.127.10
    - 168.126.63.1
    - 168.126.63.2
    - 139.175.252.16
    - 139.175.55.244
    - 202.45.84.58
    - 202.45.84.59
    - 8.26.56.26
    - 23.253.163.53
    - 77.88.8.1
    - 77.88.8.8
    - 89.233.43.71
    - 91.239.100.100
    - 198.101.242.72
    - 8.20.247.20
    - 64.6.64.6
    - 64.6.65.6
    - 209.244.0.3
    - 209.244.0.4
    - 210.220.163.82
    - 219.250.36.130
    - 202.14.67.4
    - 84.200.69.80
    - 84.200.70.40
    - 202.14.67.14
    - 156.154.70.1
    - 156.154.71.1
    - 216.146.35.35
    - 216.146.36.36
    - 77.109.148.136
    - 77.109.148.137
    - 101.101.101.101
    - 101.102.103.104
    - 74.82.42.42
    - 66.220.18.42
    - https://dns.quad9.net/dns-query
    - https://dns9.quad9.net/dns-query
    - tls://dns.google:853
    - https://8.8.4.4/dns-query
    - https://8.8.8.8/dns-query
    - https://dns.google/dns-query
    - tls://1.0.0.1:853
    - tls://1.1.1.1:853
    - tls://one.one.one.one
    - tls://1dot1dot1dot1.cloudflare-dns.com
    - https://1.0.0.1/dns-query
    - https://1.1.1.1/dns-query
    - https://cloudflare-dns.com/dns-query
    - https://dns.daycat.space/dns-query
    - https://dns.adguard.com/dns-query
    - https://dns-family.adguard.com/dns-query
    - https://dns-unfiltered.adguard.com/dns-query
    - tls://b.iqiq.io:853
    - tls://h.iqiq.io:853
    - tls://j.iqiq.io:853
    - tls://c.passcloud.xyz:853
    - tls://x.passcloud.xyz:853
    - https://a.passcloud.xyz/hk
    - https://a.passcloud.xyz/am
    - https://a.passcloud.xyz/us
    - https://a.passcloud.xyz/sz
    - https://a.passcloud.xyz/cdn
    - https://a.passcloud.xyz/dns-query
    - https://worldwide.passcloud.xyz/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/8
      - 0.0.0.0/32
    domain:
      - +.google.com
      - +.github.com
      - +.facebook.com
      - +.twitter.com
      - +.youtube.com
      - +.google.cn
      - +.googleapis.cn
      - +.googleapis.com
      - +.gvt1.com
```

## 本地验证 clash 配置

### 验证命令

```bash
./mihomo-linux -ext-ctl 127.0.0.1:9998 -f
urlencode() {   local LANG=C;   for ((i=0;i<${#1};i++)); do     if [[ ${1:$i:1} =~ ^[a-zA-Z0-9\.\~\_\-]$ ]]; then       printf "${1:$i:1}";     else       printf '%%%02X' "'${1:$i:1}";     fi;   done; }
encoded_query=$(urlencode '♻️ 自动选择')
curl "http://127.0.0.1:9999/group/$encoded_query/delay?timeout=5000&url=https://www.youtube.com" > _delay_youtube.json
curl "http://127.0.0.1:9999/group/$encoded_query/delay?timeout=5000&url=http://cp.cloudflare.com/generate_204" > _delay_cloudflare.json
curl "http://127.0.0.1:9999/group/$encoded_query/delay?timeout=5000&url=https://www.pinterest.com" > _delay_pinterest.json
curl "http://127.0.0.1:9999/group/$encoded_query/delay?timeout=5000&url=https://www.gstatic.com/generate_204" > _delay_gstatic.json
curl  http://127.0.0.1:9999/proxies > _proxies.json
curl "http://127.0.0.1:9999/proxies/$encoded_query/delay?timeout=5000&url=http://cp.cloudflare.com/generate_204"
```

通用配置：

```yaml
dns:
  enable: true
  listen: :1053
  ipv6: true
  enhanced-mode: redir-host
  nameserver:
    - 223.5.5.5
    - 223.6.6.6
    - 114.114.114.114
  fallback:
    - 8.8.8.8
    - 8.8.4.4
    - 1.1.1.1
tun:
  enable: true
tcp-concurrent: true
unified-delay: true
```


- <https://github.com/hagezi/dns-blocklists>
