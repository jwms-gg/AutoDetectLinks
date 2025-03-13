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
    - https://120.53.53.53/dns-query # 腾讯
  fallback:
    - https://1.1.1.1/dns-query # Cloudflare Public DNS
    - https://1.1.1.2/dns-query # cloudflare （过滤恶意网站）
    - https://1.0.0.1/dns-query # Cloudflare Public DNS
    - https://1.0.0.2/dns-query # cloudflare （过滤恶意网站）
    - https://8.8.8.8/dns-query # Google Public DNS
    - https://8.8.4.4/dns-query # Google Public DNS
    - tls://8.8.4.4
    - tls://1.1.1.1

    - https://9.9.9.9/dns-query # IBM Quad9 （过滤恶意网站）
    - https://9.9.9.11:5053/dns-query # Quad9 Public DNS
    - https://208.67.222.222/dns-query # OpenDNS
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
    - 1.1.1.2
tun:
  enable: true
tcp-concurrent: true
unified-delay: true
```
