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
dns:
  enable: true
  ipv6: false
  enhanced-mode: redir-host
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 223.6.6.6
    - 1.1.1.1
    - 8.8.8.8
  nameserver:
    - https://223.5.5.5/dns-query # 阿里云公共DNS
    - https://223.6.6.6/dns-query # 阿里云公共DNS
    # - 114.114.114.114 # 国内运行商 污染率高
    # - 101.101.101.101 # Quad tw
    - https://dns.adguard.com/dns-query # AdGuard 延迟高
  fallback:
    - dns.cloudflare.com # DoT cf
    - dns.google # DoT gg
    - https://8.8.8.8/dns-query # DoH gg
    - https://1.1.1.1/dns-query # DoH cf
    - https://dns.adguard.com/dns-query
    - https://dns-family.adguard.com/dns-query
    - https://dns-unfiltered.adguard.com/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/8
      - 0.0.0.0/32
    domain: # direct to fallback
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
      - '+.github.com'
      - '+.githubusercontent.com'
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
  nameserver-policy:
    'geosite:cn,private':
      - https://223.5.5.5/dns-query
      - https://223.6.6.6/dns-query

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

TUN 通用配置：

```yaml
tun:
  enable: true
```


- <https://github.com/hagezi/dns-blocklists>
