# AutoDetectLinks

自动抓取合并互联网上的公开节点。

## 公告

警报：Clash 死了！[最后的遗照](https://github.com/doreamon-design/clash)

受此影响，MetaCubeX 团队宣布放弃 Clash.Meta，改入游戏行业并发布了第一款基于 YS 二开的游戏：[mihomo](https://github.com/MetaCubeX/mihomo)。我试过了，很好玩（

为推动国产游戏(?)发展，本项目现已适配 mihomo 专用订阅，支持更多节点！详见下方 Clash 使用说明。

## Google Play 下载服务器已调整

Google Play 的**国内**下载服务器已完成部署，国行机下载软件时可以不过代理直连，非国行机仍然走国外服务器但也可直连。下载时将 `🐟 漏网之鱼` 切换成 `DIRECT` 即可享受**直连**的快感！

如果此问题有变化，我们会在此更新，请及时关注。

我们新增了 `snippets` 文件夹来存放从 `list.yml` 中拆分出的配置片段，用于将本项目提供的一些配置整合到你自己的配置中。

此项目现已添加“反 996 许可证”，请各位使用者**不要违法违规要求别人加班，自觉遵守《中华人民共和国劳动法》及其它法律法规**！

## 使用方法

注意：加速链接可能会失效，如果无法更新订阅，请把所有链接从上到下每个试一遍！你可以在电脑浏览器上安装油猴脚本 [Github 增强 - 高速下载](https://greasyfork.org/zh-CN/scripts/412245)，在目录浏览点开 `list.txt`，然后在 `Raw` 按钮边上找到最新的加速链接。

添加 Base64 订阅：
- <https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt>
- <https://mirror.ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt>


或添加 Clash 订阅：（重磅：本项目同时提供 Meta 专用订阅，支持更多节点！要使用 Meta 专用订阅，请将链接最后的 `.yml` 替换成 `.meta.yml`。如果 Meta 提示解析错误，请**更新 Meta 至最新版本**！）
- <https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml>
- <https://mirror.ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml>

或添加 Sing-Box 订阅：（第三方提供转换，不支持本项目的节点选择）
- [转换链接（第三方）](https://subapi.fxxk.dedyn.io/sub?target=singbox&url=https%3A%2F%2Fraw.githubusercontent.com%2Fpeasoft%2FNoMoreWalls%2Fmaster%2Flist.meta.yml&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online_Full_NoAuto.ini&tls13=true&emoji=true&list=false&xudp=true&udp=true&tfo=false&expand=true&scv=false&fdn=false&singbox.ipv6=1)

## 免责声明

订阅节点仅作学习交流使用，用于查找资料，学习知识，不做任何违法行为。所有资源均来自互联网，仅供大家交流学习使用，出现违法问题概不负责。**做出违法行为需要承担法律责任，侥幸逃脱是不可能的**！~~为阻止违法行为，本项目随时可以停止运行~~ 本项目可以采取各种技术手段来尽力阻止违法行为。

## 开发提示

由于本仓库的完整 Commit 历史极大（见页顶 repo size），如果要克隆本仓库，请使用：

```bash
git clone https://github.com/peasoft/NoMoreWalls.git --depth=1
```

如果本地仓库长期未更新，请删除仓库并重新克隆来同步最新更改，不要使用 `git pull`。

