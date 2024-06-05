# AutoDetectLinks

自动抓取合并互联网上的公开节点。

## 公告

警报：Clash 死了！[最后的遗照](https://github.com/doreamon-design/clash)

受此影响，MetaCubeX 团队宣布放弃 Clash.Meta，改入游戏行业并发布了第一款基于 YS 二开的游戏：[mihomo](https://github.com/MetaCubeX/mihomo)。我试过了，很好玩（

## 关于 Google Play 等服务在国内无法使用的解决方法

~~由于 Google 调整了服务器安排，将原有的国外服务器的**域名**调整到了国内专版，但是**服务器**还没跟上，导致 Google Play 等服务在国内连上的是**空域名**，直接不能用了。~~

根据一些来源，这可能是一个多年以前的历史遗留问题了，只不过以前高质量的节点可以避开这个问题，而现在节点质量的下降导致这个问题又出现了。当前的解决办法有：

1. **使用 Clash Meta**，使用本项目提供的**完整**订阅无需配置，自行配置的请看下一条。
2. **如果您使用的是本项目提供的 Rule Providers**，请在 `rules` 开头加上：
```yaml
  - DOMAIN-SUFFIX,googleapis.cn,🚀 选择代理
  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,DIRECT # Google Play 国外/国内 服务器
  - DOMAIN-SUFFIX,xn--ngstr-cn-8za9o.com,DIRECT # Google Play 纯国内 服务器
```

如果此问题有进展，我们会在此更新，请及时关注。

我们新增了 `snippets` 文件夹来存放从 `list.yml` 中拆分出的配置片段，用于将本项目提供的一些配置整合到你自己的配置中。

此项目现已添加“反 996 许可证”，请各位使用者**不要违法违规要求别人加班，自觉遵守《中华人民共和国劳动法》及其它法律法规**！

## 使用方法

注意：加速链接可能会失效，如果无法更新订阅，请把所有链接从上到下每个试一遍！你可以在电脑浏览器上安装油猴脚本 [Github 增强 - 高速下载](https://greasyfork.org/zh-CN/scripts/412245)，在目录浏览点开 `list.txt`，然后在 `Raw` 按钮边上找到最新的加速链接。

添加 Base64 订阅：
- <https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt>
- <https://mirror.ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt>

以下链接可能不是最新：
- [JsDelivr 反代（zzko.cn）](https://cdn.jsdelivr.us/gh/peasoft/NoMoreWalls@master/list.txt)
- [JsDelivr Fastly CDN](https://fastly.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.txt)
- [JsDelivr Cloudflare CDN](https://testingcf.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.txt)
- [JsDelivr GCore CDN](https://gcore.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.txt)

或添加 Clash 订阅：（重磅：本项目同时提供 Meta 专用订阅，支持更多节点！要使用 Meta 专用订阅，请将链接最后的 `.yml` 替换成 `.meta.yml`。如果 Meta 提示解析错误，请**更新 Meta 至最新版本**！）
- <https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml>
- <https://mirror.ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml>

## 免责声明

订阅节点仅作学习交流使用，用于查找资料，学习知识，不做任何违法行为。所有资源均来自互联网，仅供大家交流学习使用，出现违法问题概不负责。**做出违法行为需要承担法律责任，侥幸逃脱是不可能的**！为阻止违法行为，本项目随时可以停止运行！！！

## 开发提示

由于本仓库的完整 Commit 历史极大（见页顶 repo size），如果要克隆本仓库，请使用：

```bash
git clone https://github.com/peasoft/NoMoreWalls.git --depth=1
```

如果本地仓库长期未更新，请删除仓库并重新克隆来同步最新更改，不要使用 `git pull`。

