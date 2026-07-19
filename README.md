# DesJsFinder v1.3

> 被动 JS 分析 + Wappalyzer 指纹识别 + 主动 Fuzz — 红队 API 挖掘利器

## 截图

![API 接口采集](5.png)

![Fuzz 探测](6.png)

![实战效果](7.png)

## 功能

- **Wappalyzer 指纹** — 3774 种技术指纹，自动识别目标技术栈（框架/运行时/服务器/CDN/前端库）
- **被动 API 采集** — 浏览网页自动拦截 JS、提取隐藏 API 路径，支持内联脚本、MutationObserver、SPA 路由劫持
- **响应指纹** — 20 种漏洞指纹自动识别（Actuator 暴露、SQL 报错、Git 泄露、凭据泄露、Debug 模式等）
- **一键 Fuzz** — 16 种框架字典 + 路径变形 + 参数组合 + CRUD 推理，并发探测，带 Cookie/Token
- **Offscreen 请求** — Cookie 感知通道 + 网络层 Header 注入，绕过 CORS 限制
- **信息采集** — 域名、IP、手机号、邮箱、JWT、凭据、Cookie、localStorage、实时 API 流量监控
- **路径分类** — 16 类风险自动标注（Actuator / 认证 / 上传 / 后台 / 支付 / API 文档 / 敏感文件等）
- **代理联动** — 支持 HTTP/SOCKS 代理，配合 Burp Suite 使用

## 安装

```bash
git clone https://github.com/Dest1ny-Sec/DesJsFinder.git
```

Chrome → `chrome://extensions` → 开启「开发者模式」→ 「加载已解压的扩展程序」→ 选择项目文件夹。

## 使用

**被动模式**：打开目标站即可，插件自动收集 API、识别指纹，无需任何操作。

**主动 Fuzz**：在输入框粘贴 Token（可选），点击 **FUZZ**，自动生成字典并发探测。点击结果行展开响应体预览。

**指纹查看**：切换到「指纹」Tab，查看自动识别的技术栈（含置信度和版本号）。

## 架构

```
content.js      页面采集 + Wappalyzer 检测 + MutationObserver
injector.js     MAIN world: fetch/XHR hook + JS 全局扫描
background.js   下载 JS → 提取 API → Fuzz → 指纹识别
offscreen.js    Cookie 请求通道
popup.js        6 Tab UI (接口/实时/凭据/指纹/设置/探测)
filters/        指纹数据 + 检测引擎 + 字典生成
```

## 致谢

- [Wappalyzer](https://github.com/wappalyzer/wappalyzer) — 开源技术指纹库
- [Phantom](https://github.com/Team-intN18-SoybeanSeclab/Phantom) — Offscreen 请求架构
- [FindSomething](https://github.com/residual/FindSomething) — 被动扫描思路
- [SnowEyes](https://github.com/SickleSec/SnowEyes) — 动态扫描 / HTTP 头指纹
- [JSFinder](https://github.com/Threezh1/JSFinder) — URL 提取算法

## License

MIT
