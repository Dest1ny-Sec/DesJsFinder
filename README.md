# DesJsFinder v1.3

> 被动JS分析 + Wappalyzer指纹 + 主动Fuzz + 响应指纹 + Offscreen请求 — 红队API挖掘利器

## 功能

| 功能 | 说明 |
|------|------|
| **Wappalyzer 指纹** | 集成 Wappalyzer 开源指纹库，3774 种技术 × 7925 条规则（HTML / scriptSrc / JS 全局 / Header / Cookie） |
| **被动收集** | 浏览网页时自动拦截 JS 资源（含内联脚本、modulepreload），提取隐藏 API 路径 |
| **动态扫描** | MutationObserver 监听 DOM 变化 + SPA 路由劫持，自动增量采集 |
| **深度扫描** | Webpack chunk 路径推断 + import/require 递归分析 |
| **响应指纹** | 20 种响应指纹：Actuator 暴露、SQL 报错、Git 泄露、凭据泄露、Debug 模式、CORS 全开放等 |
| **HTTP 头指纹** | TideFinger 5000+ 关键词 + 内置 16 条正则，识别 Server / X-Powered-By 等技术栈 |
| **Cookie 识别** | PHP(PHPSESSID) / Java(JSESSIONID) / Shiro(rememberMe) / Laravel 等自动识别 |
| **路径分类** | 16 类风险标注：Actuator / 认证鉴权 / 文件上传 / 管理后台 / 交易支付 / API 文档 / 敏感文件等 |
| **一键 Fuzz** | 16 种框架字典 + 通用字典 + 路径变形 + 参数组合 + CRUD 推理，并发探测 |
| **Offscreen 请求** | Offscreen document + declarativeNetRequest 动态 Header 注入，Fuzz 可携带 Cookie/Token |
| **Token 注入** | 支持自定义 Header（Authorization / Cookie），自动捕获页面请求中的 Token |
| **代理支持** | Fuzz 时可配置 HTTP / SOCKS 代理，联动 Burp Suite |
| **信息采集** | 域名、IP、手机号、邮箱、JWT、凭据、Cookie、localStorage/sessionStorage |
| **响应预览** | 点击 Fuzz 结果行展开查看响应体，JSON 自动格式化 |

## 架构对比

| 特性 | FindSomething | Phantom | SnowEyes | JSFinder | DesJsFinder v1.3 |
|------|:---:|:---:|:---:|:---:|:---:|
| 被动收集 JS 路径 | Y | Y | Y | Y | Y |
| 内联脚本提取 | - | - | Y | Y | Y |
| 动态扫描(MutationObserver) | - | - | Y | - | Y |
| Webpack 适配 | - | - | Y | - | Y |
| Wappalyzer 指纹(3774种) | - | - | - | - | **Y** |
| 响应指纹(20种) | - | - | - | - | **Y** |
| HTTP 头指纹(TideFinger) | - | - | Y | - | **Y** |
| 路径分类+风险评级 | - | - | - | - | 16 类 |
| Offscreen Cookie 请求 | - | **Y** | - | - | **Y** |
| 主动 Fuzz + 字典生成 | - | API 测试 | - | - | **Y** |
| 参数组合 + CRUD 推理 | - | - | - | - | **Y** |
| Token 注入 + 自动捕获 | - | Y | - | - | Y |
| 代理(Burp 联动) | - | - | - | - | **Y** |
| CORS 降级 | - | - | Y | - | Y |
| 白名单 | - | - | Y | - | Y |
| 搜索过滤 | - | - | - | - | Y |

## 安装

```bash
git clone https://github.com/Dest1ny-Sec/DesJsFinder.git
```

Chrome → `chrome://extensions` → 开启"开发者模式" → "加载已解压的扩展程序" → 选择项目文件夹。

## 使用

### 被动模式（自动）

打开目标站 → 插件图标实时显示信息数量 → 点图标查看详情。

- 自动拦截页面所有 JS 文件（含内联脚本、modulepreload）
- 正则 + Wappalyzer AST 提取 API 路径、域名、IP、手机号、邮箱、JWT、凭据
- MutationObserver 监听动态注入脚本 + SPA 路由变化自动重扫

### 主动 Fuzz

1. 在输入框粘贴 Token（可选）：`Authorization: Bearer xxx` 或 `Cookie: JSESSIONID=abc`
2. 点击 **FUZZ** 按钮
3. 自动生成字典（框架模板 + 路径变形 + 参数组合 + CRUD 推理）
4. 并发探测 → 点击结果行展开响应 → 筛选 2xx/3xx/401/403/5xx
5. Offscreen document 自动处理带 Cookie 的请求

### 指纹 Tab

打开任意网站 → 切换到**指纹**标签页 → 查看自动识别的技术栈。

- 色点分类：蓝=基础设施 / 绿=运行时 / 金=框架 / 紫=前端 / 红=安全
- Wappalyzer 3774 种技术 + 内置框架检测 + HTTP 头指纹自动合并去重
- 显示置信度%、版本号、检测来源

## 架构

```
injector.js (MAIN world)
  ├─ fetch/XHR monkey-patch → 拦截运行时 API 请求
  └─ JS globals 扫描 → 发送到 content script

content.js (ISOLATED world)
  ├─ 提取 JS URL + 内联脚本 + DOM 属性路径
  ├─ Wappalyzer 引擎 → 3774 种技术指纹检测
  ├─ MutationObserver + SPA 路由劫持
  └─ 发送到 background

background.js (Service Worker)
  ├─ 下载 JS → 提取 API → 框架检测 → 指纹识别
  ├─ fuzzURL: 直接 fetch → Offscreen document → 页面注入 (三层降级)
  └─ declarativeNetRequest 动态 Header 注入

offscreen.html/js
  └─ Cookie 感知请求通道 (credentials:'include')

popup.html/js
  └─ 6 Tab: 接口 / 实时 / 凭据 / 指纹 / 设置 / 探测

filters/
  ├─ wappalyzer-data.json       1.3MB — 3774 种技术指纹数据
  ├─ wappalyzer-engine.js       轻量检测引擎 (HTML/scriptSrc/JS/Header/Cookie)
  ├─ api-filter.js              路径提取 + 16 类分类 + HTTP 方法推测
  ├─ framework-detect.js        20 种框架识别 + 配置提取
  ├─ response-fingerprint.js    20 种响应指纹
  └─ tide-fingerprint.js        5337 条 Header 关键词

src/core/
  └─ dict-generator.js          16 种框架字典 + 通用字典 + CRUD 推理
```

## 致谢

- [Wappalyzer](https://github.com/wappalyzer/wappalyzer) — 开源技术指纹数据库
- [FindSomething](https://github.com/residual/FindSomething) — 被动扫描思路
- [Phantom](https://github.com/Team-intN18-SoybeanSeclab/Phantom) — Offscreen 请求架构
- [SnowEyes](https://github.com/SickleSec/SnowEyes) — 动态扫描 / HTTP 头指纹
- [JSFinder](https://github.com/Threezh1/JSFinder) — URL 提取算法

## License

MIT — Dest1ny
