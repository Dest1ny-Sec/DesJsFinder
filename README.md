# DesJsFinder v1.2

> 被动JS分析 + 动态扫描 + 深度扫描 + 框架识别 + 主动Fuzz + 指纹识别 — 红队API挖掘利器

## 功能

| 功能 | 说明 |
|------|------|
| **被动收集** | 浏览网页时自动拦截JS资源（含内联脚本、modulepreload），提取隐藏API路径 |
| **动态扫描** | MutationObserver 监听 DOM 变化，SPA 应用自动增量采集新注入的 JS |
| **深度扫描** | 递归分析 JS 中的 import/require 引用，Webpack chunk 文件名还原，自动拼接完整路径 |
| **框架识别** | 20种框架：芋道Yudao / 若依Ruoyi / Spring Boot / Spring Cloud / ThinkPHP / Laravel / FastAPI / Django / Flask / ASP.NET / Shiro / Vue / React / Angular / Next.js / Webpack / Vite / jQuery / ECharts / Node.js |
| **配置提取** | 自动提取 VITE_GLOB_API_URL_PREFIX、apiHost、baseURL 等框架配置 |
| **HTTP头指纹** | 识别 Server / X-Powered-By / X-AspNet-Version 等响应头，推断技术栈 |
| **Cookie识别** | 识别 PHPSESSID / JSESSIONID / ASP.NET_SessionId / rememberMe 等技术特征 |
| **信息采集** | 域名、IP地址、手机号、邮箱、JWT Token、凭据(key=value)、Cookie、公司机构、GitHub链接 |
| **路径分类** | 16类风险自动标注：Actuator / 认证鉴权 / 文件上传 / 管理后台 / 交易支付 / 用户管理 / API文档 / 数据查询 / 数据写入 / 基础设施 / 第三方对接 / 敏感文件 / 消息发送 / 工作流 / 业务模块 |
| **响应指纹** | 20种响应指纹识别：Actuator暴露、SQL报错、ThinkPHP调试、凭据泄露、Debug模式、CORS全开放等 |
| **一键Fuzz** | 框架字典(16种框架) + 路径变形 + 参数组合 + 并发探测，CORS自动降级 |
| **Token注入** | 支持自定义Header（Authorization / Cookie / 自定义Token），一键带Token探测 |
| **响应预览** | 点击Fuzz结果行展开查看响应体，JSON自动格式化 |
| **白名单** | 支持域名白名单，指定域名跳过扫描 |
| **网站解析** | 备案查询(ICP)、IP地理位置、搜索引擎权重 |
| **导出字典** | 一键导出命中接口或完整字典为txt文件 |

## 架构对比

| 特性 | FindSomething | Phantom | SnowEyes | JSFinder | DesJsFinder v1.2 |
|------|:---:|:---:|:---:|:---:|:---:|
| 被动收集JS路径 | Y | Y | Y | Y | Y |
| 内联脚本提取 | - | - | Y | Y | Y |
| 动态扫描(MutationObserver) | - | - | Y | - | Y |
| 深度扫描(递归JS) | - | - | Y | - | Y |
| Webpack适配 | - | - | Y | - | Y |
| 框架识别 | - | - | 基础 | - | 20种 |
| 路径分类+风险评级 | - | - | - | - | 16类 |
| HTTP头指纹 | - | - | Y | - | Y |
| Cookie指纹 | - | - | Y | - | Y |
| 响应指纹 | - | - | - | - | 20种 |
| 多类型信息采集 | - | - | 18种 | - | 10+种 |
| 主动Fuzz | - | Y | - | - | Y |
| 参数组合探测 | - | - | - | - | Y |
| Token注入 | - | Y | - | - | Y |
| 白名单 | - | - | Y | - | Y |
| 网站解析(ICP/IP) | - | - | Y | - | Y |
| 响应内容预览 | - | - | - | - | Y |
| CORS自动降级 | - | - | Y | - | Y |
| 复制/来源追踪 | - | - | Y | - | Y |
| 搜索过滤 | - | - | - | - | Y |

## 安装

```
git clone https://github.com/Dest1ny-Sec/DesJsFinder.git
```

Chrome → `chrome://extensions` → 开启"开发者模式" → "加载已解压的扩展程序" → 选择项目文件夹 → 打开任意网站即可。

## 使用

### 被动模式（自动）

打开目标站 → 插件图标实时显示信息数量 → 点图标查看详情

- 自动拦截页面所有JS文件（含内联脚本、modulepreload）
- 正则提取API路径 + 域名/IP/手机号/邮箱/JWT/凭据等
- MutationObserver 监听动态注入的脚本

### 主动Fuzz

1. 点击 Fuzz 按钮
2. 插件自动生成字典（框架模板 + 路径变形 + 参数组合 + 前缀推断）
3. 并发探测每个接口，CORS失败自动降级
4. 点击任意结果行展开查看响应内容

### 带Token探测

在输入框粘贴 `Authorization: Bearer xxx`，Fuzz时所有请求自动带Token。

支持多个Header，每行一个：
```
Authorization: Bearer eyJhbGciOi...
Cookie: JSESSIONID=abc123
X-App-Id: sephora
```

### 白名单

配置页面 → 输入域名（每行一个）→ 保存。这些域名的扫描将被跳过。

### 网站解析

切换到 Analysis 标签页 → 自动查询当前域名的ICP备案、IP地理位置。

### 搜索过滤

按 `/` 键 → 输入关键词实时过滤当前Tab的结果。

## 技术栈

| 框架 | 识别特征 | 字典特点 |
|------|---------|---------|
| 芋道Yudao | `/admin-api/`, `VITE_GLOB_API_URL_PREFIX` | 30+ 接口(system/user/page, infra/file/upload...) |
| 若依Ruoyi | `ruoyi`, `RuoYi` | system/user/list, monitor/job/list... |
| Spring Boot | `Whitelabel Error Page`, `actuator` | actuator完整端点 + swagger + druid |
| Spring Cloud | `gateway`, `nacos`, `eureka` | 微服务架构识别 |
| ThinkPHP | `thinkphp`, `runtime/log` | 日志泄露 + RCE路径 |
| Laravel | `csrf-token`, `XSRF-TOKEN` | /.env + storage/logs |
| FastAPI | `fastapi`, `/docs`, `/redoc` | OpenAPI端点 |
| Vue/React | `vue`, `react-dom`, `webpackJsonp` | /api/v1/ 常见路径 |

## 指纹识别

| 类别 | 内容 |
|------|------|
| HTTP头 | Apache / Nginx / IIS / Jetty / OpenResty / Tengine / Cloudflare / PHP / Java / Python / ASP.NET / Express |
| Cookie | PHP(PHPSESSID) / Java(JSESSIONID) / ASP.NET / Shiro(rememberMe) / Laravel |
| 响应 | Actuator暴露 / SQL报错 / ThinkPHP报错 / Debug模式 / CORS全开放 / Cookie无HttpOnly |

## 架构

```
content.js  →  提取页面JS URL + 内联脚本 + 动态扫描(MutationObserver) + 多类型信息提取
                → 发送background
background.js → 下载JS → 提取API → 框架识别 → 头指纹识别 → Cookie识别 → Badge计数
                → CORS降级(fetch → chrome.scripting注入)
popup.html/js → 秒开展示缓存 + 多Tab分类 + 搜索过滤 + 一键Fuzz + 网站解析
filters/
  api-filter.js          → 路径提取 + 16类分类 + 方法推测
  framework-detect.js    → 20种框架识别 + 配置提取
  response-fingerprint.js → 20种响应指纹识别
src/core/
  dict-generator.js      → 16种框架字典 + 路径变形 + 参数组合
```

## 致谢

- [FindSomething](https://github.com/residual/FindSomething) — 被动扫描思路
- [Phantom](https://github.com/Xuan8a1/Phantom) — 模块化架构
- [SnowEyes](https://github.com/SickleSec/SnowEyes) — 动态扫描 / 深度扫描 / HTTP头指纹 / 网站解析
- [JSFinder](https://github.com/Threezh1/JSFinder) — URL提取算法

## License

MIT — Dest1ny
