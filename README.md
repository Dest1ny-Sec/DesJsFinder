# DesJsFinder

> 被动JS分析 + 框架识别 + 主动Fuzz + 响应指纹 — 红队API挖掘利器

![screenshot](4.png)

## 功能

| 功能 | 说明 |
|------|------|
| 被动发现 | 浏览网页时自动拦截JS资源，提取所有隐藏API路径，图标实时显示发现数量 |
| 框架识别 | 自动识别芋道Yudao / Spring Boot / ThinkPHP / ASP.NET / Laravel / Shiro / Vue / React 等10种框架 |
| 路径分类 | 按风险自动标注：认证鉴权 / 管理后台 / 交易支付 / 用户管理 / 数据查询 |
| 一键Fuzz | 框架字典 + 路径变形 + 参数组合 + 并发探测，过滤404，只留有效接口 |
| 响应指纹 | 16种指纹自动识别：Actuator暴露、SQL报错、凭据泄露、ThinkPHP调试等 |
| Token注入 | 支持自定义Header，一键带Token探测所有接口 |
| 响应预览 | 点击Fuzz结果行展开查看响应体，JSON自动格式化 |
| 导出字典 | 一键导出命中接口或完整字典为txt文件 |

## 安装

```
git clone https://github.com/Dest1ny-Sec/DesJsFinder.git
```

Chrome → `chrome://extensions` → 开启"开发者模式" → "加载已解压的扩展程序" → 选择项目文件夹 → 打开任意网站即可。

## 使用

### 被动模式（自动）

![passive](1.png)

打开目标站 → 插件图标实时显示API数量 → 点图标查看详情

- 自动拦截页面所有JS文件（含内联脚本）
- 正则提取API路径
- 按风险等级排序（CRITICAL排最前面）

### 主动Fuzz

![fuzz](2.png)

1. 点击 Fuzz 按钮
2. 插件自动生成字典（框架模板 + 路径变形 + 参数组合 + 前缀推断）
3. 并发探测每个接口，过滤404和SPA噪音
4. 点击任意结果行展开查看响应内容

### 带Token探测

![token](3.png)

在输入框粘贴 `Authorization: Bearer xxx`，Fuzz时所有请求自动带Token。

支持多个Header，每行一个：
```
Authorization: Bearer eyJhbGciOi...
Cookie: JSESSIONID=abc123
X-App-Id: sephora
```

### 导出

- 命中 — 导出Fuzz确认存在的接口列表
- 字典 — 导出完整字典（可用于Burp/SQLMap）

## 框架识别

| 框架 | 识别特征 | 字典特点 |
|------|---------|---------|
| 芋道Yudao | `/admin-api/`, `VITE_GLOB_API_URL_PREFIX` | 80+ 接口(system/user/page, infra/file/upload, bpm/task/my...) |
| Spring Boot | `Whitelabel Error Page`, `actuator` | actuator完整端点 + swagger + druid |
| ThinkPHP | `thinkphp`, `runtime/log` | 日志泄露 + RCE路径 |
| ASP.NET | `__VIEWSTATE`, `IIS` | web.config + elmah.axd + trace.axd |
| Laravel | `csrf-token`, `XSRF-TOKEN` | /.env + storage/logs + telescope |
| Vue/React | `vue`, `react-dom`, `webpackJsonp` | /api/v1/ /api/v2/ 常见路径 |

## 响应指纹

| 指纹 | 风险 | 示例 |
|------|------|------|
| Actuator暴露 | CRITICAL | `{"_links":{"heapdump"...` |
| SQL错误 | CRITICAL | `SQL syntax`, `mysql_fetch` |
| 凭据泄露 | CRITICAL | `jdbc:mysql://`, `mongodb://` |
| ThinkPHP报错 | CRITICAL | ThinkPHP堆栈信息 |
| Spring错误页 | HIGH | `Whitelabel Error Page` |
| API文档 | HIGH | `swagger`, `api-docs` |
| 神策Debug | HIGH | `Sensors Analytics is ready` |
| Git泄露 | CRITICAL | `.git/HEAD` |

## 架构

```
content.js  →  提取页面JS URL + 内联脚本 → 发送background
background.js → 下载JS → 提取API → 框架识别 → Badge计数
popup.html/js → 秒开展示缓存 + 每1.5s拉新数据 + 一键Fuzz
filters/
  api-filter.js          → 路径提取 + 分类 + 方法推测
  framework-detect.js    → 10种框架识别 + 配置提取
  response-fingerprint.js → 16种响应指纹识别
src/core/
  dict-generator.js      → 框架字典 + 路径变形 + 参数组合
```

## 对比

| 特性 | FindSomething | Phantom | DesJsFinder |
|------|:---:|:---:|:---:|
| 被动收集JS路径 | Y | Y | Y |
| 内联脚本提取 | - | - | Y |
| 框架识别 | - | - | Y (10种) |
| 路径分类+风险评级 | - | - | Y |
| 响应指纹 | - | - | Y (16种) |
| 主动Fuzz | - | Y | Y |
| 参数组合探测 | - | - | Y |
| Token注入 | - | Y | Y |
| 响应内容预览 | - | - | Y |

## 致谢

- [FindSomething](https://github.com/residual/FindSomething) — 被动扫描思路
- [Phantom](https://github.com/Xuan8a1/Phantom) — 模块化架构

## License

MIT — Dest1ny
