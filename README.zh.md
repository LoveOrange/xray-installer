# Xray 一键安装脚本

[English](README.md) | [中文](README.zh.md)

一键安装 Xray 代理服务器，支持 VLESS + XTLS-Vision。

基于 [XTLS 官方文档](https://xtls.github.io/document/level-0/)。

## 快速开始

```bash
# 克隆并运行
git clone https://github.com/LoveOrange/xray-installer.git
cd xray-installer
sudo bash install.sh
```

安装程序会引导你完成交互式配置。

## ⚠️ 重要：安装前准备

### 第一步：购买 VPS 服务器

你需要一台 VPS（虚拟专用服务器）来安装 Xray。

**推荐的 VPS 提供商：**
- [搬瓦工](https://bandwagonhost.com/) - 可靠稳定，针对中国用户优化 ([推广链接](https://bandwagonhost.com/aff.php?aff=76049))
- [VMISS](https://www.vmiss.com/) - 性能优秀，多个机房可选 ([推广链接](https://app.vmiss.com/aff.php?aff=3114))
- [Vultr](https://www.vultr.com/) - 全球节点，易于使用 ([推广链接](https://www.vultr.com/?ref=7126266))

**配置要求：**
- 至少 512MB 内存（推荐 1GB）
- Ubuntu 20.04+ 或 Debian 10+
- 端口 80 和 443 可访问

**参考价格：** 基础 VPS 每月 $3-10 美元

### 第二步：购买域名（TLS 模式需要）

**使用 TLS 模式必须在运行安装程序之前完成以下步骤：**

1. **购买域名：**
   - [Cloudflare](https://www.cloudflare.com/products/registrar/) - 最便宜，按成本价出售（.com 约 $9/年）
   - [Namecheap](https://www.namecheap.com/) - 流行选择，价格合理（约 $10/年）
   - [GoDaddy](https://www.godaddy.com/) - 知名品牌，易于使用
   - [Porkbun](https://porkbun.com/) - 价格实惠（约 $7/年）

2. **配置 DNS A 记录** 指向你的服务器 IP 地址
   - 登录域名注册商
   - 进入 DNS 设置
   - 添加 A 记录：`你的子域名` → `你的VPS-IP`
3. **等待 5-10 分钟** DNS 生效
4. **验证 DNS 是否生效：**
   ```bash
   # 将域名替换为你的域名
   dig your-domain.com +short
   # 应该返回你的服务器 IP 地址
   ```

**如果没有正确配置域名，TLS 模式的证书签发将会失败。**

### REALITY 模式（高级用户）
- ❌ 不需要域名
- ❌ 不需要证书
- ✅ 安装后即可立即使用

## 系统要求

- **操作系统**：Debian 10+ 或 Ubuntu 20.04+
- **访问权限**：Root 或 sudo 权限
- **端口**：80 和 443 必须可用
- **域名**：TLS 模式需要（见上述警告）

## 安装内容

安装程序将自动完成：
- ✅ 创建专用 `xray` 用户（安全运行，非 root）
- ✅ 安装 Xray-core with VLESS + XTLS-Vision
- ✅ 配置 SSL 证书自动续期（TLS 模式）
- ✅ 配置伪装网站（对未授权访客显示为普通网站）
- ✅ 启用 BBR 拥塞控制以提升性能
- ✅ 生成客户端配置文件

安装完成后，查看 `/home/xray/client-config.txt` 获取连接信息。

## 两种安全模式

| 功能     | TLS 模式            | REALITY 模式 |
| -------- | ------------------- | ------------ |
| 需要域名 | ✅ 是               | ❌ 否        |
| 需要证书 | ✅ 是（自动管理）   | ❌ 否        |
| 配置难度 | 简单                | 高级         |
| 抗检测性 | 良好                | 优秀         |
| 支持 CDN | ✅ 是               | ❌ 否        |

**建议：** 除非有特殊需求，否则使用 TLS 模式。

> **⚠️ 测试状态：**
> - ✅ **TLS 模式**：已完全测试并验证可用
> - ⚠️ **REALITY 模式**：尚未测试，使用需自行承担风险

## 安装过程

安装程序会要求你配置以下内容：

### 1. 用户配置
- **用户名**：默认为 `xray`（建议保持默认）
- **密码**：为 xray 用户设置密码（可选，可跳过）

### 2. 域名配置
- **域名**：你的域名（例如 `vpn.example.com`）
- **邮箱**：用于证书通知（可使用默认值）

### 3. 安全模式选择
- **TLS 模式（选项 1）**：使用域名和 SSL 证书
- **REALITY 模式（选项 2）**：无需域名，伪装成 microsoft.com 等网站

### 4. AI 站点路由（可选）

**问题：** AI 服务提供商（OpenAI、Anthropic、Google）经常屏蔽或限制来自 VPS 提供商的数据中心 IP。

**解决方案：** 通过住宅代理或静态 ISP 代理路由 AI 流量，使用干净的 IP 信誉。

安装时会询问：
- 是否要通过二级代理路由 AI 站点？(y/N)

如果选择 **yes**，你需要提供：
- **代理 IP 地址**（SOCKS5 代理）
- **代理端口**（通常由代理服务提供）
- **用户名和密码**（SOCKS5 凭据）

**代理类型选择：**
- **静态 ISP 代理**（推荐）：固定价格，无限流量 - 适合 AI 和流媒体
- **住宅代理**：按流量计费，流媒体（HBO、Netflix）成本很高，仅适合 AI

**路由的站点：**
- ✅ `openai.com`、`chatgpt.com`、`chat.openai.com`
- ✅ `anthropic.com`、`claude.ai`
- ✅ `ai.com`

**注意：** 可以在安装时跳过此步骤，稍后再配置。

### 5. 确认安装
- 查看所有设置
- 确认继续安装

整个安装过程需要 **5-10 分钟**。

## 基础管理

```bash
# 查看服务状态
sudo systemctl status xray

# 重启 Xray
sudo systemctl restart xray

# 查看日志
tail -f /home/xray/xray/logs/error.log

# 查看客户端配置
cat /home/xray/client-config.txt
```

## 故障排除

**证书签发失败：**
- 验证 DNS：`dig your-domain.com +short` 是否匹配服务器 IP
- 检查端口 80 可访问性：`curl -I http://your-domain.com`
- 确保防火墙允许端口 80 和 443

**Xray 无法启动：**
- 测试配置：`xray -test -config /usr/local/etc/xray/config.json`
- 查看日志：`journalctl -u xray -n 50`

**连接问题：**
- 验证客户端配置是否与 `/home/xray/client-config.txt` 匹配
- 检查 VPS 提供商控制面板的防火墙设置
- 确保端口 443 未被封锁

## 客户端设置

安装完成后，脚本会生成完整的配置文件：

```bash
cat /home/xray/client-config.txt
```

此文件包含：
- 连接参数（UUID、密钥、端口）
- v2rayN/v2rayNG 的分享链接
- Clash Meta、Shadowrocket 等的配置片段

**只需将相应的分享链接或配置复制到客户端应用即可。**

支持的客户端：
- **Windows/Linux：** v2rayN、Nekoray
- **Android：** v2rayNG、NekoBox
- **iOS：** Shadowrocket、Stash
- **macOS：** V2RayXS、Clash Verge

## AI 和流媒体站点的代理选择

**常见问题：** 许多 VPS 提供商的 IP 地址被 AI 服务标记为数据中心 IP：
- OpenAI/ChatGPT：可能需要手机验证或完全阻止访问
- Anthropic/Claude：可能限流或限制 API 访问
- Google Bard/Gemini：类似的限制
- 流媒体：Netflix、HBO、Disney+ 可能检测并阻止数据中心 IP

**解决方案：** 使用住宅代理或静态 ISP 代理仅路由 AI/流媒体流量。你的代理看起来像普通家庭互联网连接。

### 住宅代理 vs 静态 ISP 代理

| 功能     | 住宅代理                   | 静态 ISP 代理                    |
| -------- | -------------------------- | -------------------------------- |
| 计费方式 | 按流量计费（昂贵）         | 固定月费                         |
| 适用于   | 仅 AI 站点                 | AI + 流媒体（Netflix、HBO）      |
| 流量限制 | 受成本限制                 | 通常无限                         |
| IP 轮换  | 频繁轮换                   | 静态 IP                          |
| 费用     | 重度使用每月 $50-200 美元  | 每月 $5-20 美元                  |

**建议：** 使用 **静态 ISP 代理** 性价比更高，特别是如果你使用流媒体服务。

### 购买渠道

**静态 ISP 代理提供商（推荐）：**
- [Thordata](https://www.thordata.com/) - 价格与性能平衡良好 ⭐（目前在用）
- [Proxy-Seller](https://proxy-seller.com/) - 静态 ISP 代理，可靠
- [IPRoyal](https://iproyal.com/) - 价格实惠的静态 ISP 选项

**住宅代理提供商：**
- [Bright Data](https://brightdata.com/) - 高端选择，按流量计费
- [Smartproxy](https://smartproxy.com/) - 适合新手，按流量计费

**费用预估：**
- 静态 ISP：每月 $5-20 美元（无限流量）
- 住宅代理：每月 $50-200 美元（取决于用量）

安装程序会自动处理所有路由配置 - 只需在设置时提供代理凭据即可。

## 高级选项

### 使用配置文件

```bash
# 复制示例配置
cp config.env.example config.env

# 编辑配置
vim config.env

# 使用配置文件安装
sudo bash install.sh --config config.env
```

### 启用 BBR（提升网络性能）

```bash
sudo bash bbr.sh
```

### 手动续期证书

```bash
sudo -u xray bash /home/xray/certs/xray-cert-renew.sh
```

## 贡献

欢迎提交 Pull Request。如有重大更改，请先开 Issue 讨论。

## 许可证

MIT

## 致谢

- [Project X / XTLS](https://github.com/XTLS/Xray-core)
- [acme.sh](https://github.com/acmesh-official/acme.sh)
- [XTLS 官方文档](https://xtls.github.io/)
