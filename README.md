# Xray Auto Installer

[English](README.md) | [中文](README.zh.md)

One-command installation script for Xray proxy with VLESS + XTLS-Vision.

Based on the [official XTLS documentation](https://xtls.github.io/document/level-0/).

## Quick Start

```bash
# Clone and run
git clone https://github.com/LoveOrange/xray-installer.git
cd xray-installer
sudo bash install.sh
```

The installer will guide you through an interactive setup.

## ⚠️ Important: Before Installation

### Step 1: Get a VPS Server

You need a VPS (Virtual Private Server) to install Xray.

**Recommended VPS Providers:**

- [Bandwagon Host](https://bandwagonhost.com/) - Reliable, optimized for China users ([Affiliate Link](https://bandwagonhost.com/aff.php?aff=76049))
- [VMISS](https://www.vmiss.com/) - Good performance, multiple locations ([Affiliate Link](https://app.vmiss.com/aff.php?aff=3114))
- [Vultr](https://www.vultr.com/) - Global presence, easy to use ([Affiliate Link](https://www.vultr.com/?ref=7126266))

**Requirements:**

- At least 512MB RAM (1GB recommended)
- Any supported Linux distribution (Ubuntu, Debian, CentOS, RHEL, Rocky, AlmaLinux, Fedora, Arch, or Manjaro)
- Ports 80 and 443 accessible

**Typical Cost:** $3-10/month for basic VPS

### Step 2: For TLS Mode - Get a Domain

**You MUST complete these steps BEFORE running the installer:**

1. **Buy a domain name** from:

   - [Cloudflare](https://www.cloudflare.com/products/registrar/) - Cheapest, at-cost pricing (~$9/year for .com)
   - [Namecheap](https://www.namecheap.com/) - Popular, good prices (~$10/year)
   - [GoDaddy](https://www.godaddy.com/) - Well-known, easy to use
   - [Porkbun](https://porkbun.com/) - Budget-friendly (~$7/year)

2. **Configure DNS A record** pointing to your server's IP address
   - Login to your domain registrar
   - Go to DNS settings
   - Add an A record: `your-subdomain` → `your-vps-ip`
3. **Wait 5-10 minutes** for DNS propagation
4. **Verify DNS is working:**
   ```bash
   # Replace with your domain and server IP
   dig your-domain.com +short
   # Should return your server's IP address
   ```

**Without a properly configured domain, TLS mode certificate issuance will fail.**

### For REALITY Mode (Advanced)

- ❌ No domain required
- ❌ No certificate needed
- ✅ Works immediately after installation

## Requirements

- **OS**: See supported operating systems below
- **Access**: Root or sudo privileges
- **Ports**: 80 and 443 must be available
- **Domain**: Required for TLS mode (see warning above)

## Supported Operating Systems

This installer now supports multiple Linux distributions:

| Distribution | Versions Tested | Package Manager | Status |
|--------------|----------------|-----------------|--------|
| **Ubuntu** | 20.04+, 22.04, 24.04 | apt | ✅ Fully Supported |
| **Debian** | 10+, 11, 12 | apt | ✅ Fully Supported |
| **CentOS** | 7, 8, Stream | yum/dnf | ✅ Fully Supported |
| **RHEL** | 7, 8, 9 | yum/dnf | ✅ Fully Supported |
| **Rocky Linux** | 8, 9 | dnf | ✅ Fully Supported |
| **AlmaLinux** | 8, 9 | dnf | ✅ Fully Supported |
| **Fedora** | 36+ | dnf | ✅ Fully Supported |
| **Arch Linux** | Latest | pacman | ✅ Supported* |
| **Manjaro** | Latest | pacman | ✅ Supported* |

*Note: Cloudflare WARP is not officially available on Arch Linux. You'll need to use AUR (`yay -S cloudflare-warp-bin`) or alternative residential proxy configuration.

The installer automatically detects your operating system and uses the appropriate package manager.

## What Gets Installed

The installer will automatically:

- ✅ Create dedicated `xray` user (runs everything securely, not as root)
- ✅ Install Xray-core with VLESS + XTLS-Vision
- ✅ Setup SSL certificates with auto-renewal (TLS mode)
- ✅ Configure camouflage website (appears as normal site to unauthorized visitors)
- ✅ Enable BBR congestion control for better performance
- ✅ Generate client configuration file

After installation, check: `/home/xray/client-config.txt` for connection details.

## Two Security Modes

| Feature              | TLS Mode              | REALITY Mode |
| -------------------- | --------------------- | ------------ |
| Domain Required      | ✅ Yes                | ❌ No        |
| Certificate Needed   | ✅ Yes (auto-managed) | ❌ No        |
| Setup Difficulty     | Easy                  | Advanced     |
| Detection Resistance | Good                  | Excellent    |
| Works with CDN       | ✅ Yes                | ❌ No        |

**Recommendation:** Use TLS mode unless you have specific reasons to use REALITY.

> **⚠️ Testing Status:**
> - ✅ **TLS Mode**: Fully tested and verified working
> - ⚠️ **REALITY Mode**: Not tested yet, use at your own risk

## Installation Process

The installer will ask you to configure the following during setup:

### 1. User Configuration

- **Username**: Default is `xray` (recommended to keep)
- **Password**: Optional password for the xray user (you can skip this)

### 2. Domain Configuration

- **Domain name**: Your domain (e.g., `vpn.example.com`)
- **Email**: For certificate notifications (can use default)

### 3. Security Mode Selection

- **TLS Mode (Option 1)**: Uses your domain and SSL certificate
- **REALITY Mode (Option 2)**: No domain needed, mimics websites like microsoft.com

### 4. AI Site Routing (Optional)

**Problem:** AI providers (OpenAI, Anthropic, Google) often block or limit datacenter IPs from VPS providers.

**Solution:** Route AI traffic through a residential or static ISP proxy with clean IP reputation.

During installation, you'll be asked:

- Do you want to route AI sites through a secondary proxy? (y/N)

If you choose **yes**, you'll need:

- **Proxy IP address** (SOCKS5 proxy)
- **Proxy port** (usually provided by proxy service)
- **Username and password** (SOCKS5 credentials)

**Proxy Type Options:**

- **Static ISP Proxy** (Recommended): Fixed price, unlimited traffic - great for AI and streaming
- **Residential Proxy**: Pay-per-traffic, very expensive for streaming (HBO, Netflix), better for AI only

**What gets routed:**

- ✅ `openai.com`, `chatgpt.com`, `chat.openai.com`
- ✅ `anthropic.com`, `claude.ai`
- ✅ `ai.com`

**Note:** You can skip this during installation and configure it later if needed.

### 5. Summary and Confirmation

- Review all settings
- Confirm to proceed with installation

The entire installation takes **5-10 minutes**.

## Basic Management

```bash
# Check service status
sudo systemctl status xray

# Restart Xray
sudo systemctl restart xray

# View logs
tail -f /home/xray/xray/logs/error.log

# View client configuration
cat /home/xray/client-config.txt
```

## Troubleshooting

**Certificate issuance fails:**

- Verify DNS: `dig your-domain.com +short` matches your server IP
- Check port 80 is accessible: `curl -I http://your-domain.com`
- Ensure firewall allows ports 80 and 443

**Xray won't start:**

- Test config: `xray -test -config /usr/local/etc/xray/config.json`
- Check logs: `journalctl -u xray -n 50`

**Connection issues:**

- Verify client configuration matches `/home/xray/client-config.txt`
- Check firewall on your VPS provider's control panel
- Ensure port 443 is not blocked

## Client Setup

After installation completes, the script generates a complete configuration file:

```bash
cat /home/xray/client-config.txt
```

This file contains:

- Connection parameters (UUID, keys, ports)
- Share links for v2rayN/v2rayNG
- Configuration snippets for Clash Meta, Shadowrocket, etc.

**Simply copy the appropriate share link or configuration to your client app.**

Supported clients:

- **Windows/Linux:** v2rayN, Nekoray
- **Android:** v2rayNG, NekoBox
- **iOS:** Shadowrocket, Stash
- **macOS:** V2RayXS, Clash Verge

## Proxy Options for AI & Streaming Sites

**Common Issue:** Many VPS providers' IP addresses are flagged as datacenter IPs by AI services:

- OpenAI/ChatGPT: May require phone verification or block access entirely
- Anthropic/Claude: May rate-limit or restrict API access
- Google Bard/Gemini: Similar restrictions
- Streaming: Netflix, HBO, Disney+ may detect and block datacenter IPs

**Solution:** Use a residential or static ISP proxy to route only AI/streaming traffic. Your proxy appears as a regular home internet connection.

### Residential Proxy vs Static ISP Proxy

| Feature       | Residential Proxy           | Static ISP Proxy              |
| ------------- | --------------------------- | ----------------------------- |
| Pricing       | Pay per GB (expensive)      | Fixed monthly fee             |
| Best for      | AI sites only               | AI + Streaming (Netflix, HBO) |
| Traffic limit | Limited by cost             | Usually unlimited             |
| IP rotation   | Rotates frequently          | Static IP                     |
| Cost          | $50-200/month for heavy use | $5-20/month                   |

**Recommendation:** Use **Static ISP Proxy** for better value, especially if you use streaming services.

### Where to Buy

**Static ISP Proxy Providers (Recommended):**

- [Thordata](https://www.thordata.com/) - Good balance of price and performance ⭐ (currently using)
- [Proxy-Seller](https://proxy-seller.com/) - Static ISP proxies, reliable
- [IPRoyal](https://iproyal.com/) - Budget-friendly static ISP options

**Residential Proxy Providers:**

- [Bright Data](https://brightdata.com/) - Premium, pay-per-GB
- [Smartproxy](https://smartproxy.com/) - Good for beginners, pay-per-GB

**Cost Estimate:**

- Static ISP: $5-20/month (unlimited traffic)
- Residential: $50-200/month (depends on usage)

The installer handles all routing configuration automatically - just provide your proxy credentials during setup.

## Advanced Options

### Using Config File

```bash
# Copy example config
cp config.env.example config.env

# Edit with your settings
vim config.env

# Install using config
sudo bash install.sh --config config.env
```

### Enable BBR (Better Network Performance)

```bash
sudo bash bbr.sh
```

### Manual Certificate Renewal

```bash
sudo -u xray bash /home/xray/certs/xray-cert-renew.sh
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

## License

MIT

## Credits

- [Project X / XTLS](https://github.com/XTLS/Xray-core)
- [acme.sh](https://github.com/acmesh-official/acme.sh)
- [Official XTLS Documentation](https://xtls.github.io/)
