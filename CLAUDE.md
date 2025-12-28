# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an automated installation system for Xray (XTLS proxy) with support for both TLS and REALITY modes. The installer creates a complete proxy server setup with camouflage websites, SSL certificate management, and optional residential proxy routing for AI sites.

## Key Architecture Decisions

### Two Security Modes
- **TLS Mode**: Traditional approach using Let's Encrypt certificates with domain validation. Requires domain name and DNS configuration. Uses nginx fallback to Hacker News for unauthorized traffic.
- **REALITY Mode**: No certificate needed. Mimics a target website (default: microsoft.com) by copying its TLS fingerprint. Cannot be used with CDN but highly resistant to detection.

### User Isolation Strategy
All Xray components run as a dedicated `xray` user (not root) for security. This includes:
- Xray service itself (via systemd override)
- acme.sh certificate management
- nginx web server (changed from default www-data/nginx user)
- All log files and certificates

Key files:
- Systemd override: `/etc/systemd/system/xray.service.d/override.conf`
- Nginx user changed in: `/etc/nginx/nginx.conf`
- Log permissions: `chmod 666` on log files to allow user writes

### Certificate Management Flow (TLS Mode)
1. Install acme.sh as xray user (not root)
2. Setup nginx on port 80 FIRST with webroot for ACME challenges
3. Test with staging server to avoid rate limits
4. Request real certificate using webroot mode (not standalone)
5. Install cert to `~/certs/` directory
6. Setup monthly auto-renewal via crontab (1st of month, 1:00 AM)

The installation order is critical: nginx must be running on port 80 before certificate requests.

### AI Site Routing (Optional)
When enabled, routes specific domains (OpenAI, Anthropic, etc.) through a residential proxy to avoid datacenter IP detection:
- Uses Xray's routing rules with domain matching
- Supports SOCKS5 proxy configuration
- Blocks UDP for AI sites (TCP only)
- Template: `templates/config-reality-warp.json`

## Common Commands

### Installation
```bash
# Interactive installation
sudo bash install.sh

# Using config file
sudo bash install.sh --config config.env
```

### Service Management
```bash
# Check status
sudo systemctl status xray
sudo systemctl status nginx

# Restart services
sudo systemctl restart xray
sudo systemctl restart nginx

# View logs
tail -f /home/xray/xray/logs/error.log
journalctl -u xray -f
```

### Certificate Management (TLS mode)
```bash
# Issue certificate
sudo bash certs.sh issue example.com

# Renew certificate
sudo bash certs.sh renew example.com

# Manual renewal using user's script
sudo -u xray bash /home/xray/certs/xray-cert-renew.sh

# Check certificate expiry
openssl x509 -in /home/xray/certs/xray.crt -noout -dates
```

### BBR Configuration
```bash
# Enable BBR congestion control
sudo bash bbr.sh

# Check BBR status
sysctl net.ipv4.tcp_congestion_control
lsmod | grep bbr
```

### Testing
```bash
# Test Xray configuration
xray -test -config /usr/local/etc/xray/config.json

# Test nginx configuration
sudo nginx -t

# Check port usage
ss -tlnp | grep -E ":(80|443)"
```

## Directory Structure
```
/home/xray/
├── certs/                    # SSL certificates (TLS mode only)
│   ├── xray.crt
│   ├── xray.key
│   └── xray-cert-renew.sh    # Auto-renewal script
├── xray/
│   └── logs/                 # Xray logs (chmod 666 for user writes)
│       ├── access.log
│       └── error.log
├── web/                      # Camouflage website / ACME webroot
│   ├── index.html
│   └── .well-known/acme-challenge/
├── .acme.sh/                 # acme.sh installation (TLS mode)
├── client-config.txt         # Generated client configuration
├── renew-cert.sh             # Certificate renewal wrapper
└── status.sh                 # Status check script

/usr/local/etc/xray/
└── config.json               # Main Xray configuration

/etc/systemd/system/
└── xray.service.d/
    └── override.conf         # Sets User=xray, Group=xray
```

## Configuration Files

### Main Configuration
- `config.env`: Installation configuration (created from `config.env.example`)
- `/usr/local/etc/xray/config.json`: Xray runtime configuration

### Templates
- `templates/config-reality.json`: REALITY mode base
- `templates/config-tls.json`: TLS mode base
- `templates/config-reality-warp.json`: REALITY with residential proxy
- `templates/nginx-proxy.conf`: Nginx reverse proxy config
- `templates/nginx-static.conf`: Nginx static site config

## Module Scripts

### Core Scripts
- `install.sh`: Main orchestration script with interactive setup
- `install-xray.sh`: Standalone Xray installer (legacy, not used by main flow)
- `certs.sh`: Certificate management module
- `bbr.sh`: BBR congestion control module
- `uninstall.sh`: Remove Xray installation
- `warp.sh`: Cloudflare WARP setup (for residential proxy)
- `xray-cert-renew.sh`: Certificate renewal (created during install)

### Library Files
- `lib/utils.sh`: Shared utility functions (logging, validation, etc.)
- `lib/colors.sh`: Color definitions for terminal output

## Important Implementation Notes

### Permission Issues
The installer fixes two common permission problems:
1. **Nginx access denied**: Changes nginx user to `xray` in `/etc/nginx/nginx.conf`
2. **Xray log writes**: Sets `chmod 666` on log files + systemd User/Group override

### DNS Validation
For TLS mode, the installer checks DNS records before certificate issuance:
- Compares domain IP vs server IP
- Tests HTTP access to `.well-known/acme-challenge/`
- Warns on mismatch but allows override

### Port 80 Requirement
- TLS mode: Port 80 required for ACME HTTP-01 challenges
- REALITY mode: Port 80 minimal (just HTTP redirect)
- Always check port availability before certificate requests

### REALITY Target Selection
Target website must support:
- TLS 1.3
- HTTP/2
- Common choices: microsoft.com, apple.com, cloudflare.com
- Verify with: `openssl s_client -connect target.com:443 -servername target.com -alpn h2`

### Routing Rules
The installer generates different routing configurations based on `USE_SECONDARY_IP`:
- Without proxy: Simple rules blocking private IPs and ads
- With proxy: Additional rules routing AI domains through SOCKS5
- Domain strategy changes: `IPIfNonMatch` (simple) vs `AsIs` (with proxy)

## Troubleshooting Common Issues

### Certificate Issuance Fails
1. Check DNS: `dig ${DOMAIN} +short`
2. Check port 80 accessibility: `curl -I http://${DOMAIN}/.well-known/acme-challenge/`
3. Check firewall allows port 80
4. Run with debug: `sudo -u xray ~/.acme.sh/acme.sh --issue -d ${DOMAIN} -w ${WEB_DIR} --keylength ec-256 --debug`

### Xray Won't Start
1. Test config: `xray -test -config /usr/local/etc/xray/config.json`
2. Check logs: `journalctl -u xray -n 50`
3. Verify log directory permissions
4. Check port 443 not already in use

### REALITY Connection Fails
1. Verify target supports TLS 1.3 and HTTP/2
2. Check serverNames matches target certificate
3. Verify shortId matches between server and client
4. Try different fingerprint (chrome/firefox/safari)

## Development Workflow

When modifying the installer:
1. Test both TLS and REALITY modes separately
2. Test with and without residential proxy configuration
3. Verify DNS checks don't block valid configurations
4. Test certificate renewal scripts work as xray user (not root)
5. Ensure all scripts work when sourced from any directory (uses `SCRIPT_DIR`)
