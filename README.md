# Xray Auto Installer

A comprehensive, modular installation script for Xray with VLESS + XTLS-Vision or REALITY support.

Based on the [official XTLS documentation](https://xtls.github.io/document/level-0/).

## Features

- ✅ Install essential packages (git, zsh, wget, vim, nginx, etc.)
- ✅ Create dedicated `xray` user with sudo privileges
- ✅ Interactive password setup with confirmation
- ✅ Camouflage website (reverse proxy Hacker News or custom site)
- ✅ acme.sh for SSL certificate management with auto-renewal
- ✅ Xray installation with proper user/permission configuration
- ✅ BBR congestion control
- ✅ Support for both TLS and REALITY modes
- ✅ Optional: Secondary IP routing via WARP for specific sites (OpenAI, Netflix, etc.)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/xray-installer.git
cd xray-installer

# Run the installer
sudo bash install.sh
```

## Requirements

- Debian 10+ or Ubuntu 20.04+
- Root or sudo access
- A domain name (for TLS mode)
- Ports 80 and 443 available

## Installation Modes

### 1. TLS Mode (Traditional)

Requires a valid domain name pointing to your server. Uses Let's Encrypt certificates.

```
Client <--TLS--> Your Server (with valid cert) <---> Internet
```

**Pros:**
- Works everywhere
- Full control over certificate

**Cons:**
- Requires domain name
- Certificate management needed

### 2. REALITY Mode

No certificate needed. Uses camouflage by mimicking a real website (e.g., microsoft.com).

```
Client <--REALITY--> Your Server (mimics microsoft.com) <---> Internet
```

**Pros:**
- No domain/certificate needed
- Highly resistant to detection
- TLS fingerprint matches target site

**Cons:**
- Requires client support for REALITY
- Cannot be used with CDN

## Directory Structure

After installation, the following directories are created:

```
/home/xray/
├── certs/              # SSL certificates (TLS mode)
│   ├── xray.crt
│   └── xray.key
├── xray/
│   └── logs/           # Xray logs
│       ├── access.log
│       └── error.log
├── web/                # Camouflage website (static mode)
│   └── index.html
├── client-config.txt   # Client configuration info
├── renew-cert.sh       # Certificate renewal script
└── status.sh           # Status check script
```

## Module Scripts

### Main Installer
```bash
sudo bash install.sh              # Interactive installation
sudo bash install.sh --config config.env  # Use config file
```

### BBR Module
```bash
sudo bash bbr.sh                  # Enable BBR congestion control
```

### Certificate Module
```bash
sudo bash certs.sh install        # Install acme.sh
sudo bash certs.sh issue <domain> # Issue certificate
sudo bash certs.sh renew          # Renew all certificates
sudo bash certs.sh list           # List certificates
sudo bash certs.sh check          # Check certificate info
```

## Configuration Files

### Xray Configuration
Location: `/usr/local/etc/xray/config.json`

### Nginx Configuration
Location: `/etc/nginx/nginx.conf`

### Systemd Service Override
Location: `/etc/systemd/system/xray.service.d/override.conf`

## Common Issues and Solutions

### Issue 1: Nginx permission denied

**Problem:** Nginx fails to access files in `/home/xray/web/`

**Solution:** The script automatically changes the nginx user to `xray` in `/etc/nginx/nginx.conf`:
```nginx
user xray;
```

### Issue 2: Xray log permission denied

**Problem:** Xray fails to write to log files when running as non-root user

**Solution:** The script creates a systemd override:
```ini
[Service]
User=xray
Group=xray
```

And sets proper log file permissions:
```bash
chmod 666 /home/xray/xray/logs/*.log
```

### Issue 3: Certificate renewal fails

**Problem:** acme.sh cannot renew certificate because port 80 is occupied

**Solution:** Use webroot mode instead of standalone:
```bash
sudo bash certs.sh issue-webroot example.com /home/xray/web
```

### Issue 4: REALITY connection fails

**Problem:** Cannot connect using REALITY mode

**Solution:** 
1. Verify the target site supports TLS 1.3 and HTTP/2
2. Check that serverNames matches your configuration
3. Ensure shortId matches between server and client
4. Try a different fingerprint (chrome, firefox, safari)

## Client Configuration

### TLS Mode

**v2rayN/v2rayNG:**
```
Protocol: VLESS
Address: your.domain.com
Port: 443
UUID: [from client-config.txt]
Flow: xtls-rprx-vision
Network: tcp
Security: tls
SNI: your.domain.com
```

### REALITY Mode

**v2rayN/v2rayNG:**
```
Protocol: VLESS
Address: YOUR_SERVER_IP
Port: 443
UUID: [from client-config.txt]
Flow: xtls-rprx-vision
Network: tcp
Security: reality
SNI: www.microsoft.com
Fingerprint: chrome
Public Key: [from client-config.txt]
Short ID: [from client-config.txt]
```

## Advanced: Secondary IP with WARP

To route specific sites (OpenAI, Netflix, etc.) through a different IP:

1. Install Cloudflare WARP:
```bash
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
sudo apt update && sudo apt install cloudflare-warp
warp-cli register
warp-cli set-mode proxy
warp-cli connect
```

2. Get WARP configuration:
```bash
warp-cli settings
```

3. Use the `config-reality-warp.json` template and fill in your WARP credentials.

## Management Commands

```bash
# Check Xray status
sudo systemctl status xray

# Restart Xray
sudo systemctl restart xray

# View logs
tail -f /home/xray/xray/logs/error.log

# Check nginx status
sudo systemctl status nginx

# Test nginx configuration
sudo nginx -t

# Renew certificates
sudo -u xray bash /home/xray/renew-cert.sh
```

## Security Recommendations

1. **Firewall:** Only allow ports 22, 80, and 443
```bash
ufw allow 22
ufw allow 80
ufw allow 443
ufw enable
```

2. **SSH:** Disable password authentication, use key-based auth
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
```

3. **Fail2ban:** Install to prevent brute force attacks
```bash
apt install fail2ban
```

4. **Updates:** Keep system updated
```bash
apt update && apt upgrade -y
```

## Troubleshooting

### Check if Xray is running
```bash
sudo systemctl status xray
```

### Check Xray configuration
```bash
xray -test -config /usr/local/etc/xray/config.json
```

### Check port usage
```bash
ss -tlnp | grep -E ":(80|443)"
```

### Check BBR status
```bash
sysctl net.ipv4.tcp_congestion_control
lsmod | grep bbr
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

## License

MIT

## Credits

- [Project X / XTLS](https://github.com/XTLS/Xray-core)
- [acme.sh](https://github.com/acmesh-official/acme.sh)
- [Official XTLS Documentation](https://xtls.github.io/)
