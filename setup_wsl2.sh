#!/bin/bash
# ============================================================
# WSL2 Setup Script cho Domain Scanner
# Chạy 1 lần trước khi scan: bash setup_wsl2.sh
# ============================================================
set -e

echo "=============================================="
echo "  WSL2 DOMAIN SCANNER SETUP"
echo "=============================================="

# 1. Cài Python dependencies
echo ""
echo "[1/4] Cài đặt Python packages..."
pip3 install --break-system-packages --quiet \
    dnspython \
    aiodns \
    aiohttp \
    pyOpenSSL \
    whoisit \
    whoisdomain \
    uvloop \
    tldextract 2>/dev/null || \
pip3 install \
    dnspython \
    aiodns \
    aiohttp \
    pyOpenSSL \
    whoisit \
    whoisdomain \
    uvloop \
    tldextract

echo "   ✅ Python packages OK"

# 2. Tăng file descriptor limits
echo ""
echo "[2/4] Tăng file descriptor limits..."
# Tạm thời cho session hiện tại
ulimit -n 65535 2>/dev/null || ulimit -n 32768 2>/dev/null || ulimit -n 10240

# Persistent
if ! grep -q "* soft nofile 65535" /etc/security/limits.conf 2>/dev/null; then
    echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf > /dev/null
    echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf > /dev/null
    echo "   Set limits.conf"
fi
echo "   ✅ FD limit: $(ulimit -n)"

# 3. Fix DNS — bypass WSL2 NAT relay
echo ""
echo "[3/4] Cấu hình DNS trực tiếp (bypass NAT)..."

# Tạo wsl.conf nếu chưa có
if ! grep -q "generateResolvConf" /etc/wsl.conf 2>/dev/null; then
    sudo bash -c 'cat >> /etc/wsl.conf << EOF

[network]
generateResolvConf = false
EOF'
    echo "   Set wsl.conf"
fi

# Set DNS servers trực tiếp
sudo bash -c 'cat > /etc/resolv.conf << EOF
# Direct DNS — bypass WSL2 NAT for high-throughput scanning
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 8.8.4.4
EOF'
echo "   ✅ DNS: 8.8.8.8, 1.1.1.1, 8.8.4.4"

# 4. Tune kernel networking
echo ""
echo "[4/4] Tune kernel networking..."
sudo sysctl -w net.core.somaxconn=65535 > /dev/null 2>&1 || true
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535 > /dev/null 2>&1 || true
sudo sysctl -w net.core.netdev_max_backlog=65535 > /dev/null 2>&1 || true
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 > /dev/null 2>&1 || true
sudo sysctl -w net.ipv4.tcp_fin_timeout=15 > /dev/null 2>&1 || true
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" > /dev/null 2>&1 || true
echo "   ✅ Kernel tuned"

# Verify
echo ""
echo "=============================================="
echo "  VERIFICATION"
echo "=============================================="
python3 -c "
import dns.resolver; print('  ✅ dnspython OK')
import aiodns; print('  ✅ aiodns OK')
import aiohttp; print('  ✅ aiohttp OK')
import OpenSSL; print('  ✅ pyOpenSSL OK')
import whoisit; print('  ✅ whoisit OK')
try:
    import uvloop; print('  ✅ uvloop OK')
except ImportError:
    print('  ⚠️  uvloop unavailable (OK, sẽ dùng default loop)')
print()
print('  ✅ SETUP HOÀN TẤT! Sẵn sàng chạy scanner.')
"

echo ""
echo "=============================================="
echo "  TIẾP THEO: bash run_scan.sh"
echo "=============================================="
