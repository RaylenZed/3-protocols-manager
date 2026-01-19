#!/bin/bash

# =========================================================
# Multi-Protocol Manager V3.1 (Fixed for Xray v26+)
# Github: https://github.com/RaylenZed/3-protocols-manager
# =========================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 路径定义 ---
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF="/usr/local/etc/xray/config.json"
HY2_CONF="/etc/hysteria/config.yaml"
SNELL_CONF="/etc/snell/snell-server.conf"

# --- 基础函数 ---

check_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}请使用 sudo -i 切换到 root 用户后运行！${NC}"; exit 1; }
}

install_tools() {
    if ! command -v jq &>/dev/null || ! command -v qrencode &>/dev/null; then
        echo -e "${BLUE}正在安装必要工具 (wget, curl, jq, qrencode)...${NC}"
        if command -v apt &>/dev/null; then
            apt update -y && apt install -y wget curl unzip vim jq qrencode openssl socat
        elif command -v yum &>/dev/null; then
            yum update -y && yum install -y wget curl unzip vim jq qrencode openssl socat
        elif command -v dnf &>/dev/null; then
            dnf update -y && dnf install -y wget curl unzip vim jq qrencode openssl socat
        fi
    fi
}

get_ip() {
    curl -s4m8 https://ip.gs || curl -s4m8 https://api.ipify.org
}

check_status() {
    if systemctl is-active --quiet $1; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}未运行${NC}"
    fi
}

# --- 1. Reality 管理 ---

install_reality() {
    echo -e "${BLUE}>>> 安装/重置 Xray Reality...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    mkdir -p /usr/local/etc/xray
    
    read -p "请输入伪装域名 (SNI) [默认: griffithobservatory.org]: " SNI
    [[ -z "$SNI" ]] && SNI="griffithobservatory.org"

    echo -e "${YELLOW}正在生成密钥...${NC}"
    KEYS_RAW=$($XRAY_BIN x25519)
    
    # 兼容性处理：尝试获取 PrivateKey
    PK=$(echo "$KEYS_RAW" | grep -i "Private" | awk -F: '{print $NF}' | awk '{print $1}')
    
    # 兼容性处理：尝试获取 PublicKey (新版 Xray 可能显示为 Password)
    PUB=$(echo "$KEYS_RAW" | grep -i "Public" | awk -F: '{print $NF}' | awk '{print $1}')
    if [[ -z "$PUB" ]]; then
        PUB=$(echo "$KEYS_RAW" | grep -i "Password" | awk -F: '{print $NF}' | awk '{print $1}')
    fi

    # 如果自动获取失败，回退到手动输入
    if [[ -z "$PK" || -z "$PUB" ]]; then
        echo -e "${RED}自动抓取密钥失败，进入手动模式。${NC}"
        echo -e "$KEYS_RAW"
        read -p "请输入 PrivateKey: " PK
        read -p "请输入 Public Key (或 Password): " PUB
    fi

    if [[ -z "$PK" || -z "$PUB" ]]; then
        echo -e "${RED}错误：未能获取有效密钥。${NC}"
        return
    fi
    
    UUID=$($XRAY_BIN uuid)
    SID=$(openssl rand -hex 4)

    cat > $XRAY_CONF <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$SNI:443",
          "serverNames": ["$SNI"],
          "privateKey": "$PK",
          "shortIds": ["$SID"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
    echo "$PUB" > /usr/local/etc/xray/public.key
    systemctl restart xray
    echo -e "${GREEN}Reality 安装完成！${NC}"
    view_reality
}

view_reality() {
    if [[ ! -f $XRAY_CONF ]]; then echo -e "${RED}未找到配置${NC}"; return; fi
    IP=$(get_ip)
    UUID=$(jq -r '.inbounds[0].settings.clients[0].id' $XRAY_CONF)
    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' $XRAY_CONF)
    SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' $XRAY_CONF)
    if [[ -f /usr/local/etc/xray/public.key ]]; then
        PUB=$(cat /usr/local/etc/xray/public.key)
    else
        PUB="未找到文件"
    fi
    LINK="vless://${UUID}@${IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUB}&sid=${SID}&type=tcp&headerType=none#Reality_Vision"
    echo -e "\n${YELLOW}=== Reality ===${NC}"
    echo -e "SNI: $SNI\nUUID: $UUID\nPublic Key: $PUB\nShortID: $SID"
    echo -e "链接: $LINK"
    qrencode -t ANSIUTF8 "$LINK"
}

manage_reality_menu() {
    echo -e "\n1. 查看配置 2. 重启 3. 停止 4. 日志"
    read -p "选择: " OPT
    case $OPT in
        1) view_reality ;;
        2) systemctl restart xray && echo "已重启" ;;
        3) systemctl stop xray && echo "已停止" ;;
        4) journalctl -u xray -n 20 --no-pager ;;
    esac
}

# --- 2. Hysteria 2 ---

install_hy2() {
    echo -e "${BLUE}>>> 安装 Hysteria 2...${NC}"
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) HY_ARCH="amd64" ;;
        aarch64) HY_ARCH="arm64" ;;
        *) echo "不支持架构"; return ;;
    esac
    LATEST=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep "tag_name" | cut -d '"' -f 4)
    wget -O /usr/local/bin/hysteria_server "https://github.com/apernet/hysteria/releases/download/${LATEST}/hysteria-linux-${HY_ARCH}"
    chmod +x /usr/local/bin/hysteria_server
    mkdir -p /etc/hysteria
    openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -days 3650 -subj "/CN=bing.com" 2>/dev/null
    PASS=$(openssl rand -base64 16)
    cat > $HY2_CONF <<EOF
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: $PASS
ignoreClientBandwidth: false
EOF
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria_server server -c /etc/hysteria/config.yaml
Restart=always
User=root
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl restart hysteria-server
    echo -e "${GREEN}Hysteria 2 安装完成！${NC}"
    view_hy2
}

view_hy2() {
    if [[ ! -f $HY2_CONF ]]; then echo -e "${RED}未找到配置${NC}"; return; fi
    IP=$(get_ip)
    PASS=$(grep "password:" $HY2_CONF | awk '{print $2}')
    LINK="hysteria2://${PASS}@${IP}:443?insecure=1&sni=bing.com#Hysteria2"
    echo -e "\n${YELLOW}=== Hysteria 2 ===${NC}"
    echo -e "密码: $PASS\n链接: $LINK"
    qrencode -t ANSIUTF8 "$LINK"
}

manage_hy2_menu() {
    echo -e "\n1. 查看配置 2. 重启 3. 停止 4. 日志"
    read -p "选择: " OPT
    case $OPT in
        1) view_hy2 ;;
        2) systemctl restart hysteria-server && echo "已重启" ;;
        3) systemctl stop hysteria-server && echo "已停止" ;;
        4) journalctl -u hysteria-server -n 20 --no-pager ;;
    esac
}

# --- 3. Snell ---

install_snell() {
    echo -e "${BLUE}>>> 安装 Snell v5...${NC}"
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        URL="https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip"
    else
        URL="https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-aarch64.zip"
    fi
    wget -O snell.zip "$URL"
    unzip -o snell.zip -d /usr/local/bin
    rm snell.zip
    chmod +x /usr/local/bin/snell-server
    mkdir -p /etc/snell
    PSK=$(openssl rand -base64 20 | tr -dc 'a-zA-Z0-9')
    cat > $SNELL_CONF <<EOF
[snell-server]
listen = 0.0.0.0:11807
psk = $PSK
ipv6 = false
EOF
    GROUP="nobody"
    grep -q "nogroup" /etc/group && GROUP="nogroup"
    cat > /lib/systemd/system/snell.service <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target
[Service]
Type=simple
User=nobody
Group=$GROUP
LimitNOFILE=32768
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=snell-server
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable snell
    systemctl restart snell
    echo -e "${GREEN}Snell 安装完成！${NC}"
    view_snell
}

view_snell() {
    if [[ ! -f $SNELL_CONF ]]; then echo -e "${RED}未找到配置${NC}"; return; fi
    IP=$(get_ip)
    PSK=$(grep "psk =" $SNELL_CONF | awk -F'= ' '{print $2}')
    echo -e "\n${YELLOW}=== Snell ===${NC}"
    echo -e "PSK: $PSK"
    echo -e "Surge: Proxy = snell, ${IP}, 11807, psk=${PSK}, version=5, tfo=true"
}

manage_snell_menu() {
    echo -e "\n1. 查看配置 2. 重启 3. 停止 4. 日志"
    read -p "选择: " OPT
    case $OPT in
        1) view_snell ;;
        2) systemctl restart snell && echo "已重启" ;;
        3) systemctl stop snell && echo "已停止" ;;
        4) journalctl -u snell -n 20 --no-pager ;;
    esac
}

# --- BBR ---

enable_bbr() {
    if grep -q "bbr" /etc/sysctl.conf; then
        echo -e "${GREEN}BBR 已开启${NC}"
    else
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR 已开启${NC}"
    fi
}

# --- Main ---

check_root
install_tools
while true; do
    clear
    echo -e "${BLUE}=== VPS All-in-One Manager ===${NC}"
    echo "1. 安装/重置 Reality (TCP 443)"
    echo "2. 安装/重置 Hysteria2 (UDP 443)"
    echo "3. 安装/重置 Snell v5 (11807)"
    echo "----------------------------"
    echo "4. 管理 Reality"
    echo "5. 管理 Hysteria2"
    echo "6. 管理 Snell"
    echo "----------------------------"
    echo "7. 开启 BBR"
    echo "0. 退出"
    read -p "选择: " C
    case $C in
        1) install_reality; read -p "..." ;;
        2) install_hy2; read -p "..." ;;
        3) install_snell; read -p "..." ;;
        4) manage_reality_menu; read -p "..." ;;
        5) manage_hy2_menu; read -p "..." ;;
        6) manage_snell_menu; read -p "..." ;;
        7) enable_bbr; read -p "..." ;;
        0) exit 0 ;;
    esac
done
