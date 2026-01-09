#!/usr/bin/env bash
#
# AGN-UDP Hysteria Server Management Script
# Repository: https://github.com/mhrlet/udp.git
# Usage: agnudp
#

set -e

###############################################################################
# CONFIGURATION - DEFAULT VALUES
###############################################################################

# Server domain or IP address (will be auto-detected)
DOMAIN=""

# Protocol
PROTOCOL="udp"

# UDP Port
UDP_PORT=":36712"

# Port range for NAT
PORT_RANGE_START="10000"
PORT_RANGE_END="65000"

# Obfuscation
OBFS="agnudp"

# Password
PASSWORD="agnudp"

# Speeds (Mbps)
UP_SPEED="100"
DOWN_SPEED="100"

###############################################################################
# PATHS AND VARIABLES
###############################################################################

REPO_URL="https://github.com/mhrlet/udp.git"
HYSTERIA_REPO="https://github.com/apernet/hysteria"
HYSTERIA_VERSION="v1.3.5"

EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
SCRIPT_INSTALL_PATH="/usr/local/bin/agnudp"
SYSCTL_CONFIG="/etc/sysctl.d/99-hysteria.conf"

OPERATING_SYSTEM="linux"
ARCHITECTURE=""

###############################################################################
# COLOR FUNCTIONS
###############################################################################

has_command() {
    command -v "$1" >/dev/null 2>&1
}

tput() {
    if has_command tput; then
        command tput "$@" 2>/dev/null || true
    fi
}

tred() { tput setaf 1; }
tgreen() { tput setaf 2; }
tyellow() { tput setaf 3; }
tblue() { tput setaf 4; }
tcyan() { tput setaf 6; }
tmagenta() { tput setaf 5; }
tbold() { tput bold; }
treset() { tput sgr0; }

log_info() {
    echo -e "$(tblue)[INFO]$(treset) $1"
}

log_success() {
    echo -e "$(tgreen)$(tbold)[SUCCESS]$(treset) $1"
}

log_warning() {
    echo -e "$(tyellow)$(tbold)[WARNING]$(treset) $1"
}

log_error() {
    echo -e "$(tred)$(tbold)[ERROR]$(treset) $1"
}

###############################################################################
# BANNER AND MENU
###############################################################################

show_banner() {
    clear
    echo -e "$(tcyan)$(tbold)"
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║                    AGN-UDP MANAGER                       ║
║                 Hysteria UDP Server                      ║
║                                                          ║
║              High-Speed UDP VPN Solution                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "$(treset)"
}

show_main_menu() {
    show_banner
    
    # Check if Hysteria is installed
    local is_installed=false
    local is_running=false
    
    if [[ -f "$EXECUTABLE_INSTALL_PATH" ]]; then
        is_installed=true
    fi
    
    if systemctl is-active --quiet hysteria-server.service 2>/dev/null; then
        is_running=true
    fi
    
    # Show status
    echo -e "$(tbold)Status:$(treset)"
    if [[ "$is_installed" == true ]]; then
        echo -e "  Installation: $(tgreen)✓ Installed$(treset)"
    else
        echo -e "  Installation: $(tred)✗ Not Installed$(treset)"
    fi
    
    if [[ "$is_running" == true ]]; then
        echo -e "  Service:      $(tgreen)● Running$(treset)"
    elif [[ "$is_installed" == true ]]; then
        echo -e "  Service:      $(tyellow)○ Stopped$(treset)"
    else
        echo -e "  Service:      $(tred)○ Not Available$(treset)"
    fi
    
    echo ""
    echo -e "$(tbold)Main Menu:$(treset)"
    echo ""
    
    if [[ "$is_installed" == false ]]; then
        echo -e "  $(tgreen)1)$(treset) Install AGN-UDP Server"
    else
        echo -e "  $(tcyan)1)$(treset) Reinstall AGN-UDP Server"
    fi
    
    if [[ "$is_installed" == true ]]; then
        echo -e "  $(tblue)2)$(treset) Edit Configuration"
        echo -e "  $(tblue)3)$(treset) View Configuration"
        echo -e "  $(tyellow)4)$(treset) Service Management"
        echo -e "  $(tmagenta)5)$(treset) View Logs"
        echo -e "  $(tcyan)6)$(treset) Connection Info"
        echo -e "  $(tyellow)7)$(treset) Update Hysteria"
        echo -e "  $(tmagenta)8)$(treset) Update Script"
        echo -e "  $(tgreen)9)$(treset) Fix Missing Server Field"
        echo -e "  $(tred)10)$(treset) Uninstall"
    fi
    
    echo -e "  $(tred)0)$(treset) Exit"
    echo ""
    echo -ne "$(tbold)Select option:$(treset) "
}

show_service_menu() {
    show_banner
    echo -e "$(tbold)Service Management:$(treset)"
    echo ""
    
    local status=$(systemctl is-active hysteria-server.service 2>/dev/null || echo "inactive")
    
    if [[ "$status" == "active" ]]; then
        echo -e "  Current Status: $(tgreen)● Running$(treset)"
        echo ""
        echo -e "  $(tyellow)1)$(treset) Stop Service"
        echo -e "  $(tcyan)2)$(treset) Restart Service"
    else
        echo -e "  Current Status: $(tred)○ Stopped$(treset)"
        echo ""
        echo -e "  $(tgreen)1)$(treset) Start Service"
        echo -e "  $(tcyan)2)$(treset) Restart Service"
    fi
    
    echo -e "  $(tblue)3)$(treset) Service Status"
    echo -e "  $(tmagenta)4)$(treset) Enable Auto-start"
    echo -e "  $(tyellow)5)$(treset) Disable Auto-start"
    echo -e "  $(tred)0)$(treset) Back to Main Menu"
    echo ""
    echo -ne "$(tbold)Select option:$(treset) "
}

pause() {
    echo ""
    echo -ne "$(tbold)Press Enter to continue...$(treset)"
    read
}

###############################################################################
# HELPER FUNCTIONS
###############################################################################

check_root() {
    if [[ "$UID" -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Please run: sudo agnudp"
        exit 1
    fi
}

detect_architecture() {
    case "$(uname -m)" in
        'i386' | 'i686')
            ARCHITECTURE='386'
            ;;
        'amd64' | 'x86_64')
            ARCHITECTURE='amd64'
            ;;
        'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
            ARCHITECTURE='arm'
            ;;
        'armv8' | 'aarch64')
            ARCHITECTURE='arm64'
            ;;
        'mipsle')
            ARCHITECTURE='mipsle'
            ;;
        's390x')
            ARCHITECTURE='s390x'
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    local deps=("curl" "wget" "openssl" "iptables" "net-tools")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! has_command "$dep"; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "${missing[@]}" >/dev/null 2>&1
    fi
}

get_server_ip() {
    # Try to get public IP address
    local ip=""
    
    # Try multiple services
    ip=$(curl -s -4 ifconfig.me 2>/dev/null) || \
    ip=$(curl -s -4 icanhazip.com 2>/dev/null) || \
    ip=$(curl -s -4 ipinfo.io/ip 2>/dev/null) || \
    ip=$(wget -qO- -4 ifconfig.me 2>/dev/null)
    
    # If all fail, try to get from ip command
    if [[ -z "$ip" ]]; then
        ip=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d/ -f1)
    fi
    
    echo "$ip"
}

load_config() {
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        # Load server from config (could be IP or domain)
        local config_server=$(grep -oP '(?<="server": ")[^"]*' "$CONFIG_DIR/config.json" 2>/dev/null)
        
        # If config has a server value, use it; otherwise detect current IP
        if [[ -n "$config_server" ]]; then
            DOMAIN="$config_server"
        else
            DOMAIN=$(get_server_ip)
        fi
        
        UDP_PORT=$(grep -oP '(?<="listen": ")[^"]*' "$CONFIG_DIR/config.json" 2>/dev/null || echo "$UDP_PORT")
        PROTOCOL=$(grep -oP '(?<="protocol": ")[^"]*' "$CONFIG_DIR/config.json" 2>/dev/null || echo "$PROTOCOL")
        OBFS=$(grep -oP '(?<="obfs": ")[^"]*' "$CONFIG_DIR/config.json" 2>/dev/null || echo "$OBFS")
        
        # Extract password from config array - look specifically inside the "auth" section
        local password_extracted=$(grep -A 3 '"auth"' "$CONFIG_DIR/config.json" | grep -oP '\["[^"]*"\]' | grep -oP '"\K[^"]+' | head -1)
        if [[ -n "$password_extracted" ]]; then
            PASSWORD="$password_extracted"
        fi
        
        UP_SPEED=$(grep -oP '(?<="up_mbps": )[0-9]+' "$CONFIG_DIR/config.json" 2>/dev/null || echo "$UP_SPEED")
        DOWN_SPEED=$(grep -oP '(?<="down_mbps": )[0-9]+' "$CONFIG_DIR/config.json" 2>/dev/null || echo "$DOWN_SPEED")
    else
        # No config file, detect current IP
        DOMAIN=$(get_server_ip)
    fi
}

###############################################################################
# INSTALLATION FUNCTIONS
###############################################################################

download_hysteria() {
    log_info "Downloading Hysteria binary..."
    
    local download_url="$HYSTERIA_REPO/releases/download/$HYSTERIA_VERSION/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
    local tmpfile=$(mktemp)
    
    if curl -L -f -# -o "$tmpfile" "$download_url"; then
        chmod +x "$tmpfile"
        mv "$tmpfile" "$EXECUTABLE_INSTALL_PATH"
        log_success "Hysteria binary installed"
    else
        log_error "Failed to download Hysteria"
        rm -f "$tmpfile"
        return 1
    fi
}

generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    mkdir -p "$CONFIG_DIR"
    cd "$CONFIG_DIR"
    
    openssl genrsa -out hysteria.ca.key 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key hysteria.ca.key \
        -subj "/C=US/ST=State/L=City/O=Hysteria/CN=Hysteria Root CA" \
        -out hysteria.ca.crt >/dev/null 2>&1
    
    openssl req -newkey rsa:2048 -nodes -keyout hysteria.server.key \
        -subj "/C=US/ST=State/L=City/O=Hysteria/CN=$DOMAIN" \
        -out hysteria.server.csr >/dev/null 2>&1
    
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,IP:$DOMAIN") \
        -days 3650 -in hysteria.server.csr \
        -CA hysteria.ca.crt -CAkey hysteria.ca.key -CAcreateserial \
        -out hysteria.server.crt >/dev/null 2>&1
    
    chmod 600 hysteria.*.key
    chmod 644 hysteria.*.crt
    rm -f hysteria.server.csr hysteria.ca.srl
    
    log_success "SSL certificates generated"
}

create_config_file() {
    log_info "Creating configuration file..."
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_DIR/config.json" << EOF
{
  "server": "$DOMAIN",
  "listen": "$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "$CONFIG_DIR/hysteria.server.crt",
  "key": "$CONFIG_DIR/hysteria.server.key",
  "up": "$UP_SPEED Mbps",
  "up_mbps": $UP_SPEED,
  "down": "$DOWN_SPEED Mbps",
  "down_mbps": $DOWN_SPEED,
  "disable_udp": false,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": ["$PASSWORD"]
  }
}
EOF
    
    chmod 644 "$CONFIG_DIR/config.json"
    log_success "Configuration file created"
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > "$SYSTEMD_SERVICES_DIR/hysteria-server.service" << 'EOF'
[Unit]
Description=Hysteria UDP Server (AGN-UDP)
Documentation=https://github.com/mhrlet/udp
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/etc/hysteria
ExecStart=/usr/local/bin/hysteria -config /etc/hysteria/config.json server
Restart=on-failure
RestartSec=10s
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "Systemd service created"
}

configure_firewall() {
    log_info "Configuring firewall..."
    
    export DEBIAN_FRONTEND=noninteractive
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    apt-get install -y -qq iptables-persistent >/dev/null 2>&1
    
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    if [[ -z "$iface" ]]; then
        iface="eth0"
    fi
    
    iptables -t nat -D PREROUTING -i "$iface" -p udp --dport $PORT_RANGE_START:$PORT_RANGE_END -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || true
    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport $PORT_RANGE_START:$PORT_RANGE_END -j DNAT --to-destination "$UDP_PORT"
    
    ip6tables -t nat -D PREROUTING -i "$iface" -p udp --dport $PORT_RANGE_START:$PORT_RANGE_END -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || true
    ip6tables -t nat -A PREROUTING -i "$iface" -p udp --dport $PORT_RANGE_START:$PORT_RANGE_END -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || true
    
    cat > "$SYSCTL_CONFIG" << EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.$iface.rp_filter = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
    
    sysctl -p "$SYSCTL_CONFIG" >/dev/null 2>&1
    
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    
    log_success "Firewall configured"
}

install_script() {
    log_info "Installing agnudp command..."
    
    # Get the actual script path
    local script_path="$(readlink -f "$0")"
    
    # Copy this script to /usr/local/bin/agnudp
    if [[ -f "$script_path" ]]; then
        cp "$script_path" "$SCRIPT_INSTALL_PATH"
        chmod +x "$SCRIPT_INSTALL_PATH"
        log_success "Command 'agnudp' installed"
    else
        log_warning "Could not install agnudp command globally"
        log_info "You can still run: $script_path"
    fi
}

###############################################################################
# MENU ACTIONS
###############################################################################

generate_random_password() {
    # Generate a random 12 character password
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12
}

action_reinstall() {
    show_banner
    echo -e "$(tcyan)$(tbold)Reinstall AGN-UDP Server$(treset)"
    echo ""
    
    # Load existing config
    load_config
    
    # Get current server IP for display
    local current_ip=$(get_server_ip)
    
    echo -e "$(tbold)Current Configuration:$(treset)"
    echo -e "  Server:        $(tgreen)$DOMAIN$(treset)"
    echo -e "  Current IP:    $(tgreen)$current_ip$(treset)"
    echo -e "  Port:          $(tgreen)${UDP_PORT#:}$(treset)"
    echo -e "  Password:      $(tgreen)$PASSWORD$(treset)"
    echo -e "  Upload Speed:  $(tgreen)$UP_SPEED Mbps$(treset)"
    echo -e "  Download Speed:$(tgreen)$DOWN_SPEED Mbps$(treset)"
    echo ""
    
    echo -e "$(tyellow)This will reinstall Hysteria binary and restart the service.$(treset)"
    echo -e "$(tyellow)Your configuration will be preserved.$(treset)"
    echo ""
    
    read -p "Continue with reinstall? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log_info "Reinstall cancelled"
        pause
        return
    fi
    
    echo ""
    log_info "Starting reinstallation..."
    echo ""
    
    # Stop service
    systemctl stop hysteria-server.service 2>/dev/null || true
    
    # Reinstall binary
    detect_architecture
    download_hysteria || return 1
    
    # Restart service
    systemctl start hysteria-server.service
    
    sleep 2
    
    if systemctl is-active --quiet hysteria-server.service; then
        echo ""
        log_success "Reinstallation completed successfully!"
    else
        log_error "Service failed to start"
        echo "Check logs: journalctl -u hysteria-server -n 50"
    fi
    
    pause
}

action_install() {
    show_banner
    echo -e "$(tgreen)$(tbold)Installing AGN-UDP Server$(treset)"
    echo ""
    
    # Auto-detect server IP
    log_info "Detecting server IP address..."
    local detected_ip=$(get_server_ip)
    
    if [[ -n "$detected_ip" ]]; then
        DOMAIN="$detected_ip"
        log_success "Detected IP: $detected_ip"
    else
        log_warning "Could not detect IP, using default"
        DOMAIN="127.0.0.1"
    fi
    
    # Generate random password if using default
    if [[ "$PASSWORD" == "agnudp" ]]; then
        PASSWORD=$(generate_random_password)
        log_info "Generated secure password"
    fi
    
    echo ""
    echo -e "$(tbold)Auto-configured settings:$(treset)"
    echo -e "  Server IP:     $(tgreen)$DOMAIN$(treset)"
    echo -e "  Port:          $(tgreen)${UDP_PORT#:}$(treset)"
    echo -e "  Protocol:      $(tgreen)$PROTOCOL$(treset)"
    echo -e "  Password:      $(tgreen)$PASSWORD$(treset)"
    echo -e "  Upload Speed:  $(tgreen)$UP_SPEED Mbps$(treset)"
    echo -e "  Download Speed:$(tgreen)$DOWN_SPEED Mbps$(treset)"
    echo ""
    
    read -p "Press Enter to install with these settings, or type 'custom' to configure manually: " choice
    
    if [[ "$choice" == "custom" ]]; then
        echo ""
        echo -e "$(tbold)Custom Configuration:$(treset)"
        echo ""
        
        read -p "Server IP/Domain [$DOMAIN]: " input
        DOMAIN=${input:-$DOMAIN}
        
        read -p "UDP Port (format :36712) [$UDP_PORT]: " input
        UDP_PORT=${input:-$UDP_PORT}
        
        read -p "Password [$PASSWORD]: " input
        PASSWORD=${input:-$PASSWORD}
        
        read -p "Upload Speed (Mbps) [$UP_SPEED]: " input
        UP_SPEED=${input:-$UP_SPEED}
        
        read -p "Download Speed (Mbps) [$DOWN_SPEED]: " input
        DOWN_SPEED=${input:-$DOWN_SPEED}
    fi
    
    echo ""
    log_info "Starting installation..."
    echo ""
    
    detect_architecture
    install_dependencies
    download_hysteria || return 1
    generate_ssl_certificates
    create_config_file
    create_systemd_service
    configure_firewall
    install_script
    
    # Start service
    systemctl enable hysteria-server.service >/dev/null 2>&1
    systemctl start hysteria-server.service
    
    sleep 2
    
    if systemctl is-active --quiet hysteria-server.service; then
        echo ""
        log_success "Installation completed successfully!"
        echo ""
        show_connection_info
    else
        log_error "Service failed to start"
        echo "Check logs: journalctl -u hysteria-server -n 50"
    fi
    
    pause
}

action_edit_config() {
    show_banner
    echo -e "$(tblue)$(tbold)Edit Configuration$(treset)"
    echo ""
    
    load_config
    
    # Get current server IP (actual network IP)
    local current_ip=$(get_server_ip)
    
    echo -e "Current configuration:"
    echo -e "  Server:       $(tgreen)$DOMAIN$(treset)"
    echo -e "  Current IP:   $(tgreen)$current_ip$(treset)"
    echo -e "  Port:         $(tgreen)${UDP_PORT#:}$(treset)"
    echo -e "  Password:     $(tgreen)$PASSWORD$(treset)"
    echo -e "  Upload:       $(tgreen)$UP_SPEED Mbps$(treset)"
    echo -e "  Download:     $(tgreen)$DOWN_SPEED Mbps$(treset)"
    echo ""
    
    echo -e "$(tbold)What would you like to edit?$(treset)"
    echo ""
    echo "  1) Update Server IP/Domain (Regenerate SSL)"
    echo "  2) Change Password"
    echo "  3) Change Speeds"
    echo "  4) Change Port"
    echo "  5) Edit config file manually"
    echo "  0) Back"
    echo ""
    echo -ne "Select option: "
    
    read choice
    
    case $choice in
        1)
            echo ""
            log_info "Current Server: $DOMAIN"
            log_info "Detected IP: $current_ip"
            echo ""
            echo "You can enter an IP address or domain name"
            read -p "Enter new server IP/Domain [$current_ip]: " new_server
            new_server=${new_server:-$current_ip}
            
            if [[ -n "$new_server" ]]; then
                log_info "Regenerating SSL certificates for $new_server..."
                
                cd "$CONFIG_DIR"
                
                # Backup old certificates
                mv hysteria.server.crt hysteria.server.crt.backup 2>/dev/null || true
                mv hysteria.server.key hysteria.server.key.backup 2>/dev/null || true
                
                # Generate new server key and CSR
                openssl req -newkey rsa:2048 -nodes -keyout hysteria.server.key \
                    -subj "/C=US/ST=State/L=City/O=Hysteria/CN=$new_server" \
                    -out hysteria.server.csr >/dev/null 2>&1
                
                # Generate new server certificate
                openssl x509 -req -extfile <(printf "subjectAltName=DNS:$new_server,IP:$new_server") \
                    -days 3650 -in hysteria.server.csr \
                    -CA hysteria.ca.crt -CAkey hysteria.ca.key -CAcreateserial \
                    -out hysteria.server.crt >/dev/null 2>&1
                
                # Set permissions
                chmod 600 hysteria.server.key
                chmod 644 hysteria.server.crt
                
                # Cleanup
                rm -f hysteria.server.csr hysteria.ca.srl
                
                # Update config.json with new server
                sed -i "s/\"server\": \"[^\"]*\"/\"server\": \"$new_server\"/" "$CONFIG_DIR/config.json"
                
                log_success "SSL certificates regenerated for $new_server"
                log_success "Configuration updated"
                
                # Restart service
                systemctl restart hysteria-server.service
                log_info "Service restarted"
                
                echo ""
                log_success "Server updated to: $new_server"
            fi
            pause
            ;;
        2)
            read -p "Enter new password: " new_pass
            if [[ -n "$new_pass" ]]; then
                sed -i "s/\"config\": \[\"[^\"]*\"\]/\"config\": [\"$new_pass\"]/" "$CONFIG_DIR/config.json"
                log_success "Password updated"
                systemctl restart hysteria-server.service
                log_info "Service restarted"
            fi
            pause
            ;;
        3)
            read -p "Upload speed (Mbps): " up
            read -p "Download speed (Mbps): " down
            if [[ -n "$up" && -n "$down" ]]; then
                sed -i "s/\"up_mbps\": [0-9]*/\"up_mbps\": $up/" "$CONFIG_DIR/config.json"
                sed -i "s/\"down_mbps\": [0-9]*/\"down_mbps\": $down/" "$CONFIG_DIR/config.json"
                sed -i "s/\"up\": \"[^\"]*\"/\"up\": \"$up Mbps\"/" "$CONFIG_DIR/config.json"
                sed -i "s/\"down\": \"[^\"]*\"/\"down\": \"$down Mbps\"/" "$CONFIG_DIR/config.json"
                log_success "Speeds updated"
                systemctl restart hysteria-server.service
                log_info "Service restarted"
            fi
            pause
            ;;
        4)
            read -p "Enter new port (format :36712): " new_port
            if [[ -n "$new_port" ]]; then
                # Update port in config
                sed -i "s/\"listen\": \"[^\"]*\"/\"listen\": \"$new_port\"/" "$CONFIG_DIR/config.json"
                
                # Update firewall rules
                local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
                if [[ -n "$iface" ]]; then
                    log_info "Updating firewall rules..."
                    
                    # Remove old rules
                    iptables -t nat -D PREROUTING -i "$iface" -p udp --dport $PORT_RANGE_START:$PORT_RANGE_END -j DNAT --to-destination "$UDP_PORT" 2>/dev/null || true
                    
                    # Add new rules
                    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport $PORT_RANGE_START:$PORT_RANGE_END -j DNAT --to-destination "$new_port"
                    
                    # Save rules
                    iptables-save > /etc/iptables/rules.v4
                fi
                
                log_success "Port updated to ${new_port#:}"
                systemctl restart hysteria-server.service
                log_info "Service restarted"
            fi
            pause
            ;;
        5)
            if has_command nano; then
                nano "$CONFIG_DIR/config.json"
            elif has_command vi; then
                vi "$CONFIG_DIR/config.json"
            else
                log_error "No text editor found"
                pause
                return
            fi
            log_info "Restarting service..."
            systemctl restart hysteria-server.service
            log_success "Service restarted"
            pause
            ;;
    esac
}

action_view_config() {
    show_banner
    echo -e "$(tcyan)$(tbold)Current Configuration$(treset)"
    echo ""
    
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        cat "$CONFIG_DIR/config.json"
    else
        log_error "Configuration file not found"
    fi
    
    pause
}

action_service_management() {
    while true; do
        show_service_menu
        read choice
        
        case $choice in
            1)
                if systemctl is-active --quiet hysteria-server.service; then
                    systemctl stop hysteria-server.service
                    log_success "Service stopped"
                else
                    systemctl start hysteria-server.service
                    log_success "Service started"
                fi
                sleep 1
                ;;
            2)
                systemctl restart hysteria-server.service
                log_success "Service restarted"
                sleep 1
                ;;
            3)
                systemctl status hysteria-server.service
                pause
                ;;
            4)
                systemctl enable hysteria-server.service
                log_success "Auto-start enabled"
                sleep 1
                ;;
            5)
                systemctl disable hysteria-server.service
                log_success "Auto-start disabled"
                sleep 1
                ;;
            0)
                return
                ;;
            *)
                log_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

action_view_logs() {
    show_banner
    echo -e "$(tmagenta)$(tbold)Service Logs$(treset)"
    echo ""
    echo "Press Ctrl+C to exit log view"
    echo ""
    sleep 2
    
    journalctl -u hysteria-server.service -f --no-pager
}

show_connection_info() {
    load_config
    
    # Get current IP
    local current_ip=$(get_server_ip)
    
    echo -e "$(tcyan)$(tbold)Connection Information:$(treset)"
    echo ""
    echo -e "  Server:       $(tgreen)$DOMAIN$(treset)"
    echo -e "  Current IP:   $(tgreen)$current_ip$(treset)"
    echo -e "  Port:         $(tgreen)${UDP_PORT#:}$(treset)"
    echo -e "  Protocol:     $(tgreen)$PROTOCOL$(treset)"
    echo -e "  Password:     $(tgreen)$PASSWORD$(treset)"
    echo -e "  Obfuscation:  $(tgreen)$OBFS$(treset)"
    echo ""
    echo -e "$(tbold)Client App:$(treset)"
    echo -e "  AGN INJECTOR"
    echo -e "  https://play.google.com/store/apps/details?id=com.agn.injector"
    echo ""
}

action_connection_info() {
    show_banner
    show_connection_info
    pause
}

action_update() {
    show_banner
    echo -e "$(tyellow)$(tbold)Update Hysteria$(treset)"
    echo ""
    
    log_info "Downloading latest version..."
    
    if download_hysteria; then
        log_info "Restarting service..."
        systemctl restart hysteria-server.service
        log_success "Hysteria updated successfully"
    else
        log_error "Update failed"
    fi
    
    pause
}

action_update_script() {
    show_banner
    echo -e "$(tmagenta)$(tbold)Update AGN-UDP Script$(treset)"
    echo ""
    
    local script_url="https://raw.githubusercontent.com/mhrlet/udp/main/agnudp.sh"
    local temp_script="/tmp/agnudp_new.sh"
    
    log_info "Checking for script updates..."
    echo ""
    
    # Download the new version
    if curl -L -f -# -o "$temp_script" "$script_url"; then
        chmod +x "$temp_script"
        
        # Backup current script
        if [[ -f "$SCRIPT_INSTALL_PATH" ]]; then
            cp "$SCRIPT_INSTALL_PATH" "$SCRIPT_INSTALL_PATH.backup"
            log_info "Current script backed up to: $SCRIPT_INSTALL_PATH.backup"
        fi
        
        # Install new version
        mv "$temp_script" "$SCRIPT_INSTALL_PATH"
        chmod +x "$SCRIPT_INSTALL_PATH"
        
        echo ""
        log_success "Script updated successfully!"
        echo ""
        echo -e "$(tyellow)The script will now restart with the new version.$(treset)"
        echo ""
        
        sleep 2
        
        # Restart the script
        exec "$SCRIPT_INSTALL_PATH"
    else
        log_error "Failed to download script update"
        rm -f "$temp_script"
    fi
    
    pause
}

action_fix_missing_server() {
    show_banner
    echo -e "$(tgreen)$(tbold)Fix Missing Server Field$(treset)"
    echo ""
    
    # Check if server field exists
    if grep -q '"server":' "$CONFIG_DIR/config.json" 2>/dev/null; then
        log_info "Server field already exists in configuration"
        echo ""
        local current_server=$(grep -oP '(?<="server": ")[^"]*' "$CONFIG_DIR/config.json")
        echo -e "Current server value: $(tgreen)$current_server$(treset)"
        echo ""
        read -p "Do you want to update it? (yes/no): " update_choice
        
        if [[ "$update_choice" != "yes" ]]; then
            log_info "No changes made"
            pause
            return
        fi
    fi
    
    log_info "Detecting server IP address..."
    local server_ip=$(get_server_ip)
    
    if [[ -z "$server_ip" ]]; then
        log_error "Could not detect server IP"
        echo ""
        read -p "Enter server IP or domain manually: " server_ip
        
        if [[ -z "$server_ip" ]]; then
            log_error "No server IP provided"
            pause
            return
        fi
    fi
    
    log_success "Detected IP: $server_ip"
    echo ""
    read -p "Use this IP, or enter a custom domain/IP [$server_ip]: " custom_input
    
    if [[ -n "$custom_input" ]]; then
        server_ip="$custom_input"
    fi
    
    log_info "Updating configuration with server: $server_ip"
    
    # Check if server field exists
    if grep -q '"server":' "$CONFIG_DIR/config.json"; then
        # Update existing server field
        sed -i "s/\"server\": \"[^\"]*\"/\"server\": \"$server_ip\"/" "$CONFIG_DIR/config.json"
        log_success "Server field updated"
    else
        # Add server field at the beginning (after opening brace)
        sed -i "2i\\  \"server\": \"$server_ip\"," "$CONFIG_DIR/config.json"
        log_success "Server field added"
    fi
    
    echo ""
    log_info "Restarting service..."
    systemctl restart hysteria-server.service
    
    sleep 2
    
    if systemctl is-active --quiet hysteria-server.service; then
        echo ""
        log_success "Configuration fixed successfully!"
        echo ""
        echo -e "$(tbold)Your connection details:$(treset)"
        show_connection_info
    else
        log_error "Service failed to restart"
        echo "Check logs: journalctl -u hysteria-server -n 50"
    fi
    
    pause
}

action_uninstall() {
    show_banner
    echo -e "$(tred)$(tbold)Uninstall AGN-UDP$(treset)"
    echo ""
    echo -e "$(tyellow)Warning: This will remove all AGN-UDP components$(treset)"
    echo ""
    read -p "Are you sure? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log_info "Uninstall cancelled"
        pause
        return
    fi
    
    log_info "Stopping service..."
    systemctl stop hysteria-server.service 2>/dev/null || true
    systemctl disable hysteria-server.service 2>/dev/null || true
    
    log_info "Removing files..."
    rm -f "$EXECUTABLE_INSTALL_PATH"
    rm -f "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    
    systemctl daemon-reload
    
    log_success "AGN-UDP uninstalled"
    echo ""
    echo "Configuration preserved at: $CONFIG_DIR"
    echo "To remove config: rm -rf $CONFIG_DIR"
    echo ""
    
    pause
}

###############################################################################
# MAIN PROGRAM
###############################################################################

main_loop() {
    check_root
    
    while true; do
        show_main_menu
        read choice
        
        if [[ ! -f "$EXECUTABLE_INSTALL_PATH" ]]; then
            # Not installed
            case $choice in
                1)
                    action_install
                    ;;
                0)
                    echo ""
                    echo "Goodbye!"
                    exit 0
                    ;;
                *)
                    log_error "Invalid option"
                    sleep 1
                    ;;
            esac
        else
            # Already installed
            case $choice in
                1)
                    action_reinstall
                    ;;
                2)
                    action_edit_config
                    ;;
                3)
                    action_view_config
                    ;;
                4)
                    action_service_management
                    ;;
                5)
                    action_view_logs
                    ;;
                6)
                    action_connection_info
                    ;;
                7)
                    action_update
                    ;;
                8)
                    action_update_script
                    ;;
                9)
                    action_fix_missing_server
                    ;;
                10)
                    action_uninstall
                    ;;
                0)
                    echo ""
                    echo "Goodbye!"
                    exit 0
                    ;;
                *)
                    log_error "Invalid option"
                    sleep 1
                    ;;
            esac
        fi
    done
}

# Run main program
main_loop
