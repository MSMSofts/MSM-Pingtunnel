#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root.${NC}"
   exit 1
fi

if ! command -v socat &> /dev/null; then
    echo -e "${YELLOW}socat is not installed. Attempting to install it...${NC}"
    if command -v apt &> /dev/null; then
        apt update && apt install socat -y
    elif command -v yum &> /dev/null; then
        yum install socat -y
    elif command -v dnf &> /dev/null; then
        dnf install socat -y
    elif command -v pacman &> /dev/null; then
        pacman -Sy socat --noconfirm
    else
        echo -e "${RED}Could not detect package manager. Please install socat manually.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}Installing acme.sh ...${NC}"
curl https://get.acme.sh | sh
source ~/.bashrc

read -p $'\033[0;32mEnter your domain (e.g. sub.domain.com): \033[0m' DOMAIN

read -p $'\033[0;32mEnter your email for Lets Encrypt registration (leave blank to auto-generate): \033[0m' EMAIL
if [[ -z "$EMAIL" ]]; then
    RAND_NUM=$((RANDOM % 9000 + 1000))
    RAND_STR=$(tr -dc a-z0-9 </dev/urandom | head -c6)
    EMAIL="auto${RAND_STR}${RAND_NUM}@gmail.com"
    echo -e "${YELLOW}No email entered. Using generated email: ${EMAIL}${NC}"
fi

SSL_DIR="/root/cert/$DOMAIN"

echo "Requesting certificate for $DOMAIN using standalone mode ..."
~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --email "$EMAIL" --force --server letsencrypt

echo "Saving keys to $SSL_DIR ..."
mkdir -p "$SSL_DIR"

~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
--key-file "$SSL_DIR/private.pem" \
--fullchain-file "$SSL_DIR/public.pem"

echo -e "${GREEN}Certificate installed.${NC}"

SERVICES=("nginx" "apache2" "httpd" "haproxy")
for SERVICE in "${SERVICES[@]}"; do
    if systemctl list-units --type=service --all | grep -q "$SERVICE.service"; then
        echo -e "${YELLOW}Restarting $SERVICE service...${NC}"
        systemctl restart "$SERVICE"
        systemctl is-active "$SERVICE" &>/dev/null && \
            echo -e "${GREEN}$SERVICE restarted successfully.${NC}" || \
            echo -e "${RED}Failed to restart $SERVICE.${NC}"
    fi
done

echo -e "${GREEN}Done!${NC}"
echo -e "${YELLOW}Private key: $SSL_DIR/private.pem${NC}"
echo -e "${YELLOW}Certificate: $SSL_DIR/public.pem${NC}"
