#!/bin/bash
set -e

PYTHON_BIN="python3"
INSTALLER_URL="https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main/Source/Pingtunnel.py" 
INSTALLER_PATH="/usr/local/bin/install_pingtunnel.py"

check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Please run as root (sudo)."
    exit 1
  fi
}

download_installer() {
  echo "⬇️ Downloading Python installer..."
  apt-get update
  apt-get install -y python3 python3-colorama curl ca-certificates
  curl -fsSL "$INSTALLER_URL" -o "$INSTALLER_PATH"
  chmod +x "$INSTALLER_PATH"
  echo "✅ Installer saved at $INSTALLER_PATH"
}

install_pingtunnel() {
  check_root
  download_installer
  echo "🚀 Running installer..."
  $PYTHON_BIN "$INSTALLER_PATH"
  read -n 1 -s -r -p "Press any key to continue..."
}

uninstall_pingtunnel() {
  check_root
  if [ ! -f "$INSTALLER_PATH" ]; then
    echo "⚠️ Installer not found at $INSTALLER_PATH"
    echo "Trying uninstall with runner (pingtunnel uninstall)..."
    if command -v pingtunnel >/dev/null 2>&1; then
      pingtunnel uninstall
    else
      echo "❌ The uninstalling failed."
    fi
  else
    echo "🗑️ Running uninstaller..."
    $PYTHON_BIN "$INSTALLER_PATH" uninstall
    echo "✅ Uninstall finished"
  fi
  read -n 1 -s -r -p "Press any key to continue..."
}

check_status() {
  echo "📡 Checking Pingtunnel status..."
  if command -v pingtunnel >/dev/null 2>&1; then
    pingtunnel status || echo "⚠️ Could not get status."
  else
    echo "⚠️ Pingtunnel not installed."
  fi
  read -n 1 -s -r -p "Press any key to continue..."
}

view_logs() {
  echo "📜 Showing last 100 log lines..."
  if command -v pingtunnel >/dev/null 2>&1; then
    pingtunnel logs 100 || echo "⚠️ No logs available."
  else
    echo "⚠️ Pingtunnel not installed."
  fi
  read -n 1 -s -r -p "Press any key to continue..."
}

restart_service() {
  echo "🔄 Restarting Pingtunnel..."
  if command -v pingtunnel >/dev/null 2>&1; then
    pingtunnel restart
    echo "✅ Restart requested"
  else
    echo "⚠️ Pingtunnel not installed."
  fi
  read -n 1 -s -r -p "Press any key to continue..."
}

show_menu() {
  clear
  echo "============================"
  echo "   Pingtunnel Installer"
  echo "   By HOSEINLOL V 1.0.3"
  echo "============================"
  echo "1) Install / Update Pingtunnel"
  echo "2) Uninstall Pingtunnel"
  echo "3) Check Status"
  echo "4) View Logs"
  echo "5) Restart Service"
  echo "6) Exit"
  echo "============================"
  echo -n "Choose an option [1-6]: "
}

while true; do
  show_menu
  read -r choice
  case "$choice" in
    1) install_pingtunnel ;;
    2) uninstall_pingtunnel ;;
    3) check_status ;;
    4) view_logs ;;
    5) restart_service ;;
    6) echo "Bye 👋"; exit 0 ;;
    *) echo "❌ Invalid choice, try again."; sleep 1 ;;
  esac
done
