#!/bin/bash
# setup_server.sh - one-time network config for the VPN server.
# Run AFTER starting server.py (it needs tun0 to already exist).
# sudo python3 server.py &
# sudo ./setup_server.sh
set -e

TUN_IP="10.8.0.1"
TUN_NET="10.8.0.0/24"

# Auto-detect the interface facing the real internet (the one with the
# default route) so this works on any box without hardcoding eth0/ens5/etc.
WAN_IF=$(ip route | awk '/^default/ {print $5; exit}')
if [ -z "$WAN_IF" ]; then
  echo "Couldn't detect a default route / WAN interface. Set WAN_IF manually." >&2
  exit 1
fi
echo "Detected WAN interface: $WAN_IF"

echo "Assigning $TUN_IP to tun0..."
ip addr add ${TUN_IP}/24 dev tun0
ip link set tun0 up

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "Setting up NAT so tunnel clients can reach the internet..."
iptables -t nat -A POSTROUTING -s "$TUN_NET" -o "$WAN_IF" -j MASQUERADE
iptables -A FORWARD -i tun0 -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "Don't forget to open the UDP port in your firewall, e.g.:"
echo " ufw allow 51900/udp"
echo ""
echo "Server side ready. tun0 = $TUN_IP, clients get 10.8.0.2, .3, ..."
