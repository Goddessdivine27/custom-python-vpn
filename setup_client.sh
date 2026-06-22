#!/bin/bash
# setup_client.sh - one-time network config for the VPN client.
# Run AFTER client.py has handshaken and printed your assigned tun IP.
# sudo python3 client.py <server_ip> &
# sudo ./setup_client.sh <assigned_ip> [server_public_ip]
#
# If you pass server_public_ip, this does a FULL TUNNEL: all your
# traffic goes through the VPN. If you omit it, tun0 is just configured
# and brought up but your default route is untouched (split tunnel) - 
# safer default if you're testing this over SSH on a remote box.
set -e

if [ -z "$1" ]; then
  echo "usage: sudo ./setup_client.sh <assigned_tun_ip> [server_public_ip]"
  exit 1
fi
CLIENT_IP="$1"
SERVER_PUBLIC_IP="$2"

ip addr add "${CLIENT_IP}/24" dev tun0
ip link set tun0 up

if [ -n "$SERVER_PUBLIC_IP" ]; then
  ORIGINAL_GATEWAY=$(ip route | awk '/^default/ {print $3; exit}')
  if [ -z "$ORIGINAL_GATEWAY" ]; then
    echo "Couldn't find your current default gateway - aborting full-tunnel setup" >&2
    exit 1
  fi

  echo "Pinning a route to the VPN server itself via your ORIGINAL gateway"
  echo "first (so the encrypted tunnel traffic doesn't try to route through"
  echo "itself once we replace the default route)..."
  ip route add "${SERVER_PUBLIC_IP}/32" via "$ORIGINAL_GATEWAY"

  echo "Replacing default route with the tunnel..."
  ip route add default dev tun0

  echo "Full tunnel active. All traffic now goes through tun0."
  echo "If you're connected over SSH and just lost the connection, this is"
  echo "the classic VPN gotcha - reboot/console in and skip the second arg"
  echo "next time to stay in split-tunnel mode."
else
  echo "tun0 configured with $CLIENT_IP. Default route untouched (split tunnel)."
  echo "Only traffic you explicitly route via tun0 will use the VPN."
fi
