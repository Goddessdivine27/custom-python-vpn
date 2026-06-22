# custom-python-vpn
A minimal, fully functional IP-layer VPN engineered from scratch in Python

## About this project

This project came out of wanting to deeply understand what a VPN actually *does* to a packet at a low level, rather than just running an off-the-shelf config file. It implements virtual interfaces, a real Diffie-Hellman handshake, authenticated encryption, and the underlying Linux routing/NAT mechanics from scratch.

**Skills demonstrated:** low-level Linux networking (TUN/TAP, IP forwarding, NAT/iptables), applied cryptography (ECDH key exchange, AEAD encryption, key derivation), socket programming, and writing infrastructure code that's honest about its own limitations.

---

## Requirements
* Linux on both ends (uses `/dev/net/tun` directly), root or `CAP_NET_ADMIN`
* Python 3.8+, `pip install cryptography`
* A UDP port open between client and server (default 51900)

## Running It

**On the server** (a cloud VM works well):
```bash
sudo python3 server.py
# in another shell, once:
sudo ./setup_server.sh
