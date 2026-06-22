# Toy VPN - built from scratch

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Platform-Linux-orange.svg" alt="Linux">
  <img src="https://img.shields.io/badge/Crypto-X25519%20%2B%20AES--256--GCM-green.svg" alt="Crypto">
</p>

A minimal but real IP-layer VPN: a TUN virtual interface for capturing
raw IP packets, an X25519 Diffie-Hellman handshake for a fresh session
key, and AES-256-GCM to encrypt every packet. No OpenVPN, no
WireGuard, no third-party VPN library - every layer here is written
out so you can see exactly what a VPN does to a packet.

## About this project

This project came out of wanting to understand exactly what a VPN
does to a packet, rather than just running a pre-configured service.
It involved TUN interfaces, raw socket handling, a custom
Diffie-Hellman handshake, authenticated encryption, and the
underlying Linux routing/NAT layer.

**Skills demonstrated:** low-level Linux networking (TUN/TAP, IP
forwarding, NAT/iptables), applied cryptography (ECDH key exchange,
AEAD encryption, key derivation), socket programming, and writing
infrastructure code that handles real-world network routing
constraints.

[LinkedIn](#) | [GitHub](#) | [Portfolio](#)
*(Feel free to update these placeholders with your links)*

---

## How it works

```
  Your apps                                            Real internet
      |                                                      ^
      v (OS routes traffic here)                             |
  +--------+    read/write raw IP    +---------+        +---------+
  |  tun0  |<------------------------>|client.py|        |server.py|
  |(client)|                          +----+----+        +----+----+
  +--------+                               |    encrypt(AES-256-GCM) |
                                            |    X25519 handshake     |
                                            +------UDP packets--------+
                                                                       |
                                                              +--------+
                                                              |  tun0  |
                                                              |(server)|
                                                              +----+---+
                                                                   |  kernel IP forward + NAT
                                                                   v
                                                            real internet
```

1. **Handshake.** Client and server each generate a throwaway X25519
   keypair, swap public keys over plain UDP, and both independently
   compute the same AES-256 key via ECDH + HKDF. The server also hands
   the client a private IP (10.8.0.x) in its reply.
2. **Tunneling.** Whatever the OS sends to the client's `tun0` gets
   read by `client.py`, encrypted, and sent as a UDP packet to the
   server. The server decrypts it and writes it to its own `tun0`.
3. **Routing.** From there it's normal Linux networking: IP
   forwarding + NAT (`iptables MASQUERADE`) sends it out to the real
   destination. The reply comes back, the kernel routes it to
   `tun0`, the server re-encrypts it, and sends it back to the
   right client.

## Files Included

* **`tun.py`**: Opens `/dev/net/tun`, wraps read/write of raw IP packets.
* **`crypto_utils.py`**: X25519 handshake, HKDF key derivation, AES-256-GCM session cipher with direction-separated nonces.
* **`server.py`**: Listens for clients, decrypts onto `tun0`, re-encrypts replies back out.
* **`client.py`**: Handshakes, tunnels local traffic to/from the server.
* **`setup_server.sh`**: One-time root setup: TUN IP, IP forwarding, NAT rules.
* **`setup_client.sh`**: One-time root setup: TUN IP, optional full-tunnel routing.

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
```

**On the client:**
```bash
sudo python3 client.py <server_public_ip>
# it prints something like:
# [client] next, run: sudo ./setup_client.sh 10.8.0.2 <server_public_ip>
sudo ./setup_client.sh 10.8.0.2 <server_public_ip>
```

Leave off the second argument to `setup_client.sh` to stay in
split-tunnel mode, where only traffic explicitly routed via `tun0`
uses the VPN, instead of redirecting the full default route.

**Note:** if you're testing this over SSH on a remote VM, full-tunnel
mode replaces your default route, which can disconnect your SSH
session if it's not handled carefully. `setup_client.sh` pins a route
to the server's own IP via your original gateway first specifically
to avoid this, but keep a console/serial connection or a second SSH
session open the first time you try it, just in case.

## Security Model

**Real:**
* Forward secrecy, since a fresh ECDH keypair is generated every session
* Authenticated encryption via AES-GCM, so tampered packets are rejected rather than silently corrupted
* Direction-separated nonces, so client-to-server and server-to-client traffic can never collide on (key, nonce) even though both sides share one session key
* Basic anti-replay protection using a monotonic counter per direction

**Simplified, compared to production VPNs like WireGuard or OpenVPN:**
* **No identity authentication.** The handshake is unauthenticated Diffie-Hellman, similar to SSH before a host key is verified. An active man-in-the-middle on the first connection could impersonate either side.
* **No key rotation.** A single session key is used for the whole connection.
* **No replay window.** Anti-replay requires strictly increasing counters, so out-of-order UDP delivery just drops packets instead of tolerating a small window.
* **No MTU or fragmentation handling.** Packets larger than the tunnel's effective MTU will silently fail.

None of that is hidden, it's exactly the kind of "here's what I built
vs. what production-grade would add" analysis that's good to include
in a portfolio writeup.
