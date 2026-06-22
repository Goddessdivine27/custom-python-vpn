"""
client.py - toy VPN client.

  1. Creates a TUN interface (tun0) on the client.
  2. Sends a ClientHello (its ephemeral X25519 pubkey) to the server,
     gets back a ServerHello with the server's pubkey + an assigned
     private IP (e.g. 10.8.0.2). Derives the same AES-256-GCM session
     key the server derived.
  3. Reads whatever the OS routes to tun0 (depends on routes set up by
     setup_client.sh), encrypts it, sends it over UDP to the server.
  4. Decrypts whatever comes back over UDP, writes it into tun0 so the
     OS treats it as inbound traffic on that interface.

Run: sudo python3 client.py <server_ip> [server_port]
Then: sudo ./setup_client.sh <assigned_ip> [server_public_ip]
(the assigned IP is printed after handshake)
"""
import os
import socket
import sys
import threading

from tun import TunInterface
from crypto_utils import generate_keypair, pubkey_bytes, load_pubkey, derive_session_key, SessionCipher

MSG_CLIENT_HELLO = 0x01
MSG_SERVER_HELLO = 0x02
MSG_DATA = 0x03


def main():
    if len(sys.argv) < 2:
        print("usage: sudo python3 client.py <server_ip> [server_port]")
        sys.exit(1)
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 51900

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((server_ip, server_port))

    priv, pub = generate_keypair()
    pub_bytes = pubkey_bytes(pub)
    sock.send(bytes([MSG_CLIENT_HELLO]) + pub_bytes)

    reply = sock.recv(65535)
    if not reply or reply[0] != MSG_SERVER_HELLO:
        raise RuntimeError("handshake failed: no/garbled ServerHello")
    server_pub_bytes = reply[1:33]
    assigned_ip = socket.inet_ntoa(reply[33:37])
    server_pub = load_pubkey(server_pub_bytes)

    salt = pub_bytes + server_pub_bytes # client_pub || server_pub, same order as server
    key = derive_session_key(priv, server_pub, salt)
    cipher = SessionCipher(key, is_server=False)

    print(f"[client] handshake complete. Assigned tun IP: {assigned_ip}")
    print(f"[client] next, run: sudo ./setup_client.sh {assigned_ip} {server_ip}")

    tun = TunInterface("tun0")
    last_recv = [-1]

    def tun_loop():
        while True:
            try:
                packet = tun.read(2048)
                encrypted = cipher.encrypt(packet)
                sock.send(bytes([MSG_DATA]) + encrypted)
            except OSError as e:
                print(f"[client] tun_loop fatal error: {e}", flush=True)
                os._exit(1) # daemon thread dying silently would hide this; force the whole process down

    def udp_loop():
        while True:
            try:
                data = sock.recv(65535)
                if not data or data[0] != MSG_DATA:
                    continue
                counter = SessionCipher.counter_of(data[1:])
                if counter <= last_recv[0]:
                    continue
                try:
                    plaintext = cipher.decrypt(data[1:])
                except Exception:
                    continue
                last_recv[0] = counter
                tun.write(plaintext)
            except OSError as e:
                print(f"[client] udp_loop fatal error: {e}", flush=True)
                os._exit(1)

    threading.Thread(target=tun_loop, daemon=True).start()
    threading.Thread(target=udp_loop, daemon=True).start()
    print("[client] tunnel running - Ctrl+C to stop")
    threading.Event().wait()


if __name__ == "__main__":
    main()
