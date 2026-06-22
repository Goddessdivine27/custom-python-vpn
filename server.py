"""
server.py - toy VPN server.

What it does:
  1. Creates a TUN interface (tun0) on the server.
  2. Listens on UDP for clients. New clients do a handshake (ClientHello
     / ServerHello) and get assigned a private IP in 10.8.0.0/24.
  3. Data packets from a client are decrypted and written to tun0. From
     there, the OS's own IP forwarding + NAT rules (set up by
     setup_server.sh) route them out to the real internet, exactly like
     a NAT router would for any LAN client.
  4. Reply packets come back from the internet, the kernel routes them
     to tun0 (because their destination IP is the client's 10.8.0.x
     address), the server reads them off tun0, looks up which client
     owns that IP, encrypts, and sends them back over UDP.

This file deliberately does NOT touch iptables/sysctl itself - that's
one-time root setup, kept in setup_server.sh so the Python process
doesn't need to shell out to manage firewall state.

Run: sudo python3 server.py
Then, once: sudo ./setup_server.sh
"""
import os
import socket
import threading

from tun import TunInterface
from crypto_utils import generate_keypair, pubkey_bytes, load_pubkey, derive_session_key, SessionCipher

MSG_CLIENT_HELLO = 0x01
MSG_SERVER_HELLO = 0x02
MSG_DATA = 0x03

TUN_SUBNET_PREFIX = "10.8.0."
LISTEN_PORT = 51900


def main():
    tun = TunInterface("tun0")
    print("[server] tun0 created. If this is the first run, also do: sudo ./setup_server.sh")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    print(f"[server] listening on UDP :{LISTEN_PORT}")

    server_priv, server_pub = generate_keypair()
    server_pub_bytes = pubkey_bytes(server_pub)

    sessions_by_addr = {} # (ip, port) -> dict(key, cipher, last_recv, tun_ip)
    sessions_by_tun_ip = {} # "10.8.0.2" -> (ip, port)
    next_ip_suffix = [2] # .1 is the server's own tun0 address
    lock = threading.Lock()

    def handle_hello(data, addr):
        client_pub_bytes = data[1:33]
        client_pub = load_pubkey(client_pub_bytes)
        # Same salt order on both ends: client_pub || server_pub
        salt = client_pub_bytes + server_pub_bytes
        key = derive_session_key(server_priv, client_pub, salt)

        with lock:
            tun_ip = f"{TUN_SUBNET_PREFIX}{next_ip_suffix[0]}"
            next_ip_suffix[0] += 1
            sessions_by_addr[addr] = {
                "cipher": SessionCipher(key, is_server=True),
                "last_recv": -1,
                "tun_ip": tun_ip,
            }
            sessions_by_tun_ip[tun_ip] = addr

        reply = bytes([MSG_SERVER_HELLO]) + server_pub_bytes + socket.inet_aton(tun_ip)
        sock.sendto(reply, addr)
        print(f"[server] handshake complete with {addr} -> assigned {tun_ip}")

    def handle_data(data, addr):
        with lock:
            session = sessions_by_addr.get(addr)
        if session is None:
            return # data from an address we never shook hands with; drop

        counter = SessionCipher.counter_of(data[1:])
        if counter <= session["last_recv"]:
            return # replayed or out-of-order; drop
        try:
            plaintext = session["cipher"].decrypt(data[1:])
        except Exception:
            return # auth tag failed -> tampered or wrong key; drop silently

        session["last_recv"] = counter
        tun.write(plaintext)

    def udp_loop():
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                if not data:
                    continue
                msgtype = data[0]
                if msgtype == MSG_CLIENT_HELLO:
                    handle_hello(data, addr)
                elif msgtype == MSG_DATA:
                    handle_data(data, addr)
            except OSError as e:
                print(f"[server] udp_loop fatal error: {e}", flush=True)
                os._exit(1)

    def tun_loop():
        while True:
            try:
                packet = tun.read(2048)
                if len(packet) < 20:
                    continue # shorter than a minimal IPv4 header; ignore
                dst_ip = socket.inet_ntoa(packet[16:20])
                with lock:
                    addr = sessions_by_tun_ip.get(dst_ip)
                    session = sessions_by_addr.get(addr) if addr else None
                if session is None:
                    continue # no connected client owns this destination
                encrypted = session["cipher"].encrypt(packet)
                sock.sendto(bytes([MSG_DATA]) + encrypted, addr)
            except OSError as e:
                print(f"[server] tun_loop fatal error: {e}", flush=True)
                os._exit(1) # daemon thread dying silently would hide this; force the whole process down

    threading.Thread(target=udp_loop, daemon=True).start()
    threading.Thread(target=tun_loop, daemon=True).start()
    print("[server] running - Ctrl+C to stop")
    threading.Event().wait()


if __name__ == "__main__":
    main()
