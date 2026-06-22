"""
tun.py - minimal Linux TUN interface wrapper.

A TUN device is a virtual network interface the kernel exposes to
userspace as a file. Whatever the OS routes to this interface, you can
read() as raw IP packets. Whatever you write() to it, the kernel treats
as an inbound IP packet on that interface. This is the foundation every
real VPN (OpenVPN, WireGuard) is built on - they just add encryption
around the read/write.

Requires Linux, the `tun` kernel module loaded, and root (or
CAP_NET_ADMIN) to create the interface.
"""
import fcntl
import struct
import os

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000 # don't prefix packets with 4 bytes of flags/protocol


class TunInterface:
    def __init__(self, name: str = "tun0"):
        self.name = name
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", name.encode("utf-8"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)

    def read(self, size: int = 2048) -> bytes:
        """Blocking read of one raw IP packet from the interface."""
        return os.read(self.fd, size)

    def write(self, packet: bytes) -> int:
        """Inject one raw IP packet into the interface."""
        return os.write(self.fd, packet)

    def close(self):
        os.close(self.fd)
