
import socket
import struct
import sys
import os

# Dictionary for protocol names
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def main():
    # Get local host IP address
    host = socket.gethostbyname(socket.gethostname())

    # Create a raw socket
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("[!] You need to run this script as Administrator.")
        sys.exit(1)

    sniffer.bind((host, 0))

    # Include IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode (Windows only)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"\n[*] Sniffing on {host} (Press Ctrl+C to stop)\n")

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            version, header_length, ttl, proto, src, target = ip_header(raw_data[:20])
            proto_name = PROTOCOL_MAP.get(proto, f"Other ({proto})")

            print(f"[IP] {src} → {target} | Protocol: {proto_name} | TTL: {ttl}")

    except KeyboardInterrupt:
        print("\n[!] Detected Ctrl+C, exiting...")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)

# Unpack IP header
def ip_header(data):
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', data)
    version_header_length = unpacked_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4
    ttl = unpacked_data[5]
    proto = unpacked_data[6]
    src = socket.inet_ntoa(unpacked_data[8])
    target = socket.inet_ntoa(unpacked_data[9])
    return version, header_length, ttl, proto, src, target

if __name__ == "__main__":
    main()
