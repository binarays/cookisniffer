import socket
import struct
import sys

# Protocol name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def main():
    host = socket.gethostbyname(socket.gethostname())

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("[!] Run this script as Administrator.")
        sys.exit(1)

    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"\n[*] Sniffing on {host}...\n")

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)

            # Step 1: Extract IP header
            ip_info = parse_ip_header(raw_data)
            if not ip_info:
                continue

            version, header_length, ttl, proto, src, target = ip_info

            # Step 2: Get protocol name
            proto_name = PROTOCOL_MAP.get(proto, f"Other ({proto})")

            print(f"\n[IP] {src} → {target} | Protocol: {proto_name} | TTL: {ttl}")

            # Step 3: Extract transport-layer payload
            ip_payload = raw_data[header_length:]

            if proto == 6:  # TCP
                parse_tcp(ip_payload)
            elif proto == 17:  # UDP
                parse_udp(ip_payload)
            elif proto == 1:  # ICMP
                parse_icmp(ip_payload)
            else:
                print("[*] Unknown or unsupported protocol")

    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)

# Parse IP header
def parse_ip_header(data):
    try:
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_header_length = ip_header[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 0xF) * 4
        ttl = ip_header[5]
        proto = ip_header[6]
        src = socket.inet_ntoa(ip_header[8])
        dst = socket.inet_ntoa(ip_header[9])
        return version, header_length, ttl, proto, src, dst
    except:
        return None

# Parse TCP header and payload
def parse_tcp(data):
    if len(data) < 20:
        return
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    offset = (tcp_header[4] >> 4) * 4
    payload = data[offset:]

    print(f"[TCP] Src Port: {src_port}, Dst Port: {dst_port}")
    print_payload(payload)

# Parse UDP header and payload
def parse_udp(data):
    if len(data) < 8:
        return
    udp_header = struct.unpack('!HHHH', data[:8])
    src_port = udp_header[0]
    dst_port = udp_header[1]
    payload = data[8:]

    print(f"[UDP] Src Port: {src_port}, Dst Port: {dst_port}")
    print_payload(payload)

# Parse ICMP header and payload
def parse_icmp(data):
    if len(data) < 4:
        return
    icmp_header = struct.unpack('!BBH', data[:4])
    icmp_type = icmp_header[0]
    code = icmp_header[1]
    payload = data[4:]

    print(f"[ICMP] Type: {icmp_type}, Code: {code}")
    print_payload(payload)

# Pretty print payload
def print_payload(data):
    if data:
        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:64])
        print(f"[Data] {printable}")
    else:
        print("[Data] (No payload)")

if __name__ == "__main__":
    main()
