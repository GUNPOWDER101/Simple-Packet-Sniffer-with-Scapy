from scapy.all import sniff, TCP, UDP, IP
from datetime import datetime
import sys

# Optional: Pretty colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class DummyColor: RED = GREEN = CYAN = YELLOW = RESET = ''
    Fore = Style = DummyColor()

log_file = "packets_log.txt"
packet_filter = "tcp or udp"

print(f"{Fore.CYAN}🚀 Starting packet sniffing...")
print(f"{Fore.YELLOW}📌 Filter      : {packet_filter}")
print(f"{Fore.YELLOW}📁 Log File    : {log_file}")
print(f"{Fore.YELLOW}🔢 Packet Count: Unlimited")
print(f"{Fore.RED}⏹️  Press Ctrl+C to stop...\n")

def log_packet(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
        src = f"{pkt[IP].src}:{pkt.sport if proto in ['TCP','UDP'] else ''}"
        dst = f"{pkt[IP].dst}:{pkt.dport if proto in ['TCP','UDP'] else ''}"
        flags = pkt.sprintf("%TCP.flags%") if TCP in pkt else "-"
        payload = bytes(pkt[proto].payload)[:40].hex() if proto in ['TCP', 'UDP'] else ""

        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_line = f"{timestamp} {proto} | {src} -> {dst} | Flags: {flags} | Payload: {payload}"

        # Print to terminal
        print(f"{Fore.GREEN}{log_line}")

        # Save to file
        with open(log_file, "a") as f:
            f.write(log_line + "\n")

try:
    sniff(filter=packet_filter, prn=log_packet, store=False)
except KeyboardInterrupt:
    print(f"\n{Fore.CYAN}📴 Sniffing stopped by user. Log saved to {log_file}")
    sys.exit()

