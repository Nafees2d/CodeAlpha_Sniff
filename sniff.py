from scapy.all import sniff, IP, TCP, UDP, Raw
import csv
from datetime import datetime

# CSV file setup
csv_file = "captured_packets.csv"
csv_header = ["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Payload"]

# Create CSV file with header
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(csv_header)

def packet_callback(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = dst_ip = proto_name = src_port = dst_port = payload_data = ""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(packet[IP].proto, str(packet[IP].proto))

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if Raw in packet:
            try:
                payload_data = packet[Raw].load.decode(errors="ignore")[:50]  # limit size
            except:
                payload_data = "(Binary Data)"

        # Save to CSV
        with open(csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, proto_name, src_port, dst_port, payload_data])

        # Display in terminal
        print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {proto_name} | {payload_data}")

print(f"Starting enhanced packet capture... Saving to {csv_file} (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)
