import argparse
import json
import time
from collections import defaultdict
from scapy.all import sniff, IP, UDP, TCP, Raw

alerts = []
packet_history = defaultdict(list) # full packet history with timestamps
TRUSTED_SUBNET = "172.18.0." # subnet of the vulhub environment, outside requests are probably threats
VULHUB_INTERFACE = "br-a8377548e74c" # interface where 172.18.0.1 is

def log_alert(alert_type, src_ip, details):
    alert = {
        "timestamp": time.time(),
        "type": alert_type,
        "source_ip": src_ip,
        "details": details
    }
    alerts.append(alert)
    print(f"\n[!!!] {alert_type}")
    print(f"[*] Source: {src_ip} | Details: {details}")

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # ==========================================
    # RULE 1, 2 & 3: Analisi UDP 631 (Discovery)
    # ==========================================
    #check if is on port 631...
    if packet.haslayer(UDP) and packet[UDP].dport == 631 and packet.haslayer(Raw):
        raw_payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # looking for flooding attempt
        current_time = time.time()
        packet_history[src_ip].append(current_time)
        # keep only last 10s packets
        packet_history[src_ip] = [t for t in packet_history[src_ip] if current_time - t < 10]
        if len(packet_history[src_ip]) > 5: # trying with 5 packets first
            log_alert("ABNORMAL_DISCOVERY_RATE", src_ip, "Possible flooding detected")
            
        # packets must follow the same structure, check
        fields = raw_payload.split(' ')
        if len(fields) != 5:
            log_alert("MALFORMED_PACKET", src_ip, f"Incorrect number of fields. Raw: {raw_payload.strip()}")
            return
            
        #checking URI for unauthorized advertisements
        printer_uri = fields[2]
        if "http://" in printer_uri or "ipp://" in printer_uri:
            if TRUSTED_SUBNET not in printer_uri:
                log_alert("UNAUTHORIZED_ADVERTISEMENT", src_ip, f"Suspicious URI detected: {printer_uri}")

    # looking for suspicious IPP connections
    elif packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "POST /printers/" in payload and "Content-Type: application/ipp" in payload:
            if TRUSTED_SUBNET not in dst_ip:
                log_alert("SUSPICIOUS_IPP_CONNECTION", src_ip, f"Suspicious IPP connection towards {dst_ip}")

def main():
    parser = argparse.ArgumentParser(description="CUPS IDS Detector")
    parser.add_argument("-r", "--read", help="File PCAP da analizzare offline")
    parser.add_argument("-o", "--output", default="cups_alerts.json", help="File export (JSON)")
    args = parser.parse_args()

    try:
        if args.read:
            print(f"[*] Offline analysis: {args.read}...")
            sniff(offline=args.read, prn=analyze_packet, store=0)
        else:
            print("[*] Starting LIVE monitoring (press Ctrl+C to stop)...")
            sniff(iface=VULHUB_INTERFACE, prn=analyze_packet, store=0)
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring interrupted by user.")
        
    finally:
        # Export results
        if alerts:
            with open(args.output, "w") as f:
                json.dump(alerts, f, indent=4)
            print(f"[+] Saved {len(alerts)} alerts to file {args.output}")
        else:
            print("[-] No alerts detected. No export needed.")


main()
