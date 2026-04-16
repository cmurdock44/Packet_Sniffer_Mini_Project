from scapy.all import sniff

packets = []

def process_packet(packet):
    if packet.haslayer("IP"):
        source_ip = packet["IP"].src
        dest_ip = packet["IP"].dst
        protocol_num = packet["IP"].proto

        if protocol_num == 6:
            protocol = "TCP"
        elif protocol_num == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        packet_info = {
            "source": source_ip,
            "destination": dest_ip,
            "protocol": protocol
        }
        packets.append(packet_info)
        print("Captured Packet:")
        print(packet_info)
        print("-" * 30)

def start_sniffer():
    print("Starting packet capture...\n")
    
    while True:
        try:
            num_packets = int(input("Enter the number of packets to capture: "))
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    sniff(prn=process_packet, count=num_packets)

    print("\nSniffing complete.")


def display_packets():
    print("\nStored Packets:")
    
    for packet in packets:
        print(packet)

def display_protocol_summary():
    tcp_count = 0
    udp_count = 0
    other_count = 0

    for packet in packets:
        if packet["protocol"] == "TCP":
            tcp_count += 1
        elif packet["protocol"] == "UDP":
            udp_count += 1
        else:
            other_count += 1

    print("\n=== Packet Summary ===")
    print("TCP packets:", tcp_count)
    print("UDP packets:", udp_count)
    print("Other packets:", other_count)


def main():
    print("=== Packet Sniffer Program ===")
    start_sniffer()
    display_packets()
    display_protocol_summary()


main()