from scapy.all import sniff

# List that stores packets
packets = []

# Function to process each individual packet
def process_packet(packet):
    # Selection (if statement)
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dest_ip = packet["IP"].dst
        protocol_num = packet["IP"].proto

        # Convert protocol number to readable name
        if protocol_num == 6:
            protocol = "TCP"
        elif protocol_num == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        # Store data in a dictionaryc
        packet_info = {
            "source": src_ip,
            "destination": dest_ip,
            "protocol": protocol
        }

        packets.append(packet_info)

        print("Captured Packet:")
        print(packet_info)
        print("-" * 30)


# Function to start sniffing
def start_sniffer():
    print("Starting packet capture...\n")
    
    # Iteration happens automatically as packets come in
    sniff(prn=process_packet, count=10)

    print("\nSniffing complete.")


# Function to display stored packets
def display_packets():
    print("\nStored Packets:")
    
    # Iteration (loop)
    for packet in packets:
        print(packet)


# Main program (sequence)
def main():
    print("=== Packet Sniffer Program ===")
    start_sniffer()
    display_packets()


# Run program
main()