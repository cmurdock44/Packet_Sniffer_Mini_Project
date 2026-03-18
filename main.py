# Imports the `sniff` function from the Scapy library which is used for capturing network packets.
from scapy.all import sniff

# Creates an empty list that stores packets
packets = []

# Function to process each individual packet, runs every time a packet is captured
def process_packet(packet):
    # Checks if the packet has an IP layer, and if so, takes source and destination IP addresses and protocol information
    if packet.haslayer("IP"):
        source_ip = packet["IP"].src
        dest_ip = packet["IP"].dst
        # tells what type of protocol is being used (TCP, UDP, etc.)
        protocol_num = packet["IP"].proto

        # Converts protocol number to readable name
        # Starting with 6 for TCP and 17 for UDP, otherwise it is categorized as "Other"
        if protocol_num == 6:
            protocol = "TCP"
        elif protocol_num == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        # Store data in a dictionaryc
        packet_info = {
            "source": source_ip,
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
    
    # Loops through the list of captured packets and prints each one
    for packet in packets:
        print(packet)

# Function to display a summary of protocols used in captured packets
def display_protocol_summary():
    tcp_count = 0
    udp_count = 0
    other_count = 0

    # Loop through all packets
    for packet in packets:
        # Selection to categorize
        if packet["protocol"] == "TCP":
            tcp_count += 1
        elif packet["protocol"] == "UDP":
            udp_count += 1
        else:
            other_count += 1

    # Display results
    print("\n=== Packet Summary ===")
    print("TCP packets:", tcp_count)
    print("UDP packets:", udp_count)
    print("Other packets:", other_count)


# Main program to run the sniffer and display results
def main():
    print("=== Packet Sniffer Program ===")
    start_sniffer()
    display_packets()
    display_protocol_summary()


# Run program
main()