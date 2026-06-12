# Imports the `sniff` function from the Scapy library which is used for capturing network packets.
from scapy.all import sniff
from collections import Counter
import csv


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

        # Store data in a dictionary
        packet_info = {
            "source": source_ip,
            "destination": dest_ip,
            "protocol": protocol
        }
        # Appends the packet information to the list of captured packets
        packets.append(packet_info)
        # Lists the captured packet info in real time
        print("Captured Packet:")
        print(packet_info)
        print("-" * 30)


# Function to start sniffing
def start_sniffer():
    print("Starting packet capture...\n")
    
    # Iteration happens automatically as packets come in
    while True:
        try:
            num_packets = int(input("Enter the number of packets to capture: "))
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    sniff(prn=process_packet, count=num_packets)

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

#Counts packet["source"] values.
#Counts packet["destination"] values.
#Prints the top 5 of each using Counter(...).most_common(5).
def display_top_ips():
    source_ips = []
    destination_ips = []

    for packet in packets:
        source_ips.append(packet["source"])
        destination_ips.append(packet["destination"])

    top_sources = Counter(source_ips).most_common(5)
    top_destinations = Counter(destination_ips).most_common(5)

    print("\n=== Top Source IPs ===")
    for ip, count in top_sources:
        print(ip, ":", count, "packets")

    print("\n=== Top Destination IPs ===")
    for ip, count in top_destinations:
        print(ip, ":", count, "packets")

def export_to_csv():
    while True:
        choice = input("\nDo you want to export the captured packets to a CSV file? (y/n): ").lower()
        if choice == 'y':
            with open('captured_packets.csv', 'w', newline='') as csvfile:
                fieldnames = ['source', 'destination', 'protocol']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                writer.writerows(packets)
            print("Packets exported to captured_packets.csv")
            break
        elif choice == 'n':
            print("Export skipped.")
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")
    

# Main program to run the sniffer and display results
def main():
    print("=== Packet Sniffer Program ===")
    start_sniffer()
    display_packets()
    display_protocol_summary()
    display_top_ips()
    export_to_csv()

# Run program
main()
