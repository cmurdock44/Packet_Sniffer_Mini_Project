## Program Purpose
This program was developed in Visual Studio Code (VS Code) using Python. Its purpose is to capture and analyze basic network traffic on a computer. The program collects a small number of packets and extracts important information such as the source IP address, destination IP address, and the type of protocol used (TCP, UDP, or Other).

The program stores this information in a list and then displays both the individual packets and a summary of how many packets belong to each protocol type. This helps users better understand how data is being transmitted across a network.

## Function by function explanation
The process_packet(packet) function is responsible for analyzing each packet as it is captured. It first checks if the packet contains an IP layer. If it does, it then extracts the source and destination IP as well as the protocol number. The protocol number is what determines the specific protocol, with TCP being linked to 6, and UDP to 17. A dictionary is created to store the information in an organized way that allows for data abstraction. The dictionary is added to the list of packets

Startsniffer():
Display_packets():
display_protocol_summary()
main()