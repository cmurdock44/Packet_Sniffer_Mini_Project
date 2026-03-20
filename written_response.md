## Program Purpose
This program was developed in Visual Studio Code (VS Code) using Python. Its purpose is to capture and analyze basic network traffic on a computer. The program collects a small number of packets and extracts important information such as the source IP address, destination IP address, and the type of protocol used (TCP, UDP, or Other).

The program stores this information in a list and then displays both the individual packets and a summary of how many packets belong to each protocol type. This helps users better understand how data is being transmitted across a network.

## Function by function explanation
process_packet(packet):
This function is responsible for analyzing each packet as it is captured. It first checks if the packet contains an IP layer. If it does, it then extracts the source and destination IP as well as the protocol number. The protocol number is what determines the specific protocol, with TCP being linked to 6, and UDP to 17. A dictionary is created to store the information in an organized way that allows for data abstraction. The dictionary is added to the list of packets

startsniffer():
This funtction first prints a message that the packet capture has begun, then uses the sniff function from the Scapy library to capture ten packets. For each packet that is captured, the process_packet() function is automatically called. After all ten packets are captured, the function prints a message marking the end of the function.

display_packets():
This funcition first prints a header, then uses a loop to go through each packet stored in the list and print each one.

display_protocol_summary()
This function determines what protocol type each packet belong to. It first sets a counter for TCP, UDP, and other, then loops through the packets and determines the total amount for each type of protocol.

main()
This function prints the title of the program then calls all of the functions in the necessary order to run the program proprerly. This function keeps the program organized instead of calling each function infividually after each one is written.