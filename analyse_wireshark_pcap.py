import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sys import argv, exit
from scapy.all import *

if len(argv) != 4 :
    exit("Please pass case, pcap file and destination website as arguments")

case = argv[1]
pcap_file = argv[2]
dest_web = argv[3]

# print(case, pcap_file, dest_web)

# Replace "capture.pcap" with the name of your pcap file
packets = rdpcap(pcap_file)



def get_ip_address_dest_web(packets):
    for pkt in packets:
        # Check if the packet is a DNS query packet for www.google.com
        if DNSQR in pkt and pkt[DNSQR].qname.decode().find(dest_web) != -1:
            # Extract the IP address from the DNS response packet
            if DNSRR in pkt and pkt[DNSRR].type == 1 and pkt[DNSRR].rrname.decode().find(dest_web) != -1:
                return(pkt[DNSRR].rdata)


if case== "A" or  case == "ALL":
    # # Initialize variables to hold gateway IP and MAC addresses
    gateway_ip = None
    gateway_mac = None

    for pkt in packets:
        # Check if the packet has an ARP layer and is an ARP reply
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            # Check if the ARP reply is from the gateway IP
            if pkt[ARP].psrc == gateway_ip:
                gateway_mac = pkt[ARP].hwsrc
                break
            # Check if the gateway IP is not set yet and set it to the first ARP reply
            elif gateway_ip is None:
                gateway_ip = pkt[ARP].psrc
                gateway_mac = pkt[ARP].hwsrc

    # Print the gateway IP and MAC addresses
    print("CASE A:")
    print("IPAddr: ", gateway_ip)
    print("MACAddr: ", gateway_mac)


if case == "B" or case == "ALL" : 

    ip_address = get_ip_address_dest_web(packets)

    print("CASE B:")
    print("IPAddr-DEST: ",ip_address)



if case == "C" or case == "ALL" : 

    connections = []
    SA_conn = []
    A_conn = []

    ip_address = get_ip_address_dest_web(packets)
            
    # Loop through each packet in the pcap file
    for pkt in packets:
        connection = []
        con_dict = {}

        if pkt.haslayer(TCP):
            
            # Check if the packet is a TCP SYN packet
            if pkt[TCP].flags == 'S' and pkt.haslayer(IP) and pkt[IP].dst == ip_address:

                con_dict["src"]= pkt[IP].src
                con_dict["dst"]= pkt[IP].dst
                con_dict["sport"]= pkt[IP].sport
                con_dict["dport"] = pkt[IP].dport
                con_dict["syn"]= 1
                con_dict["ack"]= 0
                con_dict["seqno"] = pkt[TCP].seq
                con_dict["SA_flag"] = 0
                con_dict["A_flag"] = 0

                connection.append(con_dict)
                connections.append(connection)


            elif pkt[TCP].flags == 'SA' and pkt.haslayer(IP) and pkt[IP].src == ip_address:

                con_dict.clear()

                con_dict["src"]= pkt[IP].src
                con_dict["dst"]= pkt[IP].dst
                con_dict["sport"]= pkt[IP].sport
                con_dict["dport"] = pkt[IP].dport
                con_dict["syn"]= 1
                con_dict["ack"]= 1
                con_dict["ackno"] = pkt[TCP].ack

                SA_conn.append(con_dict)

        
            elif pkt[TCP].flags == 'A' and pkt.haslayer(IP) and pkt[IP].dst == ip_address:

                con_dict.clear()

                con_dict["src"]= pkt[IP].src
                con_dict["dst"]= pkt[IP].dst
                con_dict["sport"]= pkt[IP].sport
                con_dict["dport"] = pkt[IP].dport
                con_dict["syn"]= 0
                con_dict["ack"]= 1
                con_dict["seqno"] = pkt[TCP].seq

                A_conn.append(con_dict)
                

    for pkt in range(0, len(SA_conn)):
        for c in range(0, len(connections)):
            if connections[c][0]['sport'] == SA_conn[pkt]['dport'] and connections[c][0]['seqno']+1 == SA_conn[pkt]["ackno"] and connections[c][0]['SA_flag'] == 0:
                connections[c][0]['SA_flag'] = 1
                connections[c].append(SA_conn[pkt])



    for pkt in range(0, len(A_conn)):
        for c in range(0, len(connections)):
            if connections[c][0]['sport'] == A_conn[pkt]["sport"] and connections[c][0]['seqno'] + 1 == A_conn[pkt]["seqno"] and connections[c][0]['A_flag'] == 0:
                connections[c][0]['A_flag'] = 1
                connections[c].append(A_conn[pkt])


    print("CASE C:")
    for co in range(0, 1):
        if(len(connections[co]) == 3):
            print("IPAddr-SRC: ",connections[co][0]['src'],"\nIPAddr-DEST: ",connections[co][0]['dst'],"\nPort-SRC: ",connections[co][0]['dport'], "\nSYN: ",connections[co][0]['syn'], "\nACK: ",connections[co][0]['ack'])
            print("IPAddr-SRC: ",connections[co][1]['src'],"\nIPAddr-DEST: ",connections[co][1]['dst'],"\nPort-SRC: ",connections[co][1]['sport'], "\nSYN: ",connections[co][1]['syn'], "\nACK: ",connections[co][1]['ack'])
            print("IPAddr-SRC: ",connections[co][2]['src'],"\nIPAddr-DEST: ",connections[co][2]['dst'],"\nPort-SRC: ",connections[co][2]['dport'], "\nSYN: ",connections[co][2]['syn'], "\nACK: ",connections[co][2]['ack'])






