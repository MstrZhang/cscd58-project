import csv
import numpy as np
import matplotlib.pyplot as plt

mapping = {
    'APPLICATION': ['TELNET', 'MySQL', 'SMTP', 'SSH', 'RIP', 'DHCPv6', 'DNS', 'LPD', 'CVSPSERVER', 'Intel ANS probe', 'VNC', 'SSL', 'ISAKMP', 'MDNS', 'MS NLB', 'DSI', 'LLMNR', 'NTP', 'NCS', 'BOOTP', 'SRVLOC'],
    'TRANSPORT': ['TCP', 'UDP', 'NBSS', 'Syslog'],
    'NETWORK': ['IPX', 'IPv4', 'IGMPv0', 'ICMPv6', 'ICMP', 'OSPF', 'PIMv0', 'IGRP', 'VRRP', 'RSL', 'ESP', 'GRE'],
    'LINK': ['ARP', 'CDP', 'LLC', 'PPTP'],
    'OTHER': ['NBNS', '0x200e', 'Gryphon', 'NBDS', 'NCP', 'UDPENCAP']
}

def ip_to_int(address):
    split_address = address.split('.')
    total = 0
    multiplicator = 256^3
    for item in split_address:
        total += int(item) * multiplicator
        multiplicator = multiplicator / 256
    return total

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('../raw/univ1_trace.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}

    # coarse count of flows
    count = 0
    for no, time, source, destination, protocol, length, info in data[:100]:
        if protocol == "UDP" or protocol == "TCP":
            # Extract the src and dest ports
            split_info = info.split('  >  ')
            if not split_info[0][0].isdigit():
                src_port = split_info[0].split(' ')[-1]
                dest_port = split_info[1].split(' ')[0]
            else:
                src_port = split_info[0]
                dest_port = split_info[1].split(' ')[0]

            # Build a flow identifier from src/dest ips
            ident = ip_to_int(source) + ip_to_int(destination) + int(src_port) + int(dest_port)
            if not ident in flows:
                flows[ident] = {'protocol' : protocol, 'times' : [time]}
            else:
                flows[ident]['times'].append(time)
    
    # Extract the finishing times for each required analysis
    packet_arrival_set = []
    TCP_arrival_set = []
    UDP_arrival_set = []
    for flow in flows:
        for i in range(len(flows[flow]['times']) - 1):
            packet_arrival_set.append(float(flows[flow]['times'][i + 1]) - float(flows[flow]['times'][i]))

            # Filter for TCP or UDP
            if flows[flow]['protocol'] == 'TCP':
                TCP_arrival_set.append(float(flows[flow]['times'][i + 1]) - float(flows[flow]['times'][i]))
            else:
                UDP_arrival_set.append(float(flows[flow]['times'][i + 1]) - float(flows[flow]['times'][i]))

    ######################################################################
    # plot all flows cdf
    ######################################################################

    # plot all flows cdf
    plt.figure(1)
    sorted_list = np.sort(packet_arrival_set)
    p = 1. * np.arange(len(packet_arrival_set)) / (len(packet_arrival_set) - 1)
    plt.plot(sorted_list, p)
    plt.title('all flows')

    # plot tcp packets cdf
    plt.figure(2)
    tcp_list = np.sort(TCP_arrival_set)
    p = 1. * np.arange(len(TCP_arrival_set)) / (len(TCP_arrival_set) - 1)
    plt.plot(tcp_list, p)
    plt.title('tcp flows')

    # plot udp packets cdf
    plt.figure(3)
    udp_list = np.sort(UDP_arrival_set)
    p = 1. * np.arange(len(UDP_arrival_set)) / (len(UDP_arrival_set) - 1)
    plt.plot(udp_list, p)
    plt.title('udp flows')