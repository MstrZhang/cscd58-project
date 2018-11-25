######################################################################
#
# cdf function source
# (https://unix.stackexchange.com/questions/314374/how-to-plot-a-cdf-from-array-using-matplotlib-python)
#
######################################################################

import csv
import re
import numpy as np
import matplotlib.pyplot as plt

mapping = {
    'APPLICATION': ['TELNET', 'MySQL', 'SMTP', 'SSH', 'RIP', 'DHCPv6', 'DNS', 'CVSPSERVER', 'LPD', 'Intel ANS probe', 'VNC', 'SSL', 'ISAKMP', 'MDNS', 'MS NLB', 'DSI', 'LLMNR', 'NTP', 'NCS', 'BOOTP', 'SRVLOC'],
    'TRANSPORT': ['TCP', 'UDP', 'NBSS', 'Syslog'],
    'NETWORK': ['IPX', 'IPv4', 'IGMPv0', 'ICMPv6', 'ICMP', 'OSPF', 'PIMv0', 'IGRP', 'VRRP', 'RSL', 'ESP', 'GRE'],
    'LINK': ['ARP', 'CDP', 'LLC', 'PPTP'],
    'OTHER': ['NBNS', '0x200e', 'Gryphon', 'NBDS', 'NCP', 'UDPENCAP']
}

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('../raw/univ1_trace.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    # full packet size
    protocols = {}
    tcp = []
    udp = []
    ip = []
    non_ip = []

    # header size
    tcp_header = []
    udp_header = []
    ip_header = []

    # collect all packet lengths
    for no, time, source, destination, protocol, length, info in data:
        if not protocol in protocols:
            protocols[protocol] = int(length)
        else:
            protocols[protocol] += int(length)

        # collect TCP lengths
        if protocol == 'TCP':
            tcp.append(int(length))
            match = re.search(r'Len=(\d*)', info)
            if match:
                tcp_header.append(int(match.group(0).split('=')[1]))
        # collect UDP lengths
        elif protocol == 'UDP':
            udp.append(int(length))
            match = re.search(r'Len=(\d*)', info)
            if match:
                udp_header.append(int(match.group(0).split('=')[1]))
        # collect IP lengths
        elif protocol == 'IPv4':
            ip.append(int(length))
            match = re.search(r'Len=(\d*)', info)
            if match:
                ip_header.append(int(match.group(0).split('=')[1]))
        # collect non-IP lengths:
        else:
            non_ip.append(int(length))

    # collect values
    all_size = [x for x in protocols.values()]

    ######################################################################
    # plot all packets cdf
    ######################################################################

    # plot all packets cdf
    # sorted_list = np.sort(all_size)
    # p = 1. * np.arange(len(all_size)) / (len(all_size) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('all packets')
    # plt.show()

    # plot tcp packets cdf
    # sorted_list = np.sort(tcp)
    # p = 1. * np.arange(len(tcp)) / (len(tcp) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('tcp packets')
    # plt.show()

    # plot udp packets cdf
    # sorted_list = np.sort(udp)
    # p = 1. * np.arange(len(udp)) / (len(udp) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('udp packets')
    # plt.show()

    # plot ip packets cdf
    # sorted_list = np.sort(ip)
    # p = 1. * np.arange(len(ip)) / (len(ip) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('ip packets')
    # plt.show()

    # plot non-ip packets cdf
    # sorted_list = np.sort(non_ip)
    # p = 1. * np.arange(len(non_ip)) / (len(non_ip) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('non ip packets')
    # plt.show()

    ######################################################################
    # plot headers cdf
    ######################################################################

    # plot tcp header cdf
    # sorted_list = np.sort(tcp_header)
    # p = 1. * np.arange(len(tcp_header)) / (len(tcp_header) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('tcp headers')
    # plt.show()

    # plot udp header cdf
    # sorted_list = np.sort(udp_header)
    # p = 1. * np.arange(len(udp_header)) / (len(udp_header) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('udp headers')
    # plt.show()

    # plot ip header cdf
    print(ip_header)
    sorted_list = np.sort(ip_header)
    p = 1. * np.arange(len(ip_header)) / (len(ip_header) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('ip headers')
    plt.show()