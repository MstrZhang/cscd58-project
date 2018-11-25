import csv
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

    protocols = {}
    tcp = []
    udp = []
    ip = []

    # collect all packet lengths
    for no, time, source, destination, protocol, length, info in data:
        if not protocol in protocols:
            protocols[protocol] = int(length)
        else:
            protocols[protocol] += int(length)

        # collect TCP lengths
        if protocol == 'TCP':
            tcp.append(int(length))
        # collect UDP lengths
        elif protocol == 'UDP':
            udp.append(int(length))

    # collect values
    all_size = [x for x in protocols.values()]

    # debug
    # print(all_size)
    # print(tcp)
    # print(udp)

    ######################################################################

    # plot all packets cdf
    # sorted_list = np.sort(all_size)
    # p = 1. * np.arange(len(all_size)) / (len(all_size) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('all packets')
    # plt.show()

    # plot tcp packets cdf
    sorted_list = np.sort(tcp)
    p = 1. * np.arange(len(tcp)) / (len(tcp) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('tcp packets')
    plt.show()

    # plot udp packets cdf
    # sorted_list = np.sort(udp)
    # p = 1. * np.arange(len(udp)) / (len(udp) - 1)
    # plt.plot(sorted_list, p)
    # plt.xscale('log')
    # plt.title('udp packets')
    # plt.show()