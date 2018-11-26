# cdf function source
# (https://unix.stackexchange.com/questions/314374/how-to-plot-a-cdf-from-array-using-matplotlib-python)

import csv
import numpy as np
from pylab import *
import matplotlib.pyplot as plt

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark -- tcp and ip header lengths specifically extracted from wireshark)
    with open('../raw/packet_size_dump.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    # full packet size
    all_size = []
    tcp = []
    udp = []
    ip = []
    non_ip = []

    # header size
    tcp_header = []
    udp_header = []
    ip_header = []

    # collect all packet lengths
    for no, time, source, destination, protocol, length, info, tcp_payload, ip_payload in data:

        # collect all lengths
        all_size.append(int(length))
        # collect TCP lengths
        if protocol == 'TCP':
            tcp.append(int(length))
            tcp_header.append(int(length) - int(tcp_payload))
        # collect UDP lengths
        elif protocol == 'UDP':
            udp.append(int(length))
            udp_header.append(8) # udp headers are always 8 bytes
        # collect IP lengths
        elif protocol == 'IPv4':
            ip.append(int(length))
            ip_header.append(int(length) - int(ip_payload))
        # collect non-IP lengths:
        elif protocol != 'IPv4':
            non_ip.append(int(length))

    ######################################################################
    # plot cdfs
    ######################################################################

    # plot all packets cdf
    plt.figure(1)
    sorted_list = np.sort(all_size)
    p = 1. * np.arange(len(all_size)) / (len(all_size) - 1)
    plt.plot(sorted_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Packet Sizes for All Packets')

    # plot tcp packets cdf
    plt.figure(2)
    tcp_list = np.sort(tcp)
    p = 1. * np.arange(len(tcp)) / (len(tcp) - 1)
    plt.plot(tcp_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Packet Sizes for TCP Packets')

    # plot udp packets cdf
    plt.figure(3)
    udp_list = np.sort(udp)
    p = 1. * np.arange(len(udp)) / (len(udp) - 1)
    plt.plot(udp_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Packet Sizes for UDP Packets')

    # plot ip packets cdf
    plt.figure(4)
    sorted_list = np.sort(ip)
    p = 1. * np.arange(len(ip)) / (len(ip) - 1)
    plt.plot(sorted_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Packet Sizes for IP Packets')

    # plot non-ip packets cdf
    plt.figure(5)
    sorted_list = np.sort(non_ip)
    p = 1. * np.arange(len(non_ip)) / (len(non_ip) - 1)
    plt.plot(sorted_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Packet Sizes for Non-IP Packets')

    ######################################################################
    # plot headers cdf
    ######################################################################

    # plot tcp header cdf
    plt.figure(6)
    tcp_header_list = np.sort(tcp_header)
    p = 1. * np.arange(len(tcp_header)) / (len(tcp_header) - 1)
    plt.plot(tcp_header_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Header Sizes for TCP Packets')

    # plot udp header cdf
    plt.figure(7)
    udp_header_list = np.sort(udp_header)
    p = 1. * np.arange(len(udp_header)) / (len(udp_header) - 1)
    plt.plot(udp_header_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Header Sizes for UDP Packets')

    # plot ip header cdf
    plt.figure(8)
    ip_header_list = np.sort(ip_header)
    p = 1. * np.arange(len(ip_header)) / (len(ip_header) - 1)
    plt.plot(ip_header_list, p)
    plt.xlabel('bytes')
    plt.title('CDF of Header Sizes for IP Packets')


    # show figures
    plt.show()