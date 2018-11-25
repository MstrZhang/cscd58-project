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

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('../raw/univ1_trace.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    # full packet size
    all_size = []
    tcp = []
    udp = []
    ip = []
    non_ip = []

    # header size
    # TODO: header calculation is probably not exactly correct
    tcp_header = []
    udp_header = []
    ip_header = []

    # collect all packet lengths
    for no, time, source, destination, protocol, length, info in data:
        # collect all lengths
        all_size.append(int(length))

        # collect TCP lengths
        if protocol == 'TCP':
            tcp.append(int(length))
            ip.append(int(length))
            match = re.search(r'Len=(\d*)', info)
            if match:
                tcp_header.append(int(match.group(0).split('=')[1]))
                ip_header.append(int(match.group(0).split('=')[1]))
        # collect UDP lengths
        elif protocol == 'UDP':
            udp.append(int(length))
            ip.append(int(length))
            match = re.search(r'Len=(\d*)', info)
            if match:
                udp_header.append(int(match.group(0).split('=')[1]))
                ip_header.append(int(match.group(0).split('=')[1]))
        # collect non-IP lengths:
        else:
            non_ip.append(int(length))


    ######################################################################
    # plot all packets cdf
    ######################################################################

    # plot all packets cdf
    plt.figure(1)
    sorted_list = np.sort(all_size)
    p = 1. * np.arange(len(all_size)) / (len(all_size) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('all packets')

    # plot tcp packets cdf
    plt.figure(2)
    tcp_list = np.sort(tcp)
    p = 1. * np.arange(len(tcp)) / (len(tcp) - 1)
    plt.plot(tcp_list, p)
    plt.xscale('log')
    plt.title('tcp packets')

    # plot udp packets cdf
    plt.figure(3)
    udp_list = np.sort(udp)
    p = 1. * np.arange(len(udp)) / (len(udp) - 1)
    plt.plot(udp_list, p)
    plt.xscale('log')
    plt.title('udp packets')

    # plot ip packets cdf
    plt.figure(4)
    sorted_list = np.sort(ip)
    p = 1. * np.arange(len(ip)) / (len(ip) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('ip packets')

    # plot non-ip packets cdf
    plt.figure(5)
    sorted_list = np.sort(non_ip)
    p = 1. * np.arange(len(non_ip)) / (len(non_ip) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('non ip packets')

    ######################################################################
    # plot headers cdf
    ######################################################################

    # plot tcp header cdf
    plt.figure(6)
    tcp_header_list = np.sort(tcp_header)
    p = 1. * np.arange(len(tcp_header)) / (len(tcp_header) - 1)
    plt.plot(tcp_header_list, p)
    plt.xscale('log')
    plt.title('tcp headers')

    # plot udp header cdf
    plt.figure(7)
    udp_header_list = np.sort(udp_header)
    p = 1. * np.arange(len(udp_header)) / (len(udp_header) - 1)
    plt.plot(udp_header_list, p)
    plt.xscale('log')
    plt.title('udp headers')

    # plot ip header cdf
    plt.figure(8)
    ip_header_list = np.sort(ip_header)
    p = 1. * np.arange(len(ip_header)) / (len(ip_header) - 1)
    plt.plot(ip_header_list, p)
    plt.xscale('log')
    plt.title('ip headers')


    # show figures
    plt.show()