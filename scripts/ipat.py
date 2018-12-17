import csv
import numpy as np
import matplotlib.pyplot as plt

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('../raw/ipat_dump.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}

    # coarse count of flows
    for no, time, source, destination, protocol, length, info, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port in data:
        # Extract the src and dest ports
        if protocol == "UDP" or protocol == "TCP":
            src_port = tcp_src_port if protocol == "TCP" else udp_src_port
            dest_port = tcp_dst_port if protocol == "TCP" else udp_dst_port

            # build a flow identifier from src/dest ips
            ident = '{src_ip}:{src_port},{dst_ip}:{dst_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            reverse = '{dst_ip}:{dst_port},{src_ip}:{src_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            
            if (not ident in flows) and (not reverse in flows):
                flows[ident] = {'protocol': protocol, 'times': [time]}
            else:
                try:
                    flows[ident]['times'].append(time)
                except:
                    flows[reverse]['times'].append(time)
    
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

    # find duplicate times
    seen = {}
    dupes = []
    for x in packet_arrival_set:
        if x not in seen:
            seen[x] = 1
        else:
            if seen[x] == 1:
                dupes.append(x)
            seen[x] += 1

    tcp_dupes = []
    udp_dupes = []
    for element in dupes:
        if element in TCP_arrival_set:
            tcp_dupes.append(element)
        if element in UDP_arrival_set:
            udp_dupes.append(element)

    print('most freq:' + str(max(set(dupes), key=dupes.count)))
    print('tcp freq:' + str(max(set(tcp_dupes), key=tcp_dupes.count)))
    print('udp freq:' + str(max(set(udp_dupes), key=udp_dupes.count)))

    ######################################################################
    # plot all flows cdf
    ######################################################################

    # plot all flows cdf
    plt.figure(1)
    sorted_list = np.sort(packet_arrival_set)
    p = 1. * np.arange(len(packet_arrival_set)) / (len(packet_arrival_set) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('CDF of All Interpacket Arrival Time')

    # plot tcp packets cdf
    plt.figure(2)
    tcp_list = np.sort(TCP_arrival_set)
    p = 1. * np.arange(len(TCP_arrival_set)) / (len(TCP_arrival_set) - 1)
    plt.plot(tcp_list, p)
    plt.xscale('log')
    plt.title('CDF of TCP Interpacket Arrival Time')

    # plot udp packets cdf
    plt.figure(3)
    udp_list = np.sort(UDP_arrival_set)
    p = 1. * np.arange(len(UDP_arrival_set)) / (len(UDP_arrival_set) - 1)
    plt.plot(udp_list, p)
    plt.xscale('log')
    plt.title('CDF of UDP Interpacket Arrival Time')

    # show graphs
    plt.show()