import csv
import numpy as np
import matplotlib.pyplot as plt

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark -- tcp and ip header lengths specifically extracted from wireshark)
    with open('../raw/flow_size.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}

    # collect all packet lengths
    for no, time, source, destination, protocol, length, info, tcp_src_port, tcp_dst_port, tcp_payload, udp_src_port, udp_dst_port, syn in data:
        # Extract the src and dest ports
        if protocol == "UDP" or protocol == "TCP":
            src_port = tcp_src_port if protocol == "TCP" else udp_src_port
            dest_port = tcp_dst_port if protocol == "TCP" else udp_dst_port

            # build a flow identifier from src/dest ips
            ident = '{src_ip}:{src_port},{dst_ip}:{dst_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            reverse = '{dst_ip}:{dst_port},{src_ip}:{src_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            
            if (not ident in flows) and (not reverse in flows):
                flows[ident] = {'protocol': protocol, 'packet-count': 1, 'size': int(length), 'header-size': 0, 'payload-size': 0}
            else:
                try:
                    flows[ident]['packet-count'] += 1
                    flows[ident]['size'] += int(length)
                    # check for overhead modifications; only concerned with TCP flows
                    if flows[ident]['protocol'] == 'TCP':
                        if tcp_payload == '':
                            tcp_payload = 0
                        flows[ident]['header-size'] += (int(length) - int(tcp_payload))
                        flows[ident]['payload-size'] += int(tcp_payload)
                except:
                    flows[reverse]['packet-count'] += 1
                    flows[reverse]['size'] += int(length)
                    # check for overhead modifications; only concerned with TCP flows
                    if flows[reverse]['protocol'] == 'TCP':
                        if tcp_payload == '':
                            tcp_payload = 0
                        flows[reverse]['header-size'] += (int(length) - int(tcp_payload))
                        flows[reverse]['payload-size'] += int(tcp_payload)

    # Extract the desired information
    packets_per_flow = []
    packets_per_TCP = []
    packets_per_UDP = []

    size_per_flow = []
    size_per_TCP = []
    size_per_UDP = []

    TCP_overhead_ratios = []

    for flow in flows:
        packets_per_flow.append(flows[flow]['packet-count'])
        size_per_flow.append(flows[flow]['size'])

        # Filter between TCP and UDP
        if flows[flow]['protocol'] == 'TCP':
            packets_per_TCP.append(flows[flow]['packet-count'])
            size_per_TCP.append(flows[flow]['size'])

            # Calculate overhead ratio
            if flows[flow]['payload-size'] == 0:
                flows[flow]['payload-size'] = 9999
            TCP_overhead_ratios.append(float(flows[flow]['header-size']) / flows[flow]['payload-size'])
        else:
            packets_per_UDP.append(flows[flow]['packet-count'])
            size_per_UDP.append(flows[flow]['size'])
    

    ######################################################################
    # plot all packets cdf
    ######################################################################

    # plot all flow packets cdf
    plt.figure(1)
    sorted_list = np.sort(packets_per_flow)
    p = 1. * np.arange(len(packets_per_flow)) / (len(packets_per_flow) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('CDF of Combined Flow Sizes (packets)')

    # plot all flow bytes cdf
    plt.figure(2)
    sorted_list = np.sort(size_per_flow)
    p = 1. * np.arange(len(size_per_flow)) / (len(size_per_flow) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('CDF of Combined Flow Sizes (bytes)')

    # plot tcp flow packets cdf
    plt.figure(3)
    tcp_list = np.sort(packets_per_TCP)
    p = 1. * np.arange(len(packets_per_TCP)) / (len(packets_per_TCP) - 1)
    plt.plot(tcp_list, p)
    plt.xscale('log')
    plt.title('CDF of TCP Flow Sizes (packets)')

    # plot tcp flow bytes cdf
    plt.figure(4)
    sorted_list = np.sort(size_per_TCP)
    p = 1. * np.arange(len(size_per_TCP)) / (len(size_per_TCP) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('CDF of TCP Flow Sizes (bytes)')

    # plot udp flow packets cdf
    plt.figure(5)
    udp_list = np.sort(packets_per_UDP)
    p = 1. * np.arange(len(packets_per_UDP)) / (len(packets_per_UDP) - 1)
    plt.plot(udp_list, p)
    plt.xscale('log')
    plt.title('CDF of UDP Flow Sizes (packets)')

    # plot udp flow bytes cdf
    plt.figure(6)
    sorted_list = np.sort(size_per_UDP)
    p = 1. * np.arange(len(size_per_UDP)) / (len(size_per_UDP) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.title('CDF of UDP Flow Sizes (bytes)')

    # ######################################################################
    # # plot tcp overhead ratio cdf
    # ######################################################################

    # plot tcp overhead ratios cdf
    plt.figure(7)
    tcp_header_list = np.sort(TCP_overhead_ratios)
    p = 1. * np.arange(len(TCP_overhead_ratios)) / (len(TCP_overhead_ratios) - 1)
    plt.plot(tcp_header_list, p)
    plt.xscale('log')
    plt.title('CDF of TCP Overhead Ratios')

    # show figures
    plt.show()