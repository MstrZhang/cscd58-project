import csv
import numpy as np
import matplotlib.pyplot as plt

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('../raw/univ1_trace.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}

    # coarse count of flows
    for no, time, source, destination, protocol, length, info in data:
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
            ident = '{src_ip}:{src_port},{dst_ip}:{dst_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            reverse = '{dst_ip}:{dst_port},{src_ip}:{src_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            
            if (not ident in flows) and (not reverse in flows):
                flows[ident] = {'protocol' : protocol, 'start-time' : time, 'end-time' : time}
            else:
                try:
                    if time > flows[ident]['end-time']:
                        flows[ident]['end-time'] = time
                except:
                    if time > flows[reverse]['end-time']:
                        flows[reverse]['end-time'] = time
    
    # Extract the finishing times for each required analysis
    # We won't consider a flow if the start time and end time are equivalent, this
    # can be read as a single packet being sent
    flow_durations = []
    TCP_durations = []
    UDP_durations = []
    for flow in flows:
        if not flows[flow]['start-time'] == flows[flow]['end-time']:
            duration = float(flows[flow]['end-time']) - float(flows[flow]['start-time'])
            flow_durations.append(duration)
            
            # Separate by protocol
            if flows[flow]['protocol'] == 'TCP':
                TCP_durations.append(duration)
            else:
                UDP_durations.append(duration)
    
    ######################################################################
    # plot cdfs
    ######################################################################

    # plot all flows cdf
    plt.figure(1)
    sorted_list = np.sort(flow_durations)
    p = 1. * np.arange(len(flow_durations)) / (len(flow_durations) - 1)
    plt.plot(sorted_list, p)
    plt.xscale('log')
    plt.xlabel('seconds')
    plt.title('CDF of Duration for All Flows')

    # plot tcp packets cdf
    plt.figure(2)
    tcp_list = np.sort(TCP_durations)
    p = 1. * np.arange(len(TCP_durations)) / (len(TCP_durations) - 1)
    plt.plot(tcp_list, p)
    plt.xscale('log')
    plt.xlabel('seconds')
    plt.title('CDF of Duration for TCP Flows')

    # plot udp packets cdf
    plt.figure(3)
    udp_list = np.sort(UDP_durations)
    p = 1. * np.arange(len(UDP_durations)) / (len(UDP_durations) - 1)
    plt.plot(udp_list, p)
    plt.xscale('log')
    plt.xlabel('seconds')
    plt.title('CDF of Duration for UDP Flows')


    # show graphs
    plt.show()