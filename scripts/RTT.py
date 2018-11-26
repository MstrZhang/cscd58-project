#SRTT <- R
#SRTT <- (1 - alpha) * SRTT + alpha * R'
# alpha = 1/8
import csv
import numpy as np
import matplotlib.pyplot as plt

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
    # (csv dump extracted from wireshark -- tcp and ip header lengths specifically extracted from wireshark)
    with open('../raw/rtt_dump.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}
    alpha = float(1/8)

    # collect all packet lengths
    for no, time, source, destination, protocol, length, info, reset, syn, rtt, ack in data:
        if protocol == "TCP":
            # Extract the src and dest ports
            split_info = info.split('  >  ')
            if not split_info[0][0].isdigit():
                src_port = split_info[0].split(' ')[-1]
                dest_port = split_info[1].split(' ')[0]
            else:
                src_port = split_info[0]
                dest_port = split_info[1].split(' ')[0]

            # Build a flow identifier from src/dest ips
            ident = '{src_ip}:{src_port},{dst_ip}:{dst_port}'.format(src_ip=source,src_port=src_port,dst_ip=destination,dst_port=dest_port)
            reverse = '{dst_ip}:{dst_port},{src_ip}:{src_port}'.format(src_ip=source,src_port=src_port,dst_ip=destination,dst_port=dest_port)
            if not ident in flows:
                flows[ident] = {'packet-count' : 1, 'size' : int(length), 'start' : 0, 'end' : 0, 'times' : [], 'syn' : 0, 'sample-rtt' : 0, 'prev-ack-number' : 0, 'duration' : 0, 'prev-time' : 0}
            else:
                if reverse in flows:
                    ident = reverse
                flows[ident]['packet-count'] += 1
                flows[ident]['size'] += int(length)
                flows[ident]['end'] = float(time)
            
            # Build for RTT estimation
            if syn == 'Set':
                flows[ident]['syn'] = 1
                flows[ident]['start'] = float(time)
                flows[ident]['prev-time'] = float(time)
                flows[ident]['prev-ack-number'] = int(ack)
            
            if syn != 'Set' and flows[ident]['syn'] == 1 and flows[ident]['prev-ack-number'] != int(ack) and rtt != '':
                flows[ident]['sample-rtt'] += float(rtt)
                flows[ident]['prev-ack-number'] = int(ack)
                flows[ident]['times'].append(float(time) - float(flows[ident]['prev-time']))
                flows[ident]['prev-time'] = float(time)

            
                
    
    # Extract the desired information
    # First find the largest flows by packet sizes
    largest_flows_p = []
    largest_flows_b = []
    largest_flows_d = []

    for flow in flows:
        if len(largest_flows_p) == 0:
            largest_flows_p.append(flows[flow])
        elif largest_flows_p[0]['packet-count'] < flows[flow]['packet-count']:
            largest_flows_p[0] = flows[flow]
        elif len(largest_flows_p) == 1:
            largest_flows_p.append(flows[flow])
        elif largest_flows_p[1]['packet-count'] < flows[flow]['packet-count']:
            largest_flows_p[1] = flows[flow]
        elif len(largest_flows_p) == 2:
            largest_flows_p.append(flows[flow])
        elif largest_flows_p[2]['packet-count'] < flows[flow]['packet-count']:
            largest_flows_p[2] = flows[flow]
        
        if len(largest_flows_b) == 0:
            largest_flows_b.append(flows[flow])
        elif largest_flows_b[0]['size'] < flows[flow]['size']:
            largest_flows_b[0] = flows[flow]
        elif len(largest_flows_b) == 1:
            largest_flows_b.append(flows[flow])
        elif largest_flows_b[1]['size'] < flows[flow]['size']:
            largest_flows_b[1] = flows[flow]
        elif len(largest_flows_b) == 2:
            largest_flows_b.append(flows[flow])
        elif largest_flows_b[2]['size'] < flows[flow]['size']:
            largest_flows_b[2] = flows[flow]
        
        flows[flow]['duration'] = flows[flow]['end'] - flows[flow]['start']
        if len(largest_flows_d) == 0:
            largest_flows_d.append(flows[flow])
        elif largest_flows_d[0]['duration'] < flows[flow]['duration']:
            largest_flows_d[0] = flows[flow]
        elif len(largest_flows_d) == 1:
            largest_flows_d.append(flows[flow])
        elif largest_flows_d[1]['duration'] < flows[flow]['duration']:
            largest_flows_d[1] = flows[flow]
        elif len(largest_flows_d) == 2:
            largest_flows_d.append(flows[flow])
        elif largest_flows_d[2]['duration'] < flows[flow]['duration']:
            largest_flows_d[2] = flows[flow]
    
    ######################################################################
    # calculate estimated RTTS - packets
    ######################################################################
    # After calculating the desired largest values, we can grab the estimated RTT
    # and calculate our own RTT
    estimated_rtts_p1 = []
    if largest_flows_p[0]['times'] != []:
        estimated_rtt_p1 = largest_flows_p[0]['times'][0]
        estimated_rtts_p1.append(estimated_rtt_p1)
        for i in range(len(largest_flows_p[0]['times']) - 1):
            estimated_rtt_p1 = ((1 - alpha) * estimated_rtt_p1) + (alpha * largest_flows_p[0]['times'][i + 1])
            estimated_rtts_p1.append(estimated_rtt_p1)
    else: estimated_rtt_p1 = 0

    estimated_rtts_p2 = []
    if largest_flows_p[1]['times'] != []:
        estimated_rtt_p2 = largest_flows_p[1]['times'][0]
        estimated_rtts_p2.append(estimated_rtt_p2)
        for i in range(len(largest_flows_p[1]['times']) - 1):
            estimated_rtt_p2 = ((1 - alpha) * estimated_rtt_p2) + (alpha * largest_flows_p[1]['times'][i + 1])
            estimated_rtts_p2.append(estimated_rtt_p2)
    else: estimated_rtt_p2 = 0
    
    estimated_rtts_p3 = []
    if largest_flows_p[2]['times'] != []:
        estimated_rtt_p3 = largest_flows_p[2]['times'][0]
        estimated_rtts_p3.append(estimated_rtt_p3)
        for i in range(len(largest_flows_p[2]['times']) - 1):
            estimated_rtt_p3 = ((1 - alpha) * estimated_rtt_p3) + (alpha * largest_flows_p[2]['times'][i + 1])
            estimated_rtts_p3.append(estimated_rtt_p3)
    else: estimated_rtt_p3 = 0

    ######################################################################
    # calculate estimated RTTS - byes
    ######################################################################
    estimated_rtts_b1 = []
    if largest_flows_b[0]['times'] != []:
        estimated_rtt_b1 = largest_flows_p[0]['times'][0]
        estimated_rtts_b1.append(estimated_rtt_b1)
        for i in range(len(largest_flows_p[0]['times']) - 1):
            estimated_rtt_b1 = ((1 - alpha) * estimated_rtt_b1) + (alpha * largest_flows_b[0]['times'][i + 1])
            estimated_rtts_b1.append(estimated_rtt_b1)
    else: estimated_rtt_b1 = 0

    estimated_rtts_b2 = []
    if largest_flows_b[1]['times'] != []:
        estimated_rtt_b2 = largest_flows_b[1]['times'][0]
        estimated_rtts_b2.append(estimated_rtt_b2)
        for i in range(len(largest_flows_b[1]['times']) - 1):
            estimated_rtt_b2 = ((1 - alpha) * estimated_rtt_b2) + (alpha * largest_flows_b[1]['times'][i + 1])
            estimated_rtts_b2.append(estimated_rtt_b2)
    else: estimated_rtt_b2 = 0
    
    estimated_rtts_b3 = []
    if largest_flows_b[2]['times'] != []:
        estimated_rtt_b3 = largest_flows_b[2]['times'][0]
        estimated_rtts_b3.append(estimated_rtt_b3)
        for i in range(len(largest_flows_b[2]['times']) - 1):
            estimated_rtt_b3 = ((1 - alpha) * estimated_rtt_b3) + (alpha * largest_flows_b[2]['times'][i + 1])
            estimated_rtts_b3.append(estimated_rtt_b3)
    else: estimated_rtt_b3 = 0

    ######################################################################
    # calculate estimated RTTS - byes
    ######################################################################
    estimated_rtts_d1 = []
    if largest_flows_d[0]['times'] != []:
        estimated_rtt_d1 = largest_flows_p[0]['times'][0]
        estimated_rtts_d1.append(estimated_rtt_d1)
        for i in range(len(largest_flows_p[0]['times']) - 1):
            estimated_rtt_d1 = ((1 - alpha) * estimated_rtt_d1) + (alpha * largest_flows_d[0]['times'][i + 1])
            estimated_rtts_d1.append(estimated_rtt_d1)
    else: estimated_rtt_d1 = 0

    estimated_rtts_d2 = []
    if largest_flows_d[1]['times'] != []:
        estimated_rtt_d2 = largest_flows_d[1]['times'][0]
        estimated_rtts_d2.append(estimated_rtt_d2)
        for i in range(len(largest_flows_d[1]['times']) - 1):
            estimated_rtt_d2 = ((1 - alpha) * estimated_rtt_d2) + (alpha * largest_flows_d[1]['times'][i + 1])
            estimated_rtts_d2.append(estimated_rtt_d2)
    else: estimated_rtt_d2 = 0
    
    estimated_rtts_d3 = []
    if largest_flows_d[2]['times'] != []:
        estimated_rtt_d3 = largest_flows_d[2]['times'][0]
        estimated_rtts_d3.append(estimated_rtt_d3)
        for i in range(len(largest_flows_d[2]['times']) - 1):
            estimated_rtts_d3 = ((1 - alpha) * estimated_rtt_d3) + (alpha * largest_flows_d[2]['times'][i + 1])
            estimated_rtts_d3.append(estimated_rtt_d3)
    else: estimated_rtt_d3 = 0
