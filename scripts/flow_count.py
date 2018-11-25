import csv

mapping = {
    'APPLICATION': ['TELNET', 'MySQL', 'SMTP', 'SSH', 'RIP', 'DHCPv6', 'DNS', 'LPD', 'CVSPSERVER', 'Intel ANS probe', 'VNC', 'SSL', 'ISAKMP', 'MDNS', 'MS NLB', 'DSI', 'LLMNR', 'NTP', 'NCS', 'BOOTP', 'SRVLOC'],
    'TRANSPORT': ['TCP', 'UDP', 'NBSS', 'Syslog'],
    'NETWORK': ['IPX', 'IPv4', 'IGMPv0', 'ICMPv6', 'ICMP', 'OSPF', 'PIMv0', 'IGRP', 'VRRP', 'RSL', 'ESP', 'GRE'],
    'LINK': ['ARP', 'CDP', 'LLC', 'PPTP'],
    'OTHER': ['NBNS', '0x200e', 'Gryphon', 'NBDS', 'NCP', 'UDPENCAP']
}

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('univ1_trace.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}
    flow_info = []

    # coarse count of flows
    for no, time, source, destination, protocol, length, info in data:
        if protocol == "UDP" or protocol == "TCP":
            split_info = info.split(' ')
            if split_info[0][0] == '[':
                src_port = split_info[2]
                dest_port = split_info[6]
            else:
                src_port = split_info[0]
                dest_port = split_info[4]
            if not protocol in flows:
                flows[protocol] = {'count' : 1}
                flow_info.append([source, destination, protocol, src_port, dest_port])
                flow_info.append([destination, source, protocol, dest_port, src_port])
            else:
                if [source, destination, protocol, src_port, dest_port] in flow_info:
                    flows[protocol]['count'] += 1
                else:
                    flow_info.append([source, destination, protocol, src_port, dest_port])
                    flow_info.append([destination, source, protocol, dest_port, src_port])

    # calculate total (for percentage calculation)
    total = 0
    for value in flows.values():
        total += value['count']

    # output
    print('flow count:')
    for key, value in flows.items():
        print(key + ':\t' + str(value['count']) + ' flows' + '\t' + '{0:.2f}'.format(float(value['count']) / total * 100)) + '%'
    print('='*55)
    