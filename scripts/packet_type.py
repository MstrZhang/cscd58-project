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

    protocols = {}

    # coarse count of protocols
    for no, time, source, destination, protocol, length, info in data:
        if not protocol in protocols:
            protocols[protocol] = {'count': 1, 'length': int(length)}
        else:
            protocols[protocol]['count'] += 1
            protocols[protocol]['length'] += int(length)

    # calculate total (for percentage calculation)
    total = 0
    for value in protocols.values():
        total += value['count']

    # output
    print('protocol count:')
    for key, value in protocols.items():
        print(key + ':\t' + str(value['count']) + ' packets'
                  + '\t' + str(value['length']) + ' bytes')
    print('='*55)
    print('link layer:')
    link_count = 0
    link_length = 0
    for key, value in protocols.items():
        if key in mapping['LINK']:
            link_count += value['count']
            link_length += value['length']
    print(str(link_count) + ' packets\t' + '{0:.2f}'.format(float(link_count) / total * 100) + '%\t' + str(link_length) + ' bytes')
    print('='*55)
    print('network layer:')
    network_count = 0
    network_length = 0
    for key, value in protocols.items():
        if key in mapping['NETWORK']:
            network_count += value['count']
            network_length += value['length']
    print(str(network_count) + ' packets\t' + '{0:.2f}'.format(float(network_count) / total * 100) + '%\t' + str(network_length) + ' bytes')
    print('='*55)
    print('transport layer:')
    transport_count = 0
    transport_length = 0
    for key, value in protocols.items():
        if key in mapping['TRANSPORT']:
            transport_count += value['count']
            transport_length += value['length']
    print(str(transport_count) + ' packets\t' + '{0:.2f}'.format(float(transport_count) / total * 100) + '%\t' + str(transport_length) + ' bytes')
    print('='*55)