import csv

mapping = {
    'APPLICATION': ['TELNET', 'MySQL', 'SMTP', 'SSH', 'RIP', 'DHCPv6', 'DNS', 'LPD', 'CVSPSERVER', 'Intel ANS probe', 'VNC', 'SSL', 'ISAKMP', 'MDNS', 'MS NLB', 'DSI', 'LLMNR', 'NTP', 'NCS', 'BOOTP', 'SRVLOC'],
    'TRANSPORT': ['TCP', 'UDP', 'NBSS', 'Syslog'],
    'NETWORK': ['IPX', 'IPv4', 'IGMPv0', 'ICMPv6', 'ICMP', 'OSPF', 'PIMv0', 'IGRP', 'VRRP', 'RSL', 'ESP', 'GRE'],
    'LINK': ['ARP', 'CDP', 'LLC', 'PPTP'],
    'OTHER': ['NBNS', '0x200e', 'Gryphon', 'NBDS', 'NCP', 'UDPENCAP']
}

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
            ident = ip_to_int(source) + ip_to_int(destination) + int(src_port) + int(dest_port)
            if not ident in flows:
                flows[ident] = {'protocol' : protocol}

    # calculate total (for percentage calculation)
    total = 0
    tcp_count = 0
    udp_count = 0
    for flow in flows:
        total += 1
        if flows[flow]['protocol'] == 'TCP':
            tcp_count += 1
        else:
            udp_count += 1

    # output
    print('flow count: ' + str(total) + ' flows')
    print('TCP total: ' + ':\t' + str(tcp_count) + ' flows' + '\t' + '{0:.2f}'.format(float(tcp_count) / total * 100)) + '%'
    print('UDP total: ' + ':\t' + str(udp_count) + ' flows' + '\t' + '{0:.2f}'.format(float(udp_count) / total * 100)) + '%'
    print('='*55)
    