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
    count = 0
    for no, time, source, destination, protocol, length, info in data[:100]:
        if protocol == "UDP" or protocol == "TCP":
            split_info = info.split(' ')
            if split_info[0][0] == '[':
                src_port = split_info[2]
                dest_port = split_info[6]
            else:
                src_port = split_info[0]
                dest_port = split_info[4]

            # Extract the important information for both directions
            imp_info = [source, destination, protocol, src_port, dest_port]
            imp_info_rev = [destination, source, protocol, dest_port, src_port]
            if not (imp_info in flow_info or imp_info_rev in flow_info):
                flows[imp_info] = {'protocol' : protocol, 'start-time' : time, 'end-time' : time}
                flow_info.append(imp_info)
                flow_info.append(imp_info_rev)
            elif imp_info in flow_info:
                flows[imp_info]['end-time'] = time
            else:
                flows[imp_info_rev]['end-time'] = time
