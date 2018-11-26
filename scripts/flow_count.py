import csv

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark)
    with open('../raw/flow_count_dump.csv', 'rb') as f:
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
                flows[ident] = {'protocol': protocol, 'packets': 1, 'length': int(length)}
            else:
                try:
                    flows[ident]['packets'] += 1
                    flows[ident]['length'] += int(length)
                except:
                    flows[reverse]['packets'] += 1
                    flows[reverse]['length'] += int(length)

    # calculate totals
    total = 0
    tcp_count = 0
    udp_count = 0
    tcp_packet_count = 0
    udp_packet_count = 0
    tcp_length = 0
    udp_length = 0

    for flow in flows:
        total += 1
        if flows[flow]['protocol'] == 'TCP':
            tcp_count += 1
            tcp_packet_count += flows[flow]['packets']
            tcp_length += flows[flow]['length']
        else:
            udp_count += 1
            udp_packet_count += flows[flow]['packets']
            udp_length += flows[flow]['length']

    # output
    print('flow count: ' + str(total) + ' flows')

    print('TCP total:\t' + str(tcp_count) + ' flows\t' 
                         + '{0:.2f}'.format(float(tcp_count) / total * 100) + '%\t'
                         + str(tcp_packet_count) + ' packets\t'
                         + str(tcp_length) + ' bytes')

    print('UDP total:\t' + str(udp_count) + ' flows\t' 
                     + '{0:.2f}'.format(float(udp_count) / total * 100) + '%\t'
                     + str(udp_packet_count) + ' packets\t'
                     + str(udp_length) + ' bytes')

    