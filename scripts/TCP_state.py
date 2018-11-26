import csv

if __name__ == '__main__':
    # read pcap csv dump
    # (csv dump extracted from wireshark -- tcp and ip header lengths specifically extracted from wireshark)
    with open('../raw/tcp_state_dump.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}

    # collect all packet lengths
    # only concerned with reset, fin and request since the time doesn't provide
    # enough info for ongoing or failed
    for no, time, source, destination, protocol, length, info, tcp_src_port, tcp_dst_port, reset, fin, request in data:
        # Extract the src and dest ports
        if protocol == "TCP":
            src_port = tcp_src_port
            dest_port = tcp_dst_port

            # build a flow identifier from src/dest ips
            ident = '{src_ip}:{src_port},{dst_ip}:{dst_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            reverse = '{dst_ip}:{dst_port},{src_ip}:{src_port}'.format(src_ip=source, src_port=src_port, dst_ip=destination, dst_port=dest_port)
            
            if (not ident in flows) and (not reverse in flows):
                flows[ident] = {'reset' : 0, 'fin' : 0, 'request' : 0, 'other' : 0}
            else:
                try:
                    if reset == 'Set':
                        flows[ident] = {'reset' : 1, 'fin' : 0, 'request' : 0, 'other' : 0}
                    elif fin == 'Set':
                        flows[ident] = {'reset' : 0, 'fin' : 1, 'request' : 0, 'other' : 0}
                    elif request == 'Set':
                        flows[ident] = {'reset' : 0, 'fin' : 0, 'request' : 1, 'other' : 0}
                    else:
                        flows[ident] = {'reset' : 0, 'fin' : 0, 'request' : 0, 'other' : 1}
                except:
                    if reset == 'Set':
                        flows[reverse] = {'reset' : 1, 'fin' : 0, 'request' : 0, 'other' : 0}
                    elif fin == 'Set':
                        flows[reverse] = {'reset' : 0, 'fin' : 1, 'request' : 0, 'other' : 0}
                    elif request == 'Set':
                        flows[reverse] = {'reset' : 0, 'fin' : 0, 'request' : 1, 'other' : 0}
                    else:
                        flows[reverse] = {'reset' : 0, 'fin' : 0, 'request' : 0, 'other' : 1}

    # Extract the desired information
    reset_count = 0
    fin_count = 0
    request_count = 0
    other_count = 0
    for value in flows.values():
        reset_count += value['reset']
        fin_count += value['fin']
        request_count += value['request']
        other_count += value['other']

    print('reset count: ' + str(reset_count))
    print('fin count: ' + str(fin_count))
    print('request count: ' + str(request_count))
    print('other count: ' + str(other_count))