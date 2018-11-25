import csv

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
    with open('../raw/tcp_state_dump.csv', 'rb') as f:
        data = list(csv.reader(f))[1:]

    flows = {}

    # collect all packet lengths
    # only concerned with reset, fin and request since the time doesn't provide
    # enough info for ongoing or failed
    for no, time, source, destination, protocol, length, info, reset, fin, request in data:
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
            ident = ip_to_int(source) + ip_to_int(destination) + int(src_port) + int(dest_port)
            if not ident in flows:
                flows[ident] = {'reset' : 0, 'fin' : 0, 'request' : 0, 'other' : 0}
            if reset == 'Set':
                flows[ident] = {'reset' : 1, 'fin' : 0, 'request' : 0, 'other' : 0}
            elif fin == 'Set':
                flows[ident] = {'reset' : 0, 'fin' : 1, 'request' : 0, 'other' : 0}
            elif request == 'Set':
                flows[ident] = {'reset' : 0, 'fin' : 0, 'request' : 1, 'other' : 0}
            else:
                flows[ident] = {'reset' : 0, 'fin' : 0, 'request' : 0, 'other' : 1}

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