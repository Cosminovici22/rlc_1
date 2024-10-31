#!/usr/bin/python3

import sys
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    dest_mac = data[:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def parse_config_bpdu(data):
    src_root_bid = int.from_bytes(data[21:29], byteorder='big')
    src_root_path_cost = int.from_bytes(data[29:33], byteorder='big')
    src_bid = int.from_bytes(data[33:], byteorder='big')

    return src_root_bid, src_root_path_cost, src_bid

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return b'\x82\x00' + (vlan_id & 0x0FFF).to_bytes(2, 'big')

def create_bpdu(bid, root_bid, root_path_cost):
    # Custom configuration BPDU containing only information necessary for this implementation
    return (b'\x01\x80\xC2\x00\x00\x00'
            + get_switch_mac() 
            + b'\x00\x1b' # 27
            + b'\x42\x42\x03'
            + b'\x00\x00\x00\x00'
            + root_bid.to_bytes(8, 'big')
            + root_path_cost.to_bytes(4, 'big')
            + bid.to_bytes(8, 'big'))

def send_bpdu_every_sec():
    bpdu = create_bpdu(bid, bid, 0)
    while True:
        if bid == root_bid:
            for interface in interfaces:
                if vlan_ids[get_interface_name(interface)] == 'T':
                    send_to_link(interface, len(bpdu), bpdu)
        time.sleep(1)

def main():
    # These must be accessed by send_bpdu_every_sec() in a separate thread, so they are global
    global bid, root_bid, interfaces, vlan_ids, is_blocking

    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print('# Starting switch with id {}'.format(switch_id), flush=True)
    print('[INFO] Switch MAC', ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Parse switch configuration files in a dictionary
    vlan_ids = {}
    with open('configs/switch' + switch_id + '.cfg') as file:
        priority = int(file.readline())
        for line in file:
            interface_name, vlan_id = line.split()
            try:
                vlan_ids[interface_name] = int(vlan_id)
            except:
                vlan_ids[interface_name] = vlan_id

    bid = priority
    root_bid = bid
    root_path_cost = 0
    root_interface = -1

    # Create and start a new thread that deals with sending BPDUs
    t = threading.Thread(target=send_bpdu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    mac_table = {}
    is_blocking = [False] * num_interfaces

    while True:
        src_interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the source and destination MAC addresses in human readable format
        print('Destination MAC: {}'.format(':'.join(f'{b:02x}' for b in dest_mac)))
        print('Source MAC: {}'.format(':'.join(f'{b:02x}' for b in src_mac)))
        print('EtherType: {}'.format(ethertype))
        print('Received frame of size {} on interface {}'.format(length, src_interface), flush=True)

        # Check whether the received data is an STP frame and act accordingly
        if dest_mac == b'\x01\x80\xC2\x00\x00\x00':
            src_root_bid, src_root_path_cost, src_bid = parse_config_bpdu(data)

            if src_root_bid < root_bid:
                # If the root BID reported by an incoming BPDU is replacing this switch's root BID
                # as its own, toggle all other ports to blocking except the new root port
                if root_bid == bid:
                    for interface in interfaces:
                        if vlan_ids[get_interface_name(interface)] == 'T':
                            is_blocking[interface] = True
                is_blocking[src_interface] = False

                root_bid = src_root_bid
                root_path_cost = src_root_path_cost + 10
                root_interface = src_interface

                # Forward knowledge of new root BID to neighboring switches
                bpdu = create_bpdu(bid, root_bid, root_path_cost)
                for interface in interfaces:
                    if src_interface != interface and vlan_ids[get_interface_name(interface)] == 'T':
                        send_to_link(interface, len(bpdu), bpdu)

            elif src_root_bid == root_bid:
                # Check whether the path to the root bridge can be optimised
                if src_interface == root_interface:
                    root_path_cost = min(root_path_cost, src_root_path_cost + 10)
                elif src_root_path_cost > root_path_cost or src_bid > bid:
                    # Tiebreakers
                    is_blocking[src_interface] = False

            # Block ports on which this switch's BPDUs may circle back
            elif src_bid == bid:
                is_blocking[src_interface] = True

            # Discard other BPDUs
            else:
                continue

            # If this switch continues to be the root bridge following the previous checks, toggle
            # all of its ports to listening
            if bid == root_bid:
                for interface in interfaces:
                    is_blocking[interface] = False

            continue

        if is_blocking[src_interface]:
            continue

        # Build tagged and untagged frames depending on the presence of the VLAN tag
        if vlan_id == -1:
            vlan_id = vlan_ids[get_interface_name(src_interface)]
            untagged_frame = data
            untagged_length = length
            tagged_frame = data[:12] + create_vlan_tag(vlan_id) + data[12:]
            tagged_length = length + 4
        else:
            untagged_frame = data[:12] + data[16:]
            untagged_length = length - 4
            tagged_frame = data
            tagged_length = length

        # Correspond the source MAC address with the port on which the frame is received
        mac_table[src_mac] = src_interface
        try:
            interface = mac_table[dest_mac] # This throws an exception if no entry exists
            if interface != src_interface and not is_blocking[interface]:
                interface_name = get_interface_name(interface)
                if vlan_ids[interface_name] == vlan_id:
                    send_to_link(interface, untagged_length, untagged_frame)
                elif vlan_ids[interface_name] == 'T':
                    send_to_link(interface, tagged_length, tagged_frame)
        except:
            # Broadcast addresses are also handled here, since they are never added to the MAC table
            for interface in interfaces:
                if interface != src_interface and not is_blocking[interface]:
                    interface_name = get_interface_name(interface)
                    if vlan_ids[interface_name] == vlan_id:
                        send_to_link(interface, untagged_length, untagged_frame)
                    elif vlan_ids[interface_name] == 'T':
                        send_to_link(interface, tagged_length, tagged_frame)

if __name__ == '__main__':
    main()
