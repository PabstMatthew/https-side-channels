#!/usr/local/bin/python3
from utils import *

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

import os
import sys

client_ip = '192.168.1.67'

def process_packet(pkt_data, pkt_metadata):
    # Handle ethernet layer
    ether_pkt = Ether(pkt_data)
    if 'type' not in ether_pkt.fields:
        # Disregard LLC (logical link control) frames
        return False
    if ether_pkt.type != 0x0800:
        # Disregard non-IPv4 packets
        return False

    ip_pkt = ether_pkt[IP]
    if ip_pkt.proto != 6:
        # Disregard non-TCP packet
        return False
    
    # Handle IP layer
    dst_ip = ip_pkt.dst
    src_ip = ip_pkt.src
    from_server = dst_ip == client_ip
    from_client = src_ip == client_ip
    if not from_server and not from_client:
        err('Packet does not appear to involve the client! src: {} dst: {}'.format(src_ip, dst_ip))
    elif from_server and from_client:
        err('Packet does not appear to involve a server! src: {} dst: {}'.format(src_ip, dst_ip))

    # Handle TCP layer
    tcp_pkt = ip_pkt[TCP]
    src_port = tcp_pkt.sport
    dst_port = tcp_pkt.dport
    protocol_port = src_port if from_server else dst_port
    if protocol_port != 443:
        err('Protocol port "{}" does not match expected default HTTPS port 443!'.format(protocol_port))

    # Identify SNI
    tcp_data = bytes(tcp_pkt.payload)
    if len(tcp_data) < 6:
        return True
    if tcp_data[0] == 0x16 and tcp_data[5] == 0x01:
        # this packet is a client hello packet
        name_len = int.from_bytes(tcp_data[125:127], 'big')
        name = str(tcp_data[127:127+name_len], 'utf-8')
        if name_len == 1:
            dbg('Found SNI-disable request from src IP {} to dst IP {}.'.format(src_ip, dst_ip))
        else:
            dbg('Found SNI from src IP {} for domain {} at dst IP {}.'.format(src_ip, name, dst_ip))

    return True

def analyze(pcap_fname):
    dbg('Analyzing pcap file "{}".'.format(pcap_fname))
    
    tcp_cnt = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_fname):
        if process_packet(pkt_data, pkt_metadata):
            tcp_cnt += 1
        
    dbg('Analyzed {} TCP packets.'.format(tcp_cnt))

        
def main():
    if len(sys.argv) < 2:
        err('Incorrect # of args! Expected `./analyze.py <pcap-filename>`')
    pcap_fname = sys.argv[1]
    if not os.path.exists(pcap_fname):
        err('pcap file "{}" does not exist!'.format(pcap_fname))
    analyze(pcap_fname)

if __name__ == '__main__':
    main()
