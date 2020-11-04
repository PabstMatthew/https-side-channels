#!/usr/local/bin/python3
from utils import *

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *

import os
import sys

target_ip = '192.168.1.67'
HTTPS_PORT = 443

ip_to_name = dict()

def calc_time(pkt_metadata):
    return (pkt_metadata.tshigh << 32) | pkt_metadata.tslow

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
    from_server = dst_ip == target_ip
    from_client = src_ip == target_ip
    server_ip = src_ip if from_server else dst_ip
    client_ip = src_ip if from_client else dst_ip
    if not from_server and not from_client:
        err('Packet does not appear to involve the client! src: {} dst: {}'.format(src_ip, dst_ip))
    elif from_server and from_client:
        err('Packet does not appear to involve a server! src: {} dst: {}'.format(src_ip, dst_ip))

    # Handle TCP layer
    tcp_pkt = ip_pkt[TCP]
    src_port = tcp_pkt.sport
    dst_port = tcp_pkt.dport
    protocol_port = src_port if from_server else dst_port
    if protocol_port != HTTPS_PORT:
        err('Protocol port "{}" does not match expected default HTTPS port 443!'.format(protocol_port))
    if TLS not in tcp_pkt:
        return False

    # Handle TLS layer
    # for more info on TLS packets check this out: 
    # http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
    tls_pkt = tcp_pkt[TLS]
    tls_len = tls_pkt.len
    server_name = ip_to_name[server_ip] if server_ip in ip_to_name else server_ip
    pkt_time = calc_time(pkt_metadata)
    preamble = '[{}]: '.format(timestamp(pkt_time, pkt_metadata.tsresol))
    preamble += '{} -> client'.format(server_name) if from_server else 'client -> {}'.format(server_name)
    if TLSChangeCipherSpec in tls_pkt:
        log('{}: Change cipher spec.'.format(preamble))
    elif TLSAlert in tls_pkt:
        log('{}: Alert.'.format(preamble))
    elif TLSApplicationData in tls_pkt:
        log('{}: {} bytes of data.'.format(preamble, tls_len))
    elif TLSClientHello in tls_pkt:
        log('{}: Handshake.'.format(preamble))
        shake = tls_pkt[TLSClientHello]
        if ServerName in shake:
            ext_data = shake[ServerName]
            if ext_data.nametype == 0xff:
                log('SNI disable request from {}.'.format(server_ip))
            else:
                name = str(ext_data.servername, 'utf-8')
                log('SNI: {} = {}.'.format(name, server_ip))
                ip_to_name[server_ip] = name

    return True

def analyze(pcap_fname):
    dbg('Analyzing pcap file "{}".'.format(pcap_fname))
    
    tls_cnt = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_fname):
        if process_packet(pkt_data, pkt_metadata):
            tls_cnt += 1
        
    dbg('Analyzed {} TLS packets.'.format(tls_cnt))

        
def main():
    if len(sys.argv) < 2:
        err('Incorrect # of args! Expected `./analyze.py <pcap-filename>`')
    pcap_fname = sys.argv[1]
    if not os.path.exists(pcap_fname):
        err('pcap file "{}" does not exist!'.format(pcap_fname))
    analyze(pcap_fname)

if __name__ == '__main__':
    main()
