#!/usr/local/bin/python3
from utils import *

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *

import os
import sys
import statistics

''' Global constants '''
TARGET_IP = '192.168.1.67' # client IP
HTTPS_PORT = 443 # assuming HTTPS traffic should be on port 443
SEGMENT_FILTER_THRESHOLD = 0.2 # if a cluster is 20% the size of the median, it is ignored

''' Stores features for clustering and prediction '''
class PacketInfo():
    def __init__(self, time_us, size):
        self.time_us = time_us
        self.size = size

''' Driver class for analyzing packet captures '''
class PacketAnalyzer():
    ''' Analyzes the packet capture on initialization '''
    def __init__(self, pcap_fname):
        self.ip_to_name = dict()
        self.name_to_pkts = dict()
        dbg('Analyzing pcap file "{}".'.format(pcap_fname))
        tls_cnt = 0
        for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_fname):
            if self._process_packet(pkt_data, pkt_metadata):
                tls_cnt += 1
        dbg('Analyzed {} TLS packets.'.format(tls_cnt))
    
    ''' Helper to combine time metadata '''
    def _calc_time(pkt_metadata):
        return (pkt_metadata.tshigh << 32) | pkt_metadata.tslow

    ''' Helper to process a single packet from the capture '''
    def _process_packet(self, pkt_data, pkt_metadata):
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
        from_server = dst_ip == TARGET_IP
        from_client = src_ip == TARGET_IP
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
        self._process_tls_packet(pkt_metadata, tcp_pkt, from_server, server_ip)
        return True

    ''' Helper to process a TLS packet specifically '''
    def _process_tls_packet(self, pkt_metadata, tcp_pkt, from_server, server_ip):
        # for more info on TLS packets check this out: 
        # http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
        tls_pkt = tcp_pkt[TLS]
        tls_len = tls_pkt.len
        server_name = self.ip_to_name[server_ip] if server_ip in self.ip_to_name else server_ip
        pkt_time = PacketAnalyzer._calc_time(pkt_metadata)
        preamble = '[{}]: '.format(timestamp(pkt_time, resol=pkt_metadata.tsresol))
        preamble += '{} -> client'.format(server_name) if from_server else 'client -> {}'.format(server_name)
        if TLSChangeCipherSpec in tls_pkt:
            log('{}: Change cipher spec.'.format(preamble))
        elif TLSAlert in tls_pkt:
            log('{}: Alert.'.format(preamble))
        elif TLSApplicationData in tls_pkt:
            log('{}: {} bytes of data.'.format(preamble, tls_len))
            if not server_name in self.name_to_pkts:
                self.name_to_pkts[server_name] = []
            pkt_info = PacketInfo(pkt_time, tls_len)
            self.name_to_pkts[server_name].append(pkt_info)
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
                    self.ip_to_name[server_ip] = name

    ''' Cluster and print results '''
    def stats(self):
        for name, pkt_info in self.name_to_pkts.items():
            pkt_times = list(x.time_us for x in pkt_info)
            times = segment_times(pkt_times)
            log('Results for domain "{}":'.format(name))
            med_size = statistics.median(list(len(seg) for seg in times))
            for segment in times:
                seg_size = len(segment)
                if seg_size/med_size > SEGMENT_FILTER_THRESHOLD:
                    log('\tFound cluster of {} requests starting at {} and ending at {}.'.format(
                        seg_size, timestamp(min(segment)), timestamp(max(segment))))
                else:
                    log('\tIgnoring ephemeral packet cluster of size {}.'.format(seg_size))

def main():
    # Check args
    if len(sys.argv) < 2:
        err('Incorrect # of args! Expected `./analyze.py <pcap-filename>`')
    pcap_fname = sys.argv[1]
    if not os.path.exists(pcap_fname):
        err('pcap file "{}" does not exist!'.format(pcap_fname))

    # Analyze packet capture
    analysis = PacketAnalyzer(pcap_fname)
    analysis.stats()

if __name__ == '__main__':
    main()
