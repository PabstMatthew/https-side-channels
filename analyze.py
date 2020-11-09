from utils import *

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *
from scapy.layers.dot11 import *
from scapy.all import sniff

import os
import sys
import statistics
import re

''' Global constants '''
TARGET_IP = '192.168.144.154' # client IP
HTTPS_PORT = 443 # assuming HTTPS traffic should be on port 443
SEGMENT_FILTER_THRESHOLD = 0.2 # if a cluster is 20% the size of the median, it is ignored

''' Stores features for clustering and prediction '''
class PacketInfo():
    def __init__(self, time_us, size, host, from_server):
        self.time = time_us
        self.size = size
        self.host = host
        self.from_server = from_server

    def __str__(self):
        if self.from_server:
            return '[{}]: {} bytes from {}'.format(timestamp(self.time), self.size, self.host)
        else:
            return '[{}]: {} bytes to {}'.format(timestamp(self.time), self.size, self.host)

    def __repr__(self):
        return str({'size':self.size, 'time':self.time, 'host':self.host, 'from_server':self.from_server})

''' Driver class for analyzing packet captures '''
class PacketAnalyzer():
    ''' Analyzes the packet capture on initialization '''
    def __init__(self, pkts):
        self.ip_to_name = dict()
        self.pkts = []
        dbg('Analyzing {} packets.'.format(len(pkts)))
        tls_cnt = 0
        for pkt in pkts:
            if self._process_packet(pkt):
                tls_cnt += 1
        dbg('Analyzed {} TLS packets.'.format(tls_cnt))
    
    ''' Helper to combine time metadata '''
    def _calc_time(pkt_metadata):
        return (pkt_metadata.tshigh << 32) | pkt_metadata.tslow

    def _process_packet(self, pkt):
        # Handle IP layer
        ip_pkt = pkt[IP]
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
        pkt_time = tcp_pkt.time
        src_port = tcp_pkt.sport
        dst_port = tcp_pkt.dport
        protocol_port = src_port if from_server else dst_port
        if TLS not in tcp_pkt:
            return False

        # Handle TLS layer
        self._process_tls_packet(pkt_time, tcp_pkt, from_server, server_ip)
        return True

    ''' Helper to process a TLS packet specifically '''
    def _process_tls_packet(self, pkt_time, tcp_pkt, from_server, server_ip):
        # for more info on TLS packets check this out: 
        # http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
        tls_pkt = tcp_pkt[TLS]
        tls_len = tls_pkt.len
        server_name = self.ip_to_name[server_ip] if server_ip in self.ip_to_name else server_ip
        preamble = '[{}]: '.format(timestamp(pkt_time))
        preamble += '{} -> client'.format(server_name) if from_server else 'client -> {}'.format(server_name)
        if TLSChangeCipherSpec in tls_pkt:
            log('{}: Change cipher spec.'.format(preamble))
        elif TLSAlert in tls_pkt:
            log('{}: Alert.'.format(preamble))
        elif TLSApplicationData in tls_pkt:
            log('{}: {} bytes of data.'.format(preamble, tls_len))
            pkt_info = PacketInfo(pkt_time, tls_len, server_name, from_server)
            self.pkts.append(pkt_info)
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

    def _cluster_within_host(self):
        clusters = []
        self.pkts.sort(key=lambda pkt: pkt.time)
        pkt_times = list(x.time for x in self.pkts)
        time_segments = segment_times(pkt_times)
        med_size = statistics.median(list(len(seg) for seg in time_segments))
        cur_pkt = 0
        for time_segment in time_segments:
            seg_size = len(time_segment)
            if seg_size/med_size > SEGMENT_FILTER_THRESHOLD:
                start_time = min(time_segment)
                end_time = max(time_segment)
                log('\tFound cluster of {} requests starting at {} and ending at {}.'.format(
                    seg_size, timestamp(start_time), timestamp(end_time)))
                # reconstruct the segment
                segment = self.pkts[cur_pkt:cur_pkt+seg_size]
                clusters.append(segment)
            else:
                log('\tIgnoring ephemeral packet cluster of size {}.'.format(seg_size))
            cur_pkt += seg_size
        return clusters

    def _analyze_cluster(self, cluster):
        # ignore hosts with no domain name
        cluster = list(filter(lambda pkt: not re.match('\d+\.\d+\.\d+\.\d+', pkt.host), cluster))
        cluster_size = len(cluster)
        if cluster_size == 0:
            return
        log('Cluster of {} packets beginning at {}:'.format(cluster_size, timestamp(cluster[0].time)))
        # check which hosts have been visited in this cluster
        hosts = set()
        for pkt in cluster:
            hosts.add(pkt.host)
        log('Hosts accessed: {}'.format(hosts))
        # print all packets
        for pkt in cluster:
            log('\t{}'.format(str(pkt)))

    ''' Cluster and print results '''
    def stats(self):
        clusters = self._cluster_within_host()
        for cluster in clusters:
            self._analyze_cluster(cluster)

def main():
    # Check args
    '''
    if len(sys.argv) < 2:
        err('Incorrect # of args! Expected `./analyze.py <pcap-filename>`')
    pcap_fname = sys.argv[1]
    if not os.path.exists(pcap_fname):
        err('pcap file "{}" does not exist!'.format(pcap_fname))
    '''

    # Analyze packet capture
    pkts = sniff(iface='wlp4s0mon', count=100, filter='tcp and port 443 and host {}'.format(TARGET_IP))
    analysis = PacketAnalyzer(pkts)
    analysis.stats()

if __name__ == '__main__':
    main()
