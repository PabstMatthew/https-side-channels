import domains
import utils
from utils import *

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *
from scapy.layers.dot11 import *

import os
import sys
import statistics
import re
import socket

''' Global constants '''
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
    def __init__(self, args, pkts, quiet=False):
        self.args = args
        self.pkts = []
        self.quiet = quiet
        self.ip_to_name = dict()
        self.unnamed_ips = set()

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
        pkt_time = pkt.time

        # Handle IP layer
        if not IP in pkt:
            return False
        ip_pkt = pkt[IP]
        dst_ip = ip_pkt.dst
        src_ip = ip_pkt.src
        from_server = dst_ip == self.args.target
        from_client = src_ip == self.args.target
        server_ip = src_ip if from_server else dst_ip
        client_ip = src_ip if from_client else dst_ip
        if not from_server and not from_client:
            # Packet doesn't involve the target
            return False
        elif from_server and from_client:
            # Packet doesn't involve the target
            return False

        # Handle TCP layer
        if not TCP in ip_pkt:
            return False
        tcp_pkt = ip_pkt[TCP]
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
        #server_name = self.ip_to_name[server_ip] if server_ip in self.ip_to_name else server_ip
        server_name = ''
        if server_ip in self.ip_to_name:
            server_name = self.ip_to_name[server_ip]
        elif not server_ip in self.unnamed_ips:
            try:
                hostname, _, _ = socket.gethostbyaddr(server_ip)
                # only take 2 top-level domains to avoid getting bogged down
                server_name = '.'.join(hostname.split('.')[-2:])
                self.ip_to_name[server_ip] = server_name
            except:
                self.unnamed_ips.add(server_ip)
                server_name = server_ip
        # process different TLS packet types
        preamble = '[{}]: '.format(timestamp(pkt_time))
        preamble += '{} -> client'.format(server_name) if from_server else 'client -> {}'.format(server_name)
        if TLSApplicationData in tls_pkt:
            if not self.quiet:
                dbg('{}: {} bytes of data.'.format(preamble, tls_len))
            if server_ip in self.ip_to_name and not domains.ignore(server_name):
                # ignore hosts with no domain name
                # filter out random analytics hosts
                pkt_info = PacketInfo(pkt_time, tls_len, server_name, from_server)
                self.pkts.append(pkt_info)
        '''
        if TLSChangeCipherSpec in tls_pkt:
            if not self.quiet:
                dbg('{}: Change cipher spec.'.format(preamble))
        elif TLSAlert in tls_pkt:
            if not self.quiet:
                dbg('{}: Alert.'.format(preamble))
        elif TLSClientHello in tls_pkt:
            if not self.quiet:
                dbg('{}: Handshake.'.format(preamble))
            shake = tls_pkt[TLSClientHello]
            if ServerName in shake:
                ext_data = shake[ServerName]
                if ext_data.nametype == 0xff:
                    if not self.quiet:
                        dbg('SNI disable request from {}.'.format(server_ip))
                else:
                    name = str(ext_data.servername, 'utf-8')
                    if not self.quiet:
                        dbg('SNI: {} = {}.'.format(name, server_ip))
                    #self.ip_to_name[server_ip] = name
        '''

    def _form_clusters(self):
        clusters = []
        self.pkts.sort(key=lambda pkt: pkt.time)
        pkt_times = list(x.time for x in self.pkts)
        time_segments = segment_times(pkt_times)
        med_size = statistics.median(list(len(seg) for seg in time_segments))
        cur_pkt = 0
        for time_segment in time_segments:
            seg_size = len(time_segment)
            if med_size > 0.0 and seg_size/med_size > SEGMENT_FILTER_THRESHOLD:
                start_time = min(time_segment)
                end_time = max(time_segment)
                if not self.quiet:
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
        cluster_size = len(cluster)
        if cluster_size == 0:
            return []
        if not self.quiet:
            log('Cluster of {} packets beginning at {}:'.format(cluster_size, timestamp(cluster[0].time)))
        # check which hosts have been visited in this cluster
        hosts = set()
        for pkt in cluster:
            hosts.add(pkt.host)
        if not self.quiet:
            log('Hosts accessed: {}'.format(hosts))
        # print all packets
        for pkt in cluster:
            if not self.quiet:
                dbg('\t{}'.format(str(pkt)))
        return cluster

    ''' Cluster and print results '''
    def stats(self):
        clusters = self._form_clusters()
        result = []
        for cluster in clusters:
            c = self._analyze_cluster(cluster)
            result.append(c)
        return result

