import domains
import utils
from utils import *

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import *
from scapy.layers.dot11 import *
from scapy.all import AsyncSniffer, sniff

import os
import sys
import statistics
import re
import argparse
import subprocess

''' Global constants '''
SEGMENT_FILTER_THRESHOLD = 0.2 # if a cluster is 20% the size of the median, it is ignored
class Profiler():
    def __init__(self, args):
        self.args = args

    def profile(self):
        url = self.args.profile
        log('Profiling URL "{}".'.format(url))
        sudo_uid = os.getenv("SUDO_UID")
        command = 'sudo -u #{} python3 browser.py {}'.format(sudo_uid, url)
        sniffer = AsyncSniffer(iface=self.args.interface, 
                               filter='tcp and port {} and host {}'.format(self.args.port, self.args.target))
        sniffer.start()
        subprocess.run(command.split())
        sniffer.stop()
        return sniffer.results

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
    def __init__(self, pkts, args):
        self.args = args
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
            err('Packet does not appear to involve the client! src: {} dst: {}'.format(src_ip, dst_ip))
        elif from_server and from_client:
            err('Packet does not appear to involve a server! src: {} dst: {}'.format(src_ip, dst_ip))

        # Handle TCP layer
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
        server_name = self.ip_to_name[server_ip] if server_ip in self.ip_to_name else server_ip
        preamble = '[{}]: '.format(timestamp(pkt_time))
        preamble += '{} -> client'.format(server_name) if from_server else 'client -> {}'.format(server_name)
        if TLSChangeCipherSpec in tls_pkt:
            dbg('{}: Change cipher spec.'.format(preamble))
        elif TLSAlert in tls_pkt:
            dbg('{}: Alert.'.format(preamble))
        elif TLSApplicationData in tls_pkt:
            dbg('{}: {} bytes of data.'.format(preamble, tls_len))
            pkt_info = PacketInfo(pkt_time, tls_len, server_name, from_server)
            self.pkts.append(pkt_info)
        elif TLSClientHello in tls_pkt:
            dbg('{}: Handshake.'.format(preamble))
            shake = tls_pkt[TLSClientHello]
            if ServerName in shake:
                ext_data = shake[ServerName]
                if ext_data.nametype == 0xff:
                    dbg('SNI disable request from {}.'.format(server_ip))
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
        # filter out random analytics hosts
        cluster = list(filter(lambda pkt: not domains.ignore(pkt.host), cluster))
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
            dbg('\t{}'.format(str(pkt)))

    ''' Cluster and print results '''
    def stats(self):
        clusters = self._cluster_within_host()
        for cluster in clusters:
            self._analyze_cluster(cluster)

def setup_interface(args):
    # TODO port to OS besides Ubuntu
    log('Setting network interface to monitor mode. You may lose internet connection for the duration of the program.')
    subprocess.run('airmon-ng check kill'.split(), stdout=subprocess.DEVNULL)
    subprocess.run('airmon-ng start {}'.format(args.interface).split(), stdout=subprocess.DEVNULL)
    args.interface += 'mon'
    subprocess.run('iwconfig {} chan {}'.format(args.interface, args.channel).split(), stdout=subprocess.DEVNULL)

def reset_interface(args):
    # TODO port to OS besides Ubuntu
    log('Resetting network interface.')
    subprocess.run('airmon-ng stop {}'.format(args.interface).split(), stdout=subprocess.DEVNULL)
    args.interface = args.interface[:-3]
    subprocess.run('ip link set dev {} up'.format(args.interface).split(), stdout=subprocess.DEVNULL)
    subprocess.run('service NetworkManager restart'.split(), stdout=subprocess.DEVNULL)

def parse_args():
    parser = argparse.ArgumentParser(description=
            'Sniff and or analyze packet captures to predict browing traffic over HTTPS.')
    parser.add_argument('-i', '--interface', type=str, help=
            'Specifies the interface to sniff on.')
    parser.add_argument('-f', '--file', type=str, help=
            'Specifies a pcap file to read from instead of sniffing WiFi traffic.')
    parser.add_argument('-t', '--target', type=str, help=
            'Specifies a target IP to sniff/analyze.')
    parser.add_argument('-p', '--profile', type=str, help=
            'Specifies a URL to profile.')
    parser.add_argument('-c', '--channel', type=int, default=3, help=
            'Specifies the wireless channel to sniff traffic on.')
    parser.add_argument('--port', type=int, default=443, help=
            'Specifies the port to sniff and analyze traffic on.')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help=
            'Prints debug information.')
    parser.add_argument('-r', '--reset', action='store_true', default=False, help=
            'Resets the interface, in case the program crashed before being able to reset it normally.')
    parser.add_argument('-l', '--list-targets', action='store_true', default=False, help=
            'Scans the channel looking for target IPs.')
    # TODO validate args
    return parser.parse_args()

def main():
    # TODO check that we're running as root
    args = parse_args()
    utils.DEBUG = args.debug
    if args.reset:
        if not 'mon' in args.interface:
            args.interface += 'mon'
        reset_interface(args)
        return

    if args.file:
        # Read packets from file
        pkts = sniff(offline=args.file)
    elif args.profile:
        # Profile a URL
        p = Profiler(args)
        pkts = p.profile()
    elif args.list_targets:
        # Sniff all packets to find
        setup_interface(args)
        log('Listening for targets on interface "{}" on channel {}.'.format(args.interface, args.channel))
        pkts = sniff(iface=args.interface, count=1000, filter='tcp and port {}'.format(args.port))
        reset_interface(args)
        targets = set()
        for pkt in pkts:
            if not IP in pkt:
                continue
            ip_pkt = pkt[IP]
            local_ip = re.compile('192.168.*')
            if local_ip.match(ip_pkt.dst):
                targets.add(ip_pkt.dst)
            if local_ip.match(ip_pkt.src):
                targets.add(ip_pkt.src)
        log('Found {} possible target(s):'.format(len(targets)))
        for target in targets:
            log('\t{}'.format(target))
        return
    else:
        # Sniff packets 
        setup_interface(args)
        log('Listening for HTTPS traffic on interface "{}" on channel {}.'.format(args.interface, args.channel))
        pkts = sniff(iface=args.interface, count=1000, filter='tcp and port {} and host {}'.format(args.port, args.target))
        reset_interface(args)

    # Analyze packets
    analysis = PacketAnalyzer(pkts, args)
    analysis.stats()

if __name__ == '__main__':
    main()

