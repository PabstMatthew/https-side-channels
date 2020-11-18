import utils
from utils import *
from profile import Profiler, Signature
from analyze import PacketAnalyzer

from scapy.all import sniff
from scapy.layers.inet import IP

import subprocess
import argparse
import pickle
import re

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
    parser.add_argument('-m', '--match', type=str, help=
            'Check for a particular site.')
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

    if args.profile:
        # Profile a URL
        p = Profiler(args)
        p.profile()
        return
    elif args.list_targets:
        # Sniff all packets to find
        if args.file:
            pkts = sniff(offline=args.file)
        else:
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
    elif args.file:
        # Read packets from file
        pkts = sniff(offline=args.file)
    else:
        # Sniff packets 
        setup_interface(args)
        log('Listening for HTTPS traffic on interface "{}" on channel {}.'.format(args.interface, args.channel))
        pkts = sniff(iface=args.interface, count=1000, filter='tcp and port {} and host {}'.format(args.port, args.target))
        reset_interface(args)

    if args.match:
        with open(args.match, 'rb') as f:
            target_signature = pickle.load(f)
        analysis = PacketAnalyzer(args, pkts, quiet=True)
        clusters = analysis.stats()
        for cluster in clusters:
            log('Analyzing cluster of {} packets starting at {} and ending at {}:'.format(
                len(cluster), timestamp(cluster[0].time), timestamp(cluster[-1].time)))
            signature = Signature(cluster)
            if target_signature.matches(signature):
                log('\tCluster matches signature for {}!'.format(args.match))
            else:
                log('\tCluster doesn\'t match signature for {}.'.format(args.match))
    else:
        # Analyze packets
        analysis = PacketAnalyzer(args, pkts)
        analysis.stats()

if __name__ == '__main__':
    main()

