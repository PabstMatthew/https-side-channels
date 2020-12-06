from utils import *
from analyze import PacketAnalyzer 
from profile import Predictor

from scapy.all import sniff, AsyncSniffer

import os 
import pickle
import subprocess
import time

N = 5

class Sampler(): 
    def __init__(self, args): 
        self.args = args

    def sample(self):
        url_file = self.args.sample
        with open(url_file, 'r') as f:
            urls = f.read().splitlines()
        sudo_uid = os.getenv("SUDO_UID")
        signatures = []
        for url in urls:
            log('Sampling URL "{}".'.format(url))
            base_cmd = 'sudo -u \\#{} python3 browser.py \'{}\''.format(sudo_uid, url)
            for i in range(N):
                sniffer = AsyncSniffer(iface=self.args.interface, 
                                       filter='tcp and port {} and host {}'.format(self.args.port, self.args.target))
                sniffer.start()
                process = subprocess.run(base_cmd, shell=True)
                del process
                sniffer.stop()
                results = sniffer.results
                fname = 'samples/{}-{}.pcap'.format(url.replace('/', '-'), str(i))
                wrpcap(fname, results)

class Evaluation():
    def __init__(self, args):
        self.args = args

    def evaluate(self):
        profile_fname = 'profiles/{}.pkl'.format(self.args.evaluate.split('.')[0])
        if not os.path.exists(profile_fname):
            err('Profile "{}" for evaluation not found!'.format(profile_fname))
        with open(profile_fname, 'rb') as f:
            urls, pkt_to_idx = pickle.load(f)
        predictor = Predictor(urls, pkt_to_idx)
        url_file = self.args.evaluate
        with open(url_file, 'r') as f:
            urls = f.read().splitlines()
        correct = 0
        correct_top5 = 0
        for url in urls:
            for i in range(N):
                if self.args.remote:
                    setup_interface(self.args)
                    sniffer = AsyncSniffer(iface=self.args.interface,
                                           filter='tcp and port {} and host {}'.format(self.args.port, self.args.target))
                    sniffer.start()
                    dbg('Press [Enter] when the browsing finishes.')
                    input()
                    sniffer.stop()
                    pkts = sniffer.results
                    reset_interface(self.args)
                    time.sleep(5)
                else:
                    fname = 'samples/{}-{}.pcap'.format(url.replace('/', '-'), str(i))
                    pkts = sniff(offline=fname)
                analysis = PacketAnalyzer(self.args, pkts, quiet=True)
                clusters = analysis.stats()
                # assuming there's only one cluster
                predictions = predictor.predict(clusters[0])
                top_prediction = predictions[0]
                log('Sample {} of {}: predicted {}'.format(str(i), url, top_prediction))
                if top_prediction == url:
                    correct += 1
                if url in predictions:
                    correct_top5 += 1
        log('Accuracy: {}'.format(str(correct/len(urls)/N)))
        log('Accuracy (top 5): {}'.format(str(correct_top5/len(urls)/N)))

