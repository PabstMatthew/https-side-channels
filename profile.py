from utils import *
from analyze import PacketAnalyzer 
from scapy.all import AsyncSniffer

import subprocess
import os 
import pickle
import time

MAC_SAFARI_USERAGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15'
PIXEL_CHROME_USERAGENT = 'Mozilla/5.0 (Linux; Android 11; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrom/86.0.4240.198 Mobile Safari/537.36'
USERAGENTS = [MAC_SAFARI_USERAGENT]

class Profiler(): 
    def __init__(self, args): 
        self.args = args

    def profile(self):
        url_file = self.args.profile
        with open(url_file, 'r') as f:
            urls = f.read().splitlines()
        sudo_uid = os.getenv("SUDO_UID")
        signatures = []
        for url in urls:
            log('Profiling URL "{}".'.format(url))
            base_cmd = 'sudo -u \\#{} python3 browser.py \'{}\''.format(sudo_uid, url)
            signature = None
            def sample(command):
                nonlocal signature
                sniffer = AsyncSniffer(iface=self.args.interface, 
                                       filter='tcp and port {} and host {}'.format(self.args.port, self.args.target))
                sniffer.start()
                process = subprocess.run(command, shell=True)
                del process
                sniffer.stop()
                results = sniffer.results
                pa = PacketAnalyzer(self.args, results, quiet=True)
                clusters = pa.stats()
                if len(clusters) == 0:
                    log('\tFailed to profile - didn\'t identify any clusters!') 
                    return
                # take the maximum list (unless we're testing caching)
                dbg('\tFound {} clusters in sample.'.format(len(clusters)))
                cluster = max(clusters, key=len)
                new_signature = Signature(cluster)
                if not signature:
                    signature = new_signature
                else:
                    signature.combine(new_signature)

            # sample without caching
            sample(base_cmd)
            sample(base_cmd)
            # sample with caching
            sample(base_cmd+' -c')
            # sample with different user-agents
            for useragent in USERAGENTS:
                sample(base_cmd+" -a '{}'".format(useragent))
            #signature.refine()
            dbg('\tCreated signature: {}'.format(signature))
            signatures.append(signature)

        # now create a mapping from packets to possible urls
        pkt_to_idx = dict()
        for i, signature in enumerate(signatures):
            # see how many times each packet appears across the list of urls
            pkts = signature.pkts
            for pkt, freq in pkts.items():
                if not pkt in pkt_to_idx:
                    pkt_to_idx[pkt] = []
                pkt_to_idx[pkt].append((i, freq))

        # save the data for prediction later
        fname = 'profiles/{}.pkl'.format(self.args.profile.split('.')[0])
        with open(fname, 'wb') as f:
            pickle.dump((urls, pkt_to_idx), f, pickle.HIGHEST_PROTOCOL)

class Predictor():
    def __init__(self, urls, pkt_to_idx):
        self.urls = urls
        self.pkt_to_idx = pkt_to_idx
        for pkt in list(pkt_to_idx.keys()):
            if len(pkt_to_idx[pkt]) > len(urls)*0.25:
                del pkt_to_idx[pkt]

    def predict(self, cluster):
        scores = [0.0] * len(self.urls) # initially zero probability for each url
        for pkt_info in cluster:
            size = pkt_info.size if pkt_info.from_server else -pkt_info.size
            pkt = (pkt_info.host, size)
            if pkt not in self.pkt_to_idx:
                # unrecognized packet, let's just ignore it
                continue
            candidates = self.pkt_to_idx[pkt] 
            #print('packet {}: {}'.format(pkt, str(candidates)))
            p = 1.0/sum(map(lambda x: x[1], candidates))
            for i, freq in candidates:
                scores[i] += p
        max_score = max(scores)
        predictions = sorted(zip(scores, self.urls), reverse=True)
        dbg('Predicted with score {}'.format(predictions[0][0]))
        return [x[1] for x in  predictions[0:5]]

class Signature():
    def __init__(self, cluster):
        self.main_host = cluster[0].host # TODO this is not the case a lot of times, so it'd be good to improve this
        self.pkts = dict()
        for pkt_info in cluster:
            size = pkt_info.size if pkt_info.from_server else -pkt_info.size
            pkt = (pkt_info.host, size)
            self.add_pkt(pkt)
        self.combines = 0

    def add_pkt(self, pkt):
        if not pkt in self.pkts:
            self.pkts[pkt] = 0
        self.pkts[pkt] += 1

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return 'main host: {}, {}'.format(self.main_host, str(self.pkts))

    def combine(self, other):
        self.combines += 1
        for pkt in other.pkts:
            self.add_pkt(pkt)

    def refine(self):
        for pkt in self.pkts.keys():
            self.pkts[pkt] /= (self.combines + 1)

