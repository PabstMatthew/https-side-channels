from utils import *
from analyze import PacketAnalyzer
from domains import split_url

from scapy.all import AsyncSniffer

import subprocess
import os 
import pickle

MAC_SAFARI_USERAGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15'
PIXEL_CHROME_USERAGENT = 'Mozilla/5.0 (Linux; Android 11; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrom/86.0.4240.198 Mobile Safari/537.36'
USERAGENTS = [MAC_SAFARI_USERAGENT, PIXEL_CHROME_USERAGENT]

class Profiler(): 
    def __init__(self, args): 
        self.args = args

    def profile(self):
        url = self.args.profile
        log('Profiling URL "{}".'.format(url))
        sudo_uid = os.getenv("SUDO_UID")
        signature = None
        base = 'sudo -u \\#{} python3 browser.py {}'.format(sudo_uid, url)
        def sample(command, cache=False):
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
                log('Failed to profile - didn\'t identify any clusters!') 
                return
            # take the maximum list (unless we're testing caching)
            dbg('Found {} clusters in sample.'.format(len(clusters)))
            if cache:
                cluster = min(clusters, key=len)
            else:
                cluster = max(clusters, key=len)
            new_signature = Signature(cluster)
            if not signature:
                signature = new_signature
            else:
                signature.combine(new_signature)

        # baseline sample
        sample(base)
        # sample with different user-agents
        for useragent in USERAGENTS:
            sample(base+" -a '{}'".format(useragent))
        # sample with caching
        sample(base+' -t 3')
        signature.refine()

        # save the signature
        domain, resource = split_url(url)
        if resource != '':
            fname = 'profiles/{}-{}.pkl'.format(domain, resource)
        else:
            fname = 'profiles/{}.pkl'.format(domain)
        with open(fname, 'wb') as f:
            pickle.dump(signature, f, pickle.HIGHEST_PROTOCOL)

# Defining this outside the Signature class to allow mutability after pickling
SIGNATURE_MATCH_THRESHOLD = 0.4

class Signature():
    def __init__(self, cluster):
        self.fingerprints = dict()
        self.main_host = cluster[0].host # TODO this is not the case a lot of times, so it'd be good to improve this
        for pkt in cluster:
            if not pkt.host in self.fingerprints:
                self.fingerprints[pkt.host] = Fingerprint()
            self.fingerprints[pkt.host].add(pkt)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return 'main host: {}, {}'.format(self.main_host, str(self.fingerprints))

    def combine(self, other):
        for host in self.fingerprints.keys():
            # refine footprint for this host
            if host in other.fingerprints:
                self.fingerprints[host].combine(other.fingerprints[host])
        for host in other.fingerprints.keys():
            # this host has not been seen yet, so add it
            if not host in self.fingerprints:
                self.fingerprints[host] = other.fingerprints[host]

    def refine(self):
        outlier_hosts = []
        for host, fingerprint in self.fingerprints.items():
            if not fingerprint.combined():
                outlier_hosts.append(host)
            else:
                fingerprint.normalize()
        for host in outlier_hosts:
            # if this host only showed up once, remove it
            del self.fingerprints[host]

    def matches(self, other):
        dbg('Checking if signature matches ...')
        max_score = 0
        score = 0
        for host, fingerprint in self.fingerprints.items():
            max_score += fingerprint.size
            if host in other.fingerprints:
                score += fingerprint.score(other.fingerprints[host])
        result = score/max_score
        if result > SIGNATURE_MATCH_THRESHOLD:
            dbg('\tMatch succeeded with score {}'.format(result))
            return True
        else:
            dbg('\tMatch failed with score {}'.format(result))
            return False

class Fingerprint():
    def __init__(self):
        self.to_server = dict()
        self.from_server = dict()
        self.combines = 0 
        self.size = 0

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return str({'to server': self.to_server, 'from server':self.from_server})

    def inc(self, target, size):
        if not size in target:
            target[size] = 0
        target[size] += 1
        self.size += 1

    def add(self, pkt):
        target = self.from_server if pkt.from_server else self.to_server
        self.inc(target, pkt.size)
        # TODO allow some flexibility in packet sizes

    def combine(self, other):
        self.combines += 1
        my_targets = [self.to_server, self.from_server]
        other_targets = [other.to_server, other.from_server]
        for i in range(2):
            target = my_targets[i]
            other_sizes = other_targets[i].keys()
            for size in other_sizes:
                self.inc(target, size)

    def combined(self):
        return self.combines > 0

    def normalize(self):
        num_samples = self.combines + 1
        targets = [self.to_server, self.from_server]
        for i in range(2):
            target = targets[i]
            for size in target.keys():
                target[size] /= num_samples
        self.size /= num_samples

    def score(self, other):
        result = 0.0
        num_samples = self.combines + 1
        my_targets = [self.to_server, self.from_server]
        other_targets = [other.to_server, other.from_server]
        for i in range(2):
            target = my_targets[i]
            other_target = other_targets[i]
            result += sum(map(lambda item: item[1], 
                              filter(lambda item: item[0] in other_target, target.items())))
        return result
            

