from functools import lru_cache
import re

IGNORE_HOSTS = {
                # Firefox domains that can be ignored (https://wiki.mozilla.org/Websites/Domain_List)
                'cdn.mozilla.net', 
                'services.mozilla.com',
                'spocs.getpocket.com',
                'mozilla.org',
                'safebrowsing.googleapis.com',
                # Apple domains that can be ignored (https://support.apple.com/en-us/HT201999)
                'itunes.apple.com',
                'smoot.apple.com',
                'albert.apple.com',
                'appldnld.apple.com',
                'configuration.apple.com',
                'cdn-apple.com',
                'deimos3.apple.com',
                'gs.apple.com',
                'itunes.apple.com',
                'mesu.apple.com'
                'mzstatic.com',
                'skl.apple.com',
                'swscan.apple.com',
                'xp.apple.com',
                'evintl-ocsp.verisign.com',
                'evsecure.verisign.com',
                'amazonaws.com',
                'digicert.com',
                'symcb.com',
                'symcd.com',
                # Generic Internet hosts
                'cloudfront.net',
                'akamaitechnologies.com',
                '1e100.net',
                }


@lru_cache
def ignore(domain):
    # Checks if a domain should be ignored
    domains = domain.split('.')
    for i in range(len(domains)):
        if '.'.join(domains[i:]) in IGNORE_HOSTS:
            return True
    return False

def split_url(url):
    tokens = re.split('/+', url)
    assert len(tokens) >= 2
    protocol = tokens[0]
    assert protocol == 'http:' or protocol == 'https:'
    domain = tokens[1]
    if len(tokens) == 2:
        resource = ''
    resource = '-'.join(tokens[2:])
    return domain, resource

