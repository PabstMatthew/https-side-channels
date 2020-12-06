from selenium.webdriver import Firefox, FirefoxProfile
from selenium.webdriver.firefox.options import Options

import argparse
import time

class Browser():
    def __init__(self, useragent=None, cache=False):
        opts = Options()
        opts.headless = True
        profile = FirefoxProfile()
        profile.set_preference("browser.cache.disk.enable", cache)
        profile.set_preference("browser.cache.memory.enable", cache)
        profile.set_preference("browser.cache.offline.enable", cache)
        profile.set_preference("network.http.use-cache", cache)
        if useragent:
            profile.set_preference('general.useragent.override', useragent)
        self.browser = Firefox(profile, options=opts)

    def browse(self, url):
        self.browser.get(url)
        time.sleep(2)

    def __del__(self):
        self.browser.quit()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str)
    parser.add_argument('-a', '--useragent', type=str)
    parser.add_argument('-c', '--cache', action='store_true', default=False)
    return parser.parse_args()

def main():
    args = parse_args()
    b = Browser(useragent=args.useragent, cache=args.cache)
    b.browse(args.url)

if __name__ == '__main__':
    main()

