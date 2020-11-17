from selenium.webdriver import Firefox, FirefoxProfile
from selenium.webdriver.firefox.options import Options

import argparse
import time

class Browser():
    def __init__(self, useragent=None):
        opts = Options()
        opts.headless = True
        profile = FirefoxProfile()
        if useragent:
            profile.set_preference('general.useragent.override', useragent)
        self.browser = Firefox(profile, options=opts)

    def browse(self, url, times):
        for i in range(times):
            self.browser.get(url)
            time.sleep(2)

    def __del__(self):
        self.browser.quit()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str)
    parser.add_argument('-a', '--useragent', type=str)
    parser.add_argument('-t', '--times', type=int, default=1)
    return parser.parse_args()

def main():
    args = parse_args()
    b = Browser(useragent=args.useragent)
    b.browse(args.url, args.times)

if __name__ == '__main__':
    main()

