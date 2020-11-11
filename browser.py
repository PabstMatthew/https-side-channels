from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options

import sys

class Browser():
    def __init__(self):
        opts = Options()
        opts.headless = True
        self.browser = Firefox(options=opts)

    def browse(self, url):
        self.browser.get(url)

def main():
    b = Browser()
    b.browse(sys.argv[1])

if __name__ == '__main__':
    main()

