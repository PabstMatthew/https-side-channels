import time
import datetime

DEBUG = True
LOG = True

BLUE = '\033[94m'
GREEN = '\u001b[32m'
RED = '\033[92m'
BOLD = '\033[1m'
END = '\033[0m'

def dbg(msg, end='\n'):
    if DEBUG:
        print(BLUE+BOLD+'[DBG] '+END+msg, end=end)

def log(msg, end='\n'):
    if LOG:
        print(GREEN+BOLD+'[LOG] '+END+msg, end=end)

def err(msg):
    print(RED+BOLD+'[ERR] '+END+msg)
    assert False

