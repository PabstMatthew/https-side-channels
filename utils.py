import time
import datetime

DEBUG = True

BLUE = '\033[94m'
RED = '\033[92m'
BOLD = '\033[1m'
END = '\033[0m'

def dbg(msg, end='\n'):
    if DEBUG:
        print(BLUE+BOLD+'[DBG] '+END+msg, end=end)

def err(msg):
    print(RED+BOLD+'[ERR] '+END+msg)
    assert False

TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'

def tstr_to_posix(tstr):
    if tstr is None:
        date = datetime.datetime.now()
    else:
        tstr = tstr[:tstr.index('.')]
        date = datetime.datetime.strptime(tstr, TIME_FORMAT)
    return time.mktime(date.timetuple())

