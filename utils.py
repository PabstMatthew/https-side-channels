from datetime import datetime

DEBUG = True
LOG = True
THRESHOLD = 800 * 1000

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

def timestamp(ts, resol=1000000):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

def segment_times(times):
    if len(times) <= 1:
        return [times]
    times.sort()
    result = []
    segment = []
    for i in range(1, len(times)):
        segment.append(times[i-1])
        diff = (times[i]-times[i-1])
        if diff > THRESHOLD:
            result.append(segment)
            segment = []
    segment.append(times[-1])
    result.append(segment)
    return result

