from datetime import datetime
import socket
import subprocess

DEBUG = True
LOG = True
THRESHOLD = 500 * 1000 # (500 ms)

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

def timestamp(ts):
    return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S.%f')

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

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()
    return IP

def setup_interface(args):
    # TODO port to OS besides Ubuntu
    log('Setting network interface to monitor mode. You may lose internet connection for the duration of the program.')
    subprocess.run('airmon-ng check kill'.split(), stdout=subprocess.DEVNULL)
    subprocess.run('airmon-ng start {}'.format(args.interface).split(), stdout=subprocess.DEVNULL)
    args.interface += 'mon'
    subprocess.run('iwconfig {} chan {}'.format(args.interface, args.channel).split(), stdout=subprocess.DEVNULL)

def reset_interface(args):
    # TODO port to OS besides Ubuntu
    log('Resetting network interface.')
    subprocess.run('airmon-ng stop {}'.format(args.interface).split(), stdout=subprocess.DEVNULL)
    args.interface = args.interface[:-3]
    subprocess.run('ip link set dev {} up'.format(args.interface).split(), stdout=subprocess.DEVNULL)
    subprocess.run('service NetworkManager restart'.split(), stdout=subprocess.DEVNULL)

