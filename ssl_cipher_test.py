#!/bin/env python


COUNT = '5'
PORT = '443'
CIPHERS = 'TLSv1+aRSA'
AB = '/usr/bin/ab'
OPENSSL = '/usr/bin/openssl'

DEBUG = 1

import subprocess, sys

from operator import itemgetter

has_check_output = 1
try:
    from subprocess import check_output
except ImportError:
    has_check_output = 0
  
def usage():
    print "\nUsage %s hostname [file]\n" % sys.argv[0]
    sys.exit(0)

def measure_cipher_rate():
    """ Runs the Apache HTTP benchmark tools iteratively over the a subset of ciphers and print their transfer rates."""
    URL = 'https://{0}:{1}/{2}'.format(SERVER, PORT, DATA)

    rates = {}
    count = 1
    if has_check_output:
        openssl_cmd = '{0} ciphers -v {1}'.format(OPENSSL, CIPHERS)
        openssl_out = check_output(openssl_cmd.split())
    else:
        openssl_out = subprocess.Popen([OPENSSL, 'ciphers', '-v', CIPHERS], stdout=subprocess.PIPE).communicate()[0]
        
    ciphers = [c.split()[0] for c in openssl_out.split('\n') if len(c) > 0]
    for cipher in ciphers:
        print count, OPENSSL, "supported ciphers:", cipher
        count += 1
    
    for cipher in ciphers:
        try:
            if DEBUG:
                ab_cmd = '{0} -f tls1 -n {1} -Z {2} {3}'.format(AB, COUNT, cipher, URL)
                print "ab command:", ab_cmd
            if has_check_output:
                ab_cmd = '{0} -f tls1 -n {1} -Z {2} {3}'.format(AB, COUNT, cipher, URL)
                ab_out = check_output(ab_cmd.split(), stderr=file('/dev/null'))
            else:
                ab_out = subprocess.Popen([AB, '-f', 'tls1', '-n', COUNT, '-Z', cipher, URL], stdout=subprocess.PIPE).communicate()[0]
            
            rate_line = [l for l in ab_out.split('\n') if l.startswith('Transfer rate:')][0]
            rates[cipher] = float(rate_line.split(':')[1].split('[')[0].strip())
        except:
            print 'unsupported cipher:', cipher
    count = 1
    for (k, v) in sorted(rates.iteritems(), key=itemgetter(1)):
        print '{0:<3} {1:<30} {2}'.format(count, k, v)
        count += 1


if __name__ == '__main__':
    try:
        DATA = sys.argv[2]
    except:
        DATA = '/'

    try:
        SERVER = sys.argv[1]
    except:
        usage()

    measure_cipher_rate()




