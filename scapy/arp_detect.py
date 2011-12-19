#!/usr/bin/env python
import sys,os
from scapy.all import *

global myIP,myMAC

#arp spoof detecting
def processPacket(pkt):
	srcIP=pkt.psrc
	srcHW=pkt.hwsrc
	arpOp=pkt.op
	print "detekuji->"+srcIP+" "+srcHW+" "+str(arpOp)
	#detect if my IP is spoofing
	if myIP==srcIP and myMAC != srcHW and arpOp==2:
		ls(pkt)
		print "*********************\n "+  "My MAC is spoofed!!!\n " + "**********************"
		sys.exit(1)
		

####################################
#start scapy detect
if len(sys.argv) != 3:
	print "usage: apr_detect my_ip my_mac" 
	sys.exit(1)

if os.getuid() != 0:
	print "Start with root privileges."
	sys.exit(1)

#get my ip
myIP=sys.argv[1]
myMAC=sys.argv[2]

print "Starting ARP spoof detector --> reacting on IP="+myIP+" with MAC="+myMAC
sniff(prn=processPacket,filter="arp",store=0)
