#!/usr/bin/env python
import sys,os
from scapy.all import *

#################################################
#Detektor by Ondrej Kunc
import time

aktokno=time.gmtime()
pocitadlo=0

def detect():
    global aktokno,pocitadlo,limit
    if aktokno!=int(time.time()):
        aktokno=int(time.time())
        pocitadlo=1
    else:
        pocitadlo+=1
        if pocitadlo > limit:
				print "\n*********************\n "+  "SYN requests are above the treshold!!! Actual is "+str(pocitadlo)+"\n" + "**********************"

####################################################
global myIP,myMAC

#arp spoof detecting
def processPacket(pkt):
	synFlag=pkt.flags
	#increment if TCP SYN is detected
	if int(synFlag)==2:
		#print "SYN detekovan"
		detect()

####################################
#start scapy detect
if len(sys.argv) != 2:
	print "usage: treshold" 
	sys.exit(1)

if os.getuid() != 0:
	print "Start with root privileges."
	sys.exit(1)

#get my ip
limit=int(sys.argv[1])


print "SYN flood detection --> starting with treshold "+str(limit)+" req/s"
sniff(prn=processPacket,filter="tcp",store=0)
