#!/usr/bin/env python

import os
import string
import sys
import random
from random import shuffle
import argparse

from scapy.all import *

#Parse the number of entries
parser = argparse.ArgumentParser(description='IPv6 PCAP generator.')
parser.add_argument('num', metavar='n', type=int,
                   help='Number of entries')
args = parser.parse_args()


pkts = []
f = 0
entries = args.num
mil = 1
if entries == 1000000:
	entries = 10000
	mil = 100
#print entries
#print entries*mil
ipdst = []
ipsrc = []
macsrc = []
macdst = []
macsrc_h = []
macdst_h = []
filenames = []
pktsize = [6, 70, 198, 454, 966, 1222, 1460] #Don't update the pktsizes

#The next code generates random IPv6 and MAC address
#########
k = []
for i in range(16):
    k.append(i)
shuffle(k)
u = []
i = 0
for i in range(9000):
    u.append(i)
shuffle(u)
v = []
i = 0
for i in range(9000):
    v.append(i)
shuffle(v)
l = 0
macsrc_c = ""
macdst_c = ""
macsrc_hex = ""
macdst_hex = ""
ipsrc_c = ""
ipdst_c = ""
for m in range(entries):
	macsrc_c = "f0:76:1c:"
	macdst_c = "f0:76:1c:"
	macsrc_hex = "0xf0:0x76:0x1c:"
	macdst_hex = "0xf0:0x76:0x1c:"
	l = 0
	n = 0
	for i in range(6):
		if l == 2:
			n = 0
			macsrc_c = macsrc_c + ":" + format(k[0], '01x')
			macdst_c = macdst_c + ":" + format(k[1], '01x')
			if n == 0:
				macsrc_hex = macsrc_hex + ":" + format(k[0], '#01x')
				macdst_hex = macdst_hex + ":" + format(k[1], '#01x')
				n = 1
			l = 0
		else:
			macsrc_c = macsrc_c + format(k[0], '01x')
			macdst_c = macdst_c + format(k[1], '01x')
			if n == 0:
				macsrc_hex = macsrc_hex + format(k[0], '#01x')
				macdst_hex = macdst_hex + format(k[1], '#01x')
				n = 1
			else:
				macsrc_hex = macsrc_hex + format(k[0], '01x')
				macdst_hex = macdst_hex + format(k[1], '01x')
		l = l + 1
		shuffle(k)
	macdst.append(macdst_c)
	macsrc.append(macsrc_c)
	macdst_h.append(macdst_hex)
	macsrc_h.append(macsrc_hex)
for m in range(entries):
	l = 0
	ipsrc_c = ""
	ipdst_c = ""
	for i in range(32):
		if l == 4:
			ipdst_c = ipdst_c + ":" + format(k[0], '01x')
			ipsrc_c = ipsrc_c + ":" + format(k[1], '01x')
			l = 0
		else:
			ipdst_c = ipdst_c + format(k[0], '01x')
			ipsrc_c = ipsrc_c + format(k[1], '01x')
		l = l + 1
		shuffle(k)
	ipdst.append(ipdst_c)
	ipsrc.append(ipsrc_c)
# print macsrc
# print macdst
# print macsrc_h
# print macdst_h
# print ipdst
# print ipsrc
#########
first = 0
for i in range(0, 7):
	for j in range(0, mil):
		for p in range(0, entries):
			#pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])/TCP(dport=u[p],sport=v[p])/Raw(RandString(size=pktsize[i])))
			pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])/Raw(RandString(size=pktsize[i])))
			#Create trace file
			if f == 0:
				FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 >> PCAP/trace_trPR_ipv6_" + str(entries*mil) + "_random.txt"
				os.system(FILE)
		pname = "./PCAP/nfpa.trPR_ipv6_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+54+4) #Update the name depending of the Use-Case, use the same format
		pnamec = "PCAP/nfpa.trPR_ipv6_%d_random.%dbytes.pcap" % (entries, pktsize[i]+54+4)
		filenames.append("PCAP/nfpa.trPR_ipv6_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+54+4))
		namef = "PCAP/nfpa.trPR_ipv6_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+54+4)
		#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
		wrpcap(pname,pkts)
		#os.system(copy)
		
		del pkts[:] #Don't delete this line
	
	with open(namef, 'w') as outfile:
		for fname in filenames:
			with open(fname) as infile:
				if first == 1:
					infile.seek(24)
				first = 1
				for line in infile:	
					outfile.write(line)	
		first = 0		
	del filenames[:]
	f = 1
	pnamec = "PCAP/nfpa.trPR_ipv6_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+54+4)
	copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
	#os.system(copy)
rem = "rm PCAP/nfpa.trPR_ipv6_%d_random_*"  % (entries)
#os.system(rem)

copy = "scp PCAP/trace_trPR_ipv6_" + str(entries*mil) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
#os.system(copy)


