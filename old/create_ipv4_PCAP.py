#!/usr/bin/env python

import os
import string
import sys
import random
from random import shuffle
import argparse

from scapy.all import *

#Parse the number of entries
parser = argparse.ArgumentParser(description='IPv4 PCAP generator.')
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
ipdst = []
ipsrc = []
macsrc = []
macdst = []
macsrc_h = []
macdst_h = []
filenames = []
pktsize = [18, 82, 210, 466, 978, 1234, 1472] #Don't update the pktsizes

#The next code generates random IPv6 and MAC address
#########
k = []
for i in range(16):
    k.append(i)
shuffle(k)
r = []
i = 0
for i in range(1,254):
    r.append(i)
shuffle(r)
u = []
i = 0
for i in range(65535):
    u.append(i)
shuffle(u)
v = []
i = 0
for i in range(65535):
    v.append(i)
shuffle(v)
l = 0
macsrc_c = ""
macdst_c = ""
macsrc_hex = ""
macdst_hex = ""
macsrc_hex2 = ""
macdst_hex2 = ""
ipsrc_c = ""
ipdst_c = ""
for m in range(entries):
	macsrc_c = "f0:76:1c:"
	macdst_c = "f0:76:1c:"
	macsrc_hex = "0xf0:0x76:0x1c:"
	macdst_hex = "0xf0:0x76:0x1c:"
	macsrc_hex2 = "f0:76:1c:"
	macdst_hex2 = "f0:76:1c:"
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
	for i in range(4):
		if l == 1:
			ipdst_c = ipdst_c + "." + str(r[0])
			ipsrc_c = ipsrc_c + "." + str(r[1])
			l = 0
		else:
			ipdst_c = ipdst_c + str(r[0])
			ipsrc_c = ipsrc_c + str(r[1])
		l = l + 1
		shuffle(r)
	ipdst.append(ipdst_c)
	ipsrc.append(ipsrc_c)
# print macsrc
# print macdst
# print macsrc_h
# print macdst_h
# print ipdst
# print ipsrc
#########
#mil = 2
first = 0
for i in range(0, 7):
	for j in range(0, mil):
		for p in range(0, entries):
			pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=10,sport=20)/Raw(RandString(size=pktsize[i])))
			#Create trace file
			if f == 0:
				FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 >> PCAP/trace_trPR_ipv4_" + str(entries*mil) + "_random.txt"
				os.system(FILE)
				FILE2 = "echo " + macsrc[p] + " 0 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
				os.system(FILE2)
				FILE2 = "echo " + macdst[p] + " 1 >> PCAP/trace_trPR_l2_" + str(entries) + "_random.txt"
				os.system(FILE2)
		pname = "./PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4) #Update the name depending of the Use-Case, use the same format
		pnamec = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries, pktsize[i]+42+4)
		filenames.append("PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4))
		namef = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)
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

	pnamec = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)
	#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
	os.system(copy)
rem = "rm PCAP/nfpa.trPR_ipv4_%d_random_*"  % (entries)
#os.system(rem)

copy = "scp PCAP/trace_trPR_ipv4_" + str(entries*mil) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
#os.system(copy)
copy = "scp PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
#os.system(copy)

