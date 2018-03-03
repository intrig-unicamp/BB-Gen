#!/usr/bin/env python

import os
import string
import sys
import random
from random import shuffle
import argparse
from scapy.packet import *
from scapy.fields import *
from scapy.all import *

class VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [ FlagsField("flags", 0x08, 8, ['R', 'R', 'R', 'I', 'R', 'R', 'R', 'R']),
                    X3BytesField("reserved1", 0x000000),
                    ThreeBytesField("vni", 0),
                    XByteField("reserved2", 0x00)]

    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)
bind_layers(VXLAN, Ether)


#Parse the number of entries
parser = argparse.ArgumentParser(description='IPv4 PCAP generator.')
parser.add_argument('num', metavar='n', type=int,
                   help='Number of entries')
args = parser.parse_args()


pkts = []
f = 0
entries = args.num
ipdst = []
ipsrc = []
macsrc = []
macdst = []
macsrc_h = []
macdst_h = []
pktsize = [0, 20, 148, 404, 916, 1172, 1460] #Don't update the pktsizes

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
	ipsrc_c = str('08') + "." + str('08') + "." + str('08') + "." + str('02')
	ipdst.append(ipdst_c)
	ipsrc.append(ipsrc_c)


# print macsrc
# print macdst
# print macsrc_h
# print macdst_h
# print ipdst
# print ipsrc
#########
i = 0
for i in range(0, 7):
	p = 0
	for p in range(0, entries):
		pkts.append(Ether(dst='06:0f:24:05:92:2c',src= 'a7:3c:48:02:8f:e1')/IP(dst='10.0.0.1',src='10.0.0.11')/UDP(sport=50000,dport=4789)/VXLAN(vni=100)/Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=10,sport=20)/Raw(RandString(size=pktsize[i])))
		#Create trace file
		if f == 0:
			FILE = "echo " + str(ipdst[p]) + " " + " 1 >> PCAP/trace_trPR_vxlan_" + str(entries) + "_random.txt"
			os.system(FILE)
#			FILE2 = "echo " + macsrc[p] + " 0 >> PCAP/trace_trPR_l2_" + str(entries) + "_random.txt"
#			os.system(FILE2)
#			FILE2 = "echo " + macdst[p] + " 1 >> PCAP/trace_trPR_l2_" + str(entries) + "_random.txt"
#			os.system(FILE2)
	pname = "./PCAP/nfpa.trPR_vxlan_%d_random.%dbytes.pcap" % (entries, pktsize[i]+42+4+12+50) #Update the name depending of the Use-Case, use the same format
	pnamec = "PCAP/nfpa.trPR_vxlan_%d_random.%dbytes.pcap" % (entries, pktsize[i]+42+4+12+50)
#	copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
	wrpcap(pname,pkts)
#	os.system(copy)
	del pkts[:] #Don't delete this line
	f = 1
#copy = "scp PCAP/trace_trPR_l2_" + str(entries) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
#os.system(copy)
#copy = "scp PCAP/trace_trPR_ipv4_" + str(entries) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
#os.system(copy)