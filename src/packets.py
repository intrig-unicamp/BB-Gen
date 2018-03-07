#!/usr/bin/env python

import string
import sys
import random
from random import shuffle
from scapy.all import *

from contrib.vxlan import *

# The create_pkt class generates the pkts list to be added to the output file
# creates the traces and PCAP from the data.
# If the number of entries is more than 1M the PCAP is going to be splited in
# PCAPs of 10000 entires and then all the files are going to be joined
#
# Protocols prot
# 0	IPv4
# 1	IPv6
# 2	VXLAN
# 3	GRE
# 4	L2

proto_list = ["ipv4", "ipv6", "vxlan", "gre", "l2"]
plist = list(enumerate(proto_list, start=0))

pkt_size_list = [64, 128, 256, 512, 1024, 1280, 1518]

info_line = 0

#Generates the Traces files
def create_trace(prot, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, i, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e, use_case, macsrc_h, macdst_h, tprefix, dist_name):
	global info_line
	if prot == 0:
		if use_case == "macsad":
			FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 >> " + tprefix + "_ipv4_" + str(entries*mil) + "_" + dist_name + ".txt"
			FILE2 = "echo " + macsrc[p] + " 0 >> " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
			os.system(FILE2)
			FILE2 = "echo " + macdst[p] + " 1 >> " + tprefix + "_l2_" + str(entries) + "_" + dist_name + ".txt"
			os.system(FILE2)
		else:
			if info_line == 0:
				FILE = "echo \"src MAC,dst MAC,src IP,dst IP,src Port,dst Port\" " +  " >> " + tprefix + "_ipv4_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + " >> " + tprefix + "_ipv4_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 1:
		if use_case == "macsad":
			FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 >> " + tprefix + "_ipv6_" + str(entries*mil) + "_" + dist_name + ".txt"
		else:
			if info_line == 0:
				FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port\" " +  ">> " + tprefix + "_ipv6_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + " >> " + tprefix + "_ipv6_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 2:
		if use_case == "macsad":
			FILE = "echo " + str(ipdst[p]) + " 1 >> " + tprefix + "_vxlan_" + str(entries) + "_" + dist_name + ".txt"
		else:
			if info_line == 0:
				FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port, enc src MAC, enc dst MAC, enc src IP, enc dst IP, enc src Port, enc dst Port\" " +  ">> " + tprefix + "_vxlan_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(4789) + macsrc_e[p] + "," + macdst_e[p] + "," + str(ipsrc_e[p]) + "," + str(ipdst_e[p]) + "," + str(portsrc_e[p]) + "," + str(portdst_e[p]) + " >> " + tprefix + "_vxlan_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 3:
		if use_case == "macsad":
			FILE = "echo " + macsrc_h[p] + " " +  str(ipsrc[p]) + " " + str(ipdst[p]) + " 1 >> " + tprefix + "_gre_" + str(entries) + "_" + dist_name + ".txt"
		else:
			if info_line == 0:
				FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port, enc src MAC, enc dst MAC, enc src IP, enc dst IP, enc src Port, enc dst Port\" " +  ">> " + tprefix + "_gre_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + macsrc_e[p] + "," + macdst_e[p] + "," + str(ipsrc_e[p]) + "," + str(ipdst_e[p]) + "," + str(portsrc_e[p]) + "," + str(portdst_e[p]) + " >> " + tprefix + "_gre_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 4:
		if info_line == 0:
			FILE = "echo \"src MAC, dst MAC\" " +  ">> " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + " >> " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
	os.system(FILE)
	return

def remove_copy_pcap(fprefix, prot, entries, dist_name):
	if prot == 0:
		rem = "rm %s_ipv4_%d_%s_*"  % (fprefix, entries, dist_name)
	if prot == 1:
		rem = "rm %s_ipv6_%d_%s_*"  % (fprefix, entries, dist_name)
	if prot == 2:
		rem = "rm %s_vxlan_%d_%s_*"  % (fprefix, entries, dist_name)
	if prot == 3:
		rem = "rm %s_gre_%d_%s_*"  % (fprefix, entries, dist_name)
	if prot == 4:
		rem = "rm %s_l2_%d_%s_*"  % (fprefix, entries, dist_name)
	os.system(rem)
	return

class create_pkt:

	def __init__(self, name):
		self.pkts = []


	def pkt_gen(self, entries, macdst, macsrc, ipdst, ipsrc, portdst, portsrc, pktsize, protoID, protoName, tra, pname_arg, macdst_e, macsrc_e, ipdst_e, ipsrc_e, portdst_e, portsrc_e, use_case, macsrc_h, macdst_h, dist_name):
		mil = 1
		if entries == 1000000:
			entries = 10000
			mil = 100
		f = 0
		filenames = []
		first = 0
		#Set the PCAP and Trace names:
		if pname_arg == "test":
			pprefix = "./PCAP/nfpa.trPR"
			tprefix = "./PCAP/trace_trPR"
		else:
			pprefix = "./PCAP/"+ pname_arg
			tprefix = "./PCAP/"+ pname_arg

		for i in range(0, 7):
			for j in range(0, mil):
				for p in range(0, entries):
					if protoName == "ipv4":
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p],sport=portsrc[p])/Raw(RandString(size=pktsize[i])))
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p],sport=portsrc[p])/Raw(RandString(size=pktsize[i])))
					elif protoName == "ipv6":
						#ipv6 # If we dont use TCP/UDP, why this if clause is here?
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])/Raw(RandString(size=pktsize[i])))
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])/Raw(RandString(size=pktsize[i])))
					elif protoName == "vxlan":
						self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(sport=portdst[p],dport=4789)/VXLAN(vni=100)/Ether(dst=macdst_e[p],src=macsrc_e[p])/IP(dst=ipdst_e[p],src=ipsrc_e[p])/TCP(dport=portdst_e[p],sport=portsrc_e[p])/Raw(RandString(size=pktsize[i])))
					elif protoName == "gre":
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p], sport=portsrc[p])/Raw(RandString(size=pktsize[i])))
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p], sport=portsrc[p])/Raw(RandString(size=pktsize[i])))
					elif protoName == "l2":
						self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/Raw(RandString(size=pktsize[i])))

					if f == 0:
							create_trace(protoID, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, i, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e, use_case, macsrc_h, macdst_h, tprefix, dist_name)

				pname = "%s_%s_%d_%s_%d.%dbytes.pcap" % (pprefix, protoName, entries, dist_name, j, pkt_size_list[i])
				namef = "%s_%s_%d_%s.%dbytes.pcap" % (pprefix, protoName, entries*mil, dist_name, pkt_size_list[i])

				filenames.append(pname)

				#Create partials PCAPs
				wrpcap(pname,self.pkts)
				del self.pkts[:] #Don't delete this line

			#Create final PCAP
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

		#Remove temporary files
		remove_copy_pcap(pprefix, protoID, entries, dist_name)
