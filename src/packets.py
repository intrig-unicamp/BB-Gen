#!/usr/bin/env python

import string
import sys
import random
from random import shuffle
from scapy.all import *

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

info_line = 0

#Generates the Traces files
def create_trace(prot, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, i, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e):
	global info_line
	if prot == 0:
		if info_line == 0:
			FILE = "echo \"src MAC,dst MAC,src IP,dst IP,src Port,dst Port\" " +  ">> PCAP/trace_trPR_ipv4_" + str(entries*mil) + "_random.txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + " >> PCAP/trace_trPR_ipv4_" + str(entries*mil) + "_random.txt"
	if prot == 1:
		if info_line == 0:
			FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port\" " +  ">> PCAP/trace_trPR_ipv6_" + str(entries*mil) + "_random.txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + " >> PCAP/trace_trPR_ipv6_" + str(entries*mil) + "_random.txt"
	if prot == 2:
		if info_line == 0:
			FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port, enc src MAC, enc dst MAC, enc src IP, enc dst IP, enc src Port, enc dst Port\" " +  ">> PCAP/trace_trPR_vxlan_" + str(entries*mil) + "_random.txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + macsrc_e[p] + "," + macdst_e[p] + "," + str(ipsrc_e[p]) + "," + str(ipdst_e[p]) + "," + str(portsrc_e[p]) + "," + str(portdst_e[p]) + " >> PCAP/trace_trPR_vxlan_" + str(entries*mil) + "_random.txt"
	if prot == 3:
		if info_line == 0:
			FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port, enc src MAC, enc dst MAC, enc src IP, enc dst IP, enc src Port, enc dst Port\" " +  ">> PCAP/trace_trPR_gre_" + str(entries*mil) + "_random.txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + macsrc_e[p] + "," + macdst_e[p] + "," + str(ipsrc_e[p]) + "," + str(ipdst_e[p]) + "," + str(portsrc_e[p]) + "," + str(portdst_e[p]) + " >> PCAP/trace_trPR_gre_" + str(entries*mil) + "_random.txt"
	if prot == 4:
		if info_line == 0:
			FILE = "echo \"src MAC, dst MAC\" " +  ">> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + " >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
	os.system(FILE)
	return

def remove_copy_pcap(prot, entries):
	if prot == 0:
		rem = "rm PCAP/nfpa.trPR_ipv4_%d_random_*"  % (entries)
	if prot == 1:
		rem = "rm PCAP/nfpa.trPR_ipv6_%d_random_*"  % (entries)
	if prot == 2:
		rem = "rm PCAP/nfpa.trPR_vxlan_%d_random_*"  % (entries)
	if prot == 3:
		rem = "rm PCAP/nfpa.trPR_gre_%d_random_*"  % (entries)
	if prot == 4:
		rem = "rm PCAP/nfpa.trPR_l2_%d_random_*"  % (entries)
	os.system(rem)
	return

class create_pkt:

	def __init__(self, name):
		self.pkts = []


	def pkt_gen(self, entries, macdst, macsrc, ipdst, ipsrc, portdst, portsrc, pktsize, prot, tra, pname, macdst_e, macsrc_e, ipdst_e, ipsrc_e, portdst_e, portsrc_e):
		mil = 1
		if entries == 1000000:
			entries = 10000
			mil = 100
		f = 0
		filenames = []
		first = 0
		for i in range(0, 7):
			for j in range(0, mil):
				for p in range(0, entries):
					if prot == 0:
						#ipv4
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p],sport=portsrc[p])/Raw(RandString(size=pktsize[i])))				
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p],sport=portsrc[p])/Raw(RandString(size=pktsize[i])))				
					if prot == 1:
						#ipv6
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])/Raw(RandString(size=pktsize[i])))
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])/Raw(RandString(size=pktsize[i])))
					if prot == 2:
						#vxlan
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(sport=portdst[p],dport=portsrc[p])/VXLAN(vni=100)/Ether(dst=macdst_e[p],src=macsrc_e[p])/IP(dst=ipdst_e[p],src=ipsrc_e[p])/TCP(dport=portdst_e[p],sport=portsrc_e[p])/Raw(RandString(size=pktsize[i])))
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(sport=portdst[p],dport=portsrc[p])/VXLAN(vni=100)/Ether(dst=macdst_e[p],src=macsrc_e[p])/IP(dst=ipdst_e[p],src=ipsrc_e[p])/TCP(dport=portdst_e[p],sport=portsrc_e[p])/Raw(RandString(size=pktsize[i])))
					if prot == 3:
						#gre
						if tra == 0:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p], sport=portsrc[p])/Raw(RandString(size=pktsize[i])))
						else:
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p], sport=portsrc[p])/Raw(RandString(size=pktsize[i])))
					if prot == 4:
						#l2
						self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/Raw(RandString(size=pktsize[i])))				
					if f == 0:
							create_trace(prot, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, i, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e)

				if prot == 0:
					#ipv4
					if tra == 0:
						pname = "./PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+12+4) 
						filenames.append("PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+12+4))
						namef = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+12+4)
					else:
						pname = "./PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4) 
						filenames.append("PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4))
						namef = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)
				if prot == 1:
					#ipv6
					pname = "./PCAP/nfpa.trPR_ipv6_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+54+4) 
					filenames.append("PCAP/nfpa.trPR_ipv6_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+54+4))
					namef = "PCAP/nfpa.trPR_ipv6_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+54+4)
				if prot == 2:
					#vxlan
					pname = "./PCAP/nfpa.trPR_vxlan_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4+12+50)
					filenames.append("PCAP/nfpa.trPR_vxlan_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4+12+50))
					namef = "PCAP/nfpa.trPR_vxlan_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4+12+50)
				if prot == 3:
					#gre
					pname = "./PCAP/nfpa.trPR_gre_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+78+4) 
					filenames.append("PCAP/nfpa.trPR_gre_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+78+4))
					namef = "PCAP/nfpa.trPR_gre_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+78+4)
				if prot == 4:
					#l2
					pname = "./PCAP/nfpa.trPR_l2_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4) 
					filenames.append("PCAP/nfpa.trPR_l2_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4))
					namef = "PCAP/nfpa.trPR_l2_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)

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
		remove_copy_pcap(prot, entries)

