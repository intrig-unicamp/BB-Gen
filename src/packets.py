#!/usr/bin/env python

import string
import sys
import random
from random import shuffle
from scapy.all import *

def create_trace(prot, ipdst, ipsrc, macdst, macsrc, entries, mil, p, i):
	if prot == 0:
		FILE = "echo " + str(ipdst[p]) + " " + macdst[p] + " 1 >> PCAP/trace_trPR_ipv4_" + str(entries*mil) + "_random.txt"
		os.system(FILE)
		FILE2 = "echo " + macsrc[p] + " 0 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
		os.system(FILE2)
		FILE2 = "echo " + macdst[p] + " 1 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
		os.system(FILE2)
	if prot == 1:
		FILE = "echo " + str(ipdst[p]) + " " + macdst[p] + " 1 >> PCAP/trace_trPR_ipv6_" + str(entries*mil) + "_random.txt"
		os.system(FILE)
	if prot == 2:
		FILE = "echo " + str(ipdst[p]) + " " + " 1 >> PCAP/trace_trPR_vxlan_" + str(entries*mil) + "_random.txt"
		os.system(FILE)
	if prot == 3:
		#FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 >> PCAP/trace_trPR_ipv4_" + str(entries) + "_random.txt"
		# FILE = "echo " + macsrc_h[p] + " " +  str(ipsrc[p]) + " " + str(ipdst[p])+ " " +str(r[index])+" 1 >> PCAP/trace_trPR_gre_" + str(entries) + "_random.txt"
		FILE = "echo " + macsrc[p] + " " +  str(ipsrc[p]) + " " + str(ipdst[p])+ " 1 >> PCAP/trace_trPR_gre_" + str(entries*mil) + "_random.txt"
		os.system(FILE)
		FILE2 = "echo " + macsrc[p] + " 0 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
		#os.system(FILE2)
		FILE2 = "echo " + macdst[p] + " 1 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
		#os.system(FILE2)
	if prot == 4:
		FILE2 = "echo " + macsrc[p] + " 0 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
		os.system(FILE2)
		FILE2 = "echo " + macdst[p] + " 1 >> PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt"
		os.system(FILE2)
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
							self.pkts.append(Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=10,sport=1)/Raw(RandString(size=pktsize[i])))				
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
							create_trace(prot, ipdst, ipsrc, macdst, macsrc, entries, mil, p, i)


				if prot == 0:
					pname = "./PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4) #Update the name depending of the Use-Case, use the same format
					#pnamec = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries, pktsize[i]+42+4)
					filenames.append("PCAP/nfpa.trPR_ipv4_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4))
					namef = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)
					#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
					#os.system(copy)
				if prot == 1:
					#ipv6
					pname = "./PCAP/nfpa.trPR_ipv6_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+54+4) #Update the name depending of the Use-Case, use the same format
					#pnamec = "PCAP/nfpa.trPR_ipv6_%d_random.%dbytes.pcap" % (entries, pktsize[i]+54+4)
					filenames.append("PCAP/nfpa.trPR_ipv6_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+54+4))
					namef = "PCAP/nfpa.trPR_ipv6_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+54+4)
					#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
				if prot == 2:
					#vxlan
					pname = "./PCAP/nfpa.trPR_vxlan_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4+12+50)
					filenames.append("PCAP/nfpa.trPR_vxlan_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4+12+50))
					namef = "PCAP/nfpa.trPR_vxlan_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4+12+50)
				if prot == 3:
					#gre
					pname = "./PCAP/nfpa.trPR_gre_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+78+4) #Update the name depending of the Use-Case, use the same format
					#pnamec = "PCAP/nfpa.trPR_gre_%d_random.%dbytes.pcap" % (entries, pktsize[i]+42+4)
					#pnamec = "PCAP/nfpa.trPR_gre_%d_random.%dbytes.pcap" % (entries, pktsize[i]+78+4)
					#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
					filenames.append("PCAP/nfpa.trPR_gre_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+78+4))
					namef = "PCAP/nfpa.trPR_gre_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+78+4)
				if prot == 4:
					#l2
					pname = "./PCAP/nfpa.trPR_l2_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4) #Update the name depending of the Use-Case, use the same format
					#pnamec = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries, pktsize[i]+42+4)
					filenames.append("PCAP/nfpa.trPR_l2_%d_random_%d.%dbytes.pcap" % (entries, j, pktsize[i]+42+4))
					namef = "PCAP/nfpa.trPR_l2_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)
					#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
					#os.system(copy)

				wrpcap(pname,self.pkts)
				del self.pkts[:] #Don't delete this line
			
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

			#pnamec = "PCAP/nfpa.trPR_ipv4_%d_random.%dbytes.pcap" % (entries*mil, pktsize[i]+42+4)
			#copy = "scp " + pnamec + " macsad@10.1.1.29:/home/macsad/nfpa/PCAP"
			#os.system(copy)
		remove_copy_pcap(prot, entries)

		#copy = "scp PCAP/trace_trPR_ipv4_" + str(entries*mil) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
		#os.system(copy)
		#copy = "scp PCAP/trace_trPR_l2_" + str(entries*mil) + "_random.txt" + " root@10.1.1.27:/root/Fabricio/mac_ipv6_gyn/traces/"
		#os.system(copy)

