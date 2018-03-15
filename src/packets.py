#!/usr/bin/env python

# BSD 3-Clause License

# Copyright (c) 2018, Fabricio Rodriguez, UNICAMP, Brazil
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.

# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.

# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

proto_list = ["ipv4", "ipv6", "vxlan", "gre", "l2"]
plist = list(enumerate(proto_list, start=0))

pkt_size_list_performance = [64, 128, 256, 512, 1024, 1280, 1518]
# pkt_wsize_list = [60, 124, 252, 508, 1020, 1276, 1514]

info_line = 0

#Generates the Traces files
def create_trace(prot, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e, use_case, macsrc_h, macdst_h, tprefix, dist_name, cfile):
	global info_line
	if cfile == 0:
		nfile = ">"
	else:
		nfile = ">>"
	if prot == 0:
		if use_case == "macsad":
			FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 " + nfile + " " + tprefix + "_ipv4_" + str(entries*mil) + "_" + dist_name + ".txt"
			if cfile == 0:
				FILE2 = "echo " + macsrc[p] + " 0 " + nfile + " " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE2)
				FILE2 = "echo " + macdst[p] + " 1 >> " + tprefix + "_l2_" + str(entries) + "_" + dist_name + ".txt"
				os.system(FILE2)
			else:
				FILE2 = "echo " + macsrc[p] + " 0 " + nfile + " " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE2)
				FILE2 = "echo " + macdst[p] + " 1 " + nfile + " " + tprefix + "_l2_" + str(entries) + "_" + dist_name + ".txt"
				os.system(FILE2)
		else:
			if info_line == 0:
				FILE = "echo \"src MAC,dst MAC,src IP,dst IP,src Port,dst Port\" " +  " " + nfile + " " + tprefix + "_ipv4_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + " " + nfile + " " + tprefix + "_ipv4_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 1:
		if use_case == "macsad":
			FILE = "echo " + str(ipdst[p]) + " " + macdst_h[p] + " 1 " + nfile + " " + tprefix + "_ipv6_" + str(entries*mil) + "_" + dist_name + ".txt"
		else:
			if info_line == 0:
				FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port\" " +  "" + nfile + " " + tprefix + "_ipv6_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + " " + nfile + " " + tprefix + "_ipv6_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 2:
		if use_case == "macsad":
			FILE = "echo " + str(ipdst[p]) + " 1 " + nfile + " " + tprefix + "_vxlan_" + str(entries) + "_" + dist_name + ".txt"
		else:
			if info_line == 0:
				FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port, enc src MAC, enc dst MAC, enc src IP, enc dst IP, enc src Port, enc dst Port\" " +  "" + nfile + " " + tprefix + "_vxlan_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(4789) + macsrc_e[p] + "," + macdst_e[p] + "," + str(ipsrc_e[p]) + "," + str(ipdst_e[p]) + "," + str(portsrc_e[p]) + "," + str(portdst_e[p]) + " " + nfile + " " + tprefix + "_vxlan_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 3:
		if use_case == "macsad":
			FILE = "echo " + macsrc_h[p] + " " +  str(ipsrc[p]) + " " + str(ipdst[p]) + " 1 " + nfile + " " + tprefix + "_gre_" + str(entries) + "_" + dist_name + ".txt"
		else:
			if info_line == 0:
				FILE = "echo \"src MAC, dst MAC, src IP, dst IP, src Port, dst Port, enc src MAC, enc dst MAC, enc src IP, enc dst IP, enc src Port, enc dst Port\" " +  "" + nfile + " " + tprefix + "_gre_" + str(entries*mil) + "_" + dist_name + ".txt"
				os.system(FILE)
				info_line = 1
			FILE = "echo " + macsrc[p] + "," + macdst[p] + "," + str(ipsrc[p]) + "," + str(ipdst[p]) + "," + str(portsrc[p]) + "," + str(portdst[p]) + macsrc_e[p] + "," + macdst_e[p] + "," + str(ipsrc_e[p]) + "," + str(ipdst_e[p]) + "," + str(portsrc_e[p]) + "," + str(portdst_e[p]) + " " + nfile + " " + tprefix + "_gre_" + str(entries*mil) + "_" + dist_name + ".txt"
	if prot == 4:
		if info_line == 0:
			FILE = "echo \"src MAC, dst MAC\" " +  "" + nfile + " " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + macsrc[p] + "," + macdst[p] + " " + nfile + " " + tprefix + "_l2_" + str(entries*mil) + "_" + dist_name + ".txt"
	cfile = 1
	os.system(FILE)
	return cfile

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

def create_pkt_hdrs(protoName, p, macdst, macsrc, ipdst, ipsrc, portdst, portsrc, tra, macdst_e, macsrc_e, ipdst_e, ipsrc_e, portdst_e, portsrc_e):
	if protoName == "ipv4":
		if tra == 0:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p],sport=portsrc[p])
		else:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p],sport=portsrc[p])
	elif protoName == "ipv6":
		#ipv6 # If we dont use TCP/UDP, why this if clause is here?
		if tra == 0:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])
		else:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])
	elif protoName == "vxlan":
		pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(sport=portdst[p],dport=4789)/VXLAN(vni=100)/Ether(dst=macdst_e[p],src=macsrc_e[p])/IP(dst=ipdst_e[p],src=ipsrc_e[p])/TCP(dport=portdst_e[p],sport=portsrc_e[p])
	elif protoName == "gre":
		if tra == 0:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p], sport=portsrc[p])
		else:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p], sport=portsrc[p])
	elif protoName == "l2":
		pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])

	return pkt_hdr

class create_pkt:

	def __init__(self, name):
		self.pkts = []


	def pkt_gen(self, entries, pkt_size_list, macdst, macsrc, ipdst, ipsrc, portdst, portsrc, protoID, protoName, tra, pname_arg, macdst_e, macsrc_e, ipdst_e, ipsrc_e, portdst_e, portsrc_e, use_case, usr_data, macsrc_h, macdst_h, dist_name, performance):
		
		mil = 1
		if entries == 1000000:
			entries = 10000
			mil = 100
		f = 0
		filenames = []
		first = 0

		#Enable performance sizes
		if performance == True:
			pkt_size_list = pkt_size_list_performance

		#Set the PCAP and Trace names:
		if pname_arg == "noname":
			pprefix = "./PCAP/nfpa.trPR"
			tprefix = "./PCAP/trace_trPR"
		else:
			pprefix = "./PCAP/" + pname_arg
			tprefix = "./PCAP/" + pname_arg

		# usr_data = "1234"
		cfile = 0
		for val in pkt_size_list:
			pkt_size_proto = 82 if ((protoName=="gre") & (val < 82)) else (114 if ((protoName=="vxlan") & (val < 114)) else val)
			pkt_wsize_proto = pkt_size_proto - 4
			for j in range(0, mil):
				for p in range(0, entries):

					pkt_tmp = create_pkt_hdrs(protoName, p, macdst, macsrc, ipdst, ipsrc, portdst, portsrc, tra, macdst_e, macsrc_e, ipdst_e, ipsrc_e, portdst_e, portsrc_e)

					# print "pkt_wsize_list %d, pkt_tmp len %d, rand string length %d" %(pkt_wsize_list[i], len(pkt_tmp), pkt_wsize_list[i]-len(pkt_tmp))
					if (usr_data==""):
						self.pkts.append(pkt_tmp/Raw(RandString(size=(pkt_wsize_proto-len(pkt_tmp)))))
					else:	
						pkt_tmp = pkt_tmp/Raw(load=usr_data)
						self.pkts.append(pkt_tmp) if (len(pkt_tmp) >= pkt_wsize_proto) else (self.pkts.append(pkt_tmp/Raw(RandString(size=(pkt_wsize_proto-len(pkt_tmp))))))
						pkt_size_proto = len(pkt_tmp) + 4
						
					if f == 0:
						cfile = create_trace(protoID, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e, use_case, macsrc_h, macdst_h, tprefix, dist_name, cfile)

				pname = "%s_%s_%d_%s_%d.%dbytes.pcap" % (pprefix, protoName, entries, dist_name, j, pkt_size_proto)
				namef = "%s_%s_%d_%s.%dbytes.pcap" % (pprefix, protoName, entries*mil, dist_name, pkt_size_proto)

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
