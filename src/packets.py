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
from contrib.bb import *
import src.settings 

# The create_pkt class generates the pkts list to be added to the output file
# creates the traces and PCAP from the data.
# If the number of entries is more than 1M the PCAP is going to be splited in
# PCAPs of 10000 entires and then all the files are going to be joined
#
# Protocols list
# 0	IPv4
# 1	IPv6
# 2	VXLAN
# 3	GRE
# 4	L2

info_line = 0

#Generates the Traces files
def create_trace(prot, macsrc, macdst, ipsrc, ipdst, portsrc, portdst, entries, mil, p, macsrc_e, macdst_e, ipsrc_e, ipdst_e, portsrc_e, portdst_e, use_case, macsrc_h, macdst_h, tprefix, dist_name, cfile, num_gen):
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
	if prot == 7:
		if info_line == 0:
			FILE = "echo \"r2, c3, c2\" " +  "" + nfile + " " + tprefix + "_bb_" + str(entries*mil) + "_" + dist_name + ".txt"
			os.system(FILE)
			info_line = 1
		FILE = "echo " + str(num_gen[p]) + "," + str(num_gen[p]) + "," + str(num_gen[p]) + " " + nfile + " " + tprefix + "_bb_" + str(entries*mil) + "_" + dist_name + ".txt"
	cfile = 1
	os.system(FILE)
	return cfile

def remove_copy_pcap(fprefix, entries, dist_name):
	rem = "rm %s_%s_%d_%s_*"  % (fprefix, src.settings.proto_selected, entries, dist_name)
	os.system(rem)
	return

def create_pkt_hdrs(protoName, p, macdst, macsrc, ipdst, ipsrc, portdst, portsrc, tra, macdst_e, macsrc_e, ipdst_e, ipsrc_e, portdst_e, portsrc_e, num_gen):
	if protoName == "ipv4":
		if src.settings.proto_selected_tr == 5:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p],sport=portsrc[p])
		else:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p],sport=portsrc[p])
	elif protoName == "ipv6":
		#ipv6 # If we dont use TCP/UDP, why this if clause is here?
		if src.settings.proto_selected_tr == 5:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])
		else:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IPv6(dst=ipdst[p],src=ipsrc[p])
	elif protoName == "vxlan":
		pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/UDP(sport=portdst[p],dport=4789)/VXLAN(vni=100)/Ether(dst=macdst_e[p],src=macsrc_e[p])/IP(dst=ipdst_e[p],src=ipsrc_e[p])/TCP(dport=portdst_e[p],sport=portsrc_e[p])
	elif protoName == "gre":
		if src.settings.proto_selected_tr == 5:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/TCP(dport=portdst[p], sport=portsrc[p])
		else:
			pkt_hdr = Ether(dst=macdst[p],src=macsrc[p])/IP(dst=ipdst[p],src=ipsrc[p])/GRE()/IP(dst=ipdst[p],src=ipsrc[p])/UDP(dport=portdst[p], sport=portsrc[p])
	elif protoName == "bb":
		pkt_hdr = BB(r2=num_gen[p],c3=num_gen[p],c2=num_gen[p])

	else:
		l2_data = [macdst,macsrc]
		# print l2_data
		sclass = []
		layers = scapy.config.Conf.layers
		hdrlist = src.settings.proto_list_temp[protoName][1]

		#selecting TCP/UDP header
		if 'trL' in hdrlist:
			if (src.settings.proto_selected_tr==5):
				hdrlist[hdrlist.index('trL')] = src.settings.tcpL
			#add code for UDP
			if (src.settings.proto_selected_tr==6):
				hdrlist[hdrlist.index('trL')] = src.settings.udpL
		print hdrlist

		#Create list of headers required for the user specified protocol
		for protoName,fieldList in hdrlist:
			for i in range(len(layers)):
				str2 = str(layers[i])
				str3 = str2.split('.', str2.count('.'))
				str4 = str3[str2.count('.')].split('\'', 1 )
				if protoName == str4[0]:
					# print "found %i %s" % (i,str4[0])
					sclass.append(layers[i])
		print "sclass is %s" %(sclass)

		#creating the layers for packet header
		pkt_hdr = sclass[0]()
		for i in range(len(sclass)):
			if i > 0:
				pkt_hdr =  pkt_hdr/sclass[i]()
		# print pkt_hdr.show(dump=True)

		#Updating the header fields
		print "preparing hdr fields"
		for protoName,fieldList in hdrlist:
			# print "protocol %s and fields %s" % (protoName, fieldList)
			for i in range(len(fieldList)):
				setattr(pkt_hdr[protoName], fieldList[i], l2_data[i][p])
		print "updated" + pkt_hdr.show(dump=True)	

	return pkt_hdr

class create_pkt:

	def __init__(self, name):
		self.pkts = []

	def pkt_gen(self, values_main, values_encap):
		entries = src.settings.entries
		mil = 1
		if entries == 1000000:
			entries = 10000
			mil = 100
		f = 0
		filenames = []
		first = 0

		#Enable performance sizes
		if src.settings.performance == True:
			src.settings.packet_sizes = src.settings.pkt_size_list_performance

		#Set the PCAP and Trace names:
		if src.settings.pname == "noname":
			pprefix = "./PCAP/nfpa.trPR"
			tprefix = "./PCAP/trace_trPR"
		else:
			pprefix = "./PCAP/" + src.settings.pname
			tprefix = "./PCAP/" + src.settings.pname

		# usr_data = "1234"
		cfile = 0
		for val in src.settings.packet_sizes:
			pkt_size_proto = 82 if ((src.settings.proto_selected=="gre") & (val < 82)) else (114 if ((src.settings.proto_selected=="vxlan") & (val < 114)) else val)
			pkt_wsize_proto = pkt_size_proto - 4
			for j in range(0, mil):
				for p in range(0, entries):

					pkt_tmp = create_pkt_hdrs(src.settings.proto_selected, p, values_main.macdst, values_main.macsrc, values_main.ipdst, values_main.ipsrc, values_main.portdst, values_main.portsrc, src.settings.proto_selected_tr, values_encap.macdst, values_encap.macsrc, values_encap.ipdst, values_encap.ipsrc, values_encap.portdst, values_encap.portsrc, values_main.num)

					# print "pkt_wsize_list %d, pkt_tmp len %d, rand string length %d" %(pkt_wsize_list[i], len(pkt_tmp), pkt_wsize_list[i]-len(pkt_tmp))
					if (src.settings.usr_data==""):
						self.pkts.append(pkt_tmp/Raw(RandString(size=(pkt_wsize_proto-len(pkt_tmp)))))
					else:	
						pkt_tmp = pkt_tmp/Raw(load=src.settings.usr_data)
						self.pkts.append(pkt_tmp) if (len(pkt_tmp) >= pkt_wsize_proto) else (self.pkts.append(pkt_tmp/Raw(RandString(size=(pkt_wsize_proto-len(pkt_tmp))))))
						pkt_size_proto = len(pkt_tmp) + 4
						
					if f == 0:
						cfile = create_trace(src.settings.proto_list[src.settings.proto_selected], values_main.macsrc, values_main.macdst, values_main.ipsrc, values_main.ipdst, values_main.portsrc, values_main.portdst, entries, mil, p, values_encap.macsrc, values_encap.macdst, values_encap.ipsrc, values_encap.ipdst, values_encap.portsrc, values_encap.portdst, src.settings.use_case, values_main.macsrc_h, values_main.macdst_h, tprefix, src.settings.dist_name, cfile, values_main.num)

				pname = "%s_%s_%d_%s_%d.%dbytes.pcap" % (pprefix, src.settings.proto_selected, entries, src.settings.dist_name, j, pkt_size_proto)
				namef = "%s_%s_%d_%s.%dbytes.pcap" % (pprefix, src.settings.proto_selected, entries*mil, src.settings.dist_name, pkt_size_proto)

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
		remove_copy_pcap(pprefix, entries, src.settings.dist_name)
