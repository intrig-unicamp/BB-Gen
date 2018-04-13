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

# The pkt_type Class defines the type of pkts to create, the transport protocol UDP/TCP
# and defines the distribution of the data
#
# Protocols -p
# 0	IPv4
# 1	IPv6
# 2	VXLAN
# 3	GRE
# 4	L2
#
# Transport Protol -t
# 0	TCP
# 1	UDP
#
# Random IP, MAC, PORT
# 0	random
# 1	simple

ethernet = [[],[]]
ipv4 = [[],[]]
ipv4_2 = [[],[]]
ipv6 = [[],[]]
udp = [[],[]]
tcp = [[],[]]
vxlan = [[],[]]
arp_t = [[],[]]
arp_ipv4_t = [[],[]]
gre = [[],[]]

class pkt_type:

	def __init__(self, name):
		self.name = name
		self.pktsize = []
		self.protoID = 0
		self.protoName = ""
		self.tra = 0
		self.ranip = 1
		self.ranmac = 1
		self.ranport = 1
		self.dist_name = "simple"
		self.protocol = ""
		self.transport = ""

	def get_prot_type(self, data, tra):
		if data == 'ipv6':
			self.protoID = 1
			self.protoName = data
		elif data == 'vxlan':
			self.protoID = 2
			self.protoName = data
		elif data == 'gre':
			self.protoID = 3
			self.protoName = data
		elif data == 'l2':
			self.protoID = 4
			self.protoName = data
		else: #ipv4
			self.protoID = 0
			self.protoName = "ipv4"

	def get_tra_type(self, data):
		if data == 'udp':
			self.tra = 1
		else:
			self.tra = 0

	def get_random(self, data):
		if data[0] == True:
			self.ranip = 0
			ipname = "rip"
		else:
			self.ranip = 1
			ipname = "sip"
		if data[1] == True:
			self.ranmac = 0
			macname = "rmac"
		else:
			self.ranmac = 1
			macname = "smac"		
		if data[2] == True:
			self.ranport = 0
			portname = "rport"
		else:
			self.ranport = 1
			portname = "sport"
		
		if data[0] == True and data[1] == True and data[2] == True:
			self.dist_name = "random"
		elif data[0] == False and data[1] == False and data[2] == False:
			self.dist_name = "simple"
		else:
			self.dist_name = ipname + "_" + macname + "_" + portname

	def get_prot(self, header_list_len, header_list_val):
		
		header_list = ['l2', 'arp', 'arp', 'ipv4', 'ipv4', 'ipv6', 'udp', 'tcp', 'vxlan', 'gre']

		ethernet[0] = ['48', '48', '16']
		ethernet[1] = ['dstAddr', 'srcAddr', 'etherType']

		ipv4[0] = ['4', '4', '8', '16', '16', '3', '13', '8', '8', '16', '32', '32']
		ipv4[1] = ['version', 'ihl', 'diffserv', 'totalLen', 'identification', 'frag', 'Offset', 'ttl', 'protocol', 'hdrChecksum', 'srcAddr', 'dstAddr']

		ipv4_2[0] = ['8', '8', '16', '16', '16', '8', '8', '16', '32', '32']
		ipv4_2[1] = ['versionIhl', 'diffserv', 'totalLen', 'identification', 'fragOffset', 'ttl', 'protocol', 'hdrChecksum', 'srcAddr', 'dstAddr']

		ipv6[0] = ['4', '8', '20', '16', '8', '8', '128', '128']
		ipv6[1] = ['version', 'trafficClass', 'flowLabel', 'payloadLen', 'nextHdr', 'hopLimit', 'srcAddr', 'dstAddr']

		udp[0] = ['16', '16', '16', '16']
		udp[1] = ['srcPort', 'dstPort', 'length_', 'checksum']

		tcp[0] = ['16', '16', '32', '32', '4', '4', '8', '16', '16', '16']
		tcp[1] = ['srcPort', 'dstPort', 'seqNo', 'ackNo', 'dataOffset', 'res', 'flags', 'window', 'checksum', 'urgentPtr']

		vxlan[0] = ['8', '24', '24', '8']
		vxlan[1] = ['flags', 'reserved', 'vni', 'reserved2']

		arp_t[0] = ['16', '16', '8', '8', '16']
		arp_t[1] = ['htype', 'ptype', 'hlength', 'plength', 'opcode']

		arp_ipv4_t[0] = ['16', '16', '8', '8', '16']
		arp_ipv4_t[1] = ['htype', 'ptype', 'hlength', 'plength', 'opcode']

		gre[0] = ['1', '1', '1', '1', '1', '3', '5', '3', '16']
		gre[1] = ['C', 'R', 'K', 'S', 's', 'recurse', 'flags', 'ver', 'proto']

		headers = [ethernet, arp_t, arp_ipv4_t, ipv4, ipv4_2, ipv6, udp, tcp, vxlan, gre]

		for val in xrange(0,len(headers)):
			for hed in xrange(0,len(header_list_len)):
				if header_list_len[hed] == headers[val][0]:
				 	self.protocol = header_list[val]
				 	if self.protocol == 'tcp':
				 		self.transport = 'tcp'
				 	elif self.protocol == 'udp':
				 		self.transport = 'udp'
