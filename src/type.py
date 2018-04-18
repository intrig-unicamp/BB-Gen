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
import src.settings 

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
bb = [[],[]]

class pkt_type:

	def __init__(self, name):
		self.name = name
		self.pktsize = []
		self.tra = 0
		self.ranip = 1
		self.ranmac = 1
		self.ranport = 1
		self.dist_name = "simple"
		self.protocol = ""
		self.transport = ""

	def get_prot_type(self, data):
		if data in src.settings.proto_list:
			src.settings.proto_selected = data
		else:
			print "Protocol not supported, using default value: ipv4"


	def get_tra_type(self, data):
		if data == 'udp':
			self.tra = 1
		else:
			self.tra = 0

		src.settings.proto_selected_tr = data


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


		if data[0] == True:
			src.settings.ranip = 0
			ipname = "rip"
		else:
			src.settings.ranip = 1
			ipname = "sip"
		if data[1] == True:
			src.settings.ranmac = 0
			macname = "rmac"
		else:
			src.settings.ranmac = 1
			macname = "smac"		
		if data[2] == True:
			src.settings.ranport = 0
			portname = "rport"
		else:
			src.settings.ranport = 1
			portname = "sport"
		
		if data[0] == True and data[1] == True and data[2] == True:
			src.settings.dist_name = "random"
		elif data[0] == False and data[1] == False and data[2] == False:
			src.settings.dist_name = "simple"
		else:
			src.settings.dist_name = ipname + "_" + macname + "_" + portname

	def get_prot(self, header_list_len):
		
		for val in xrange(0,len(src.settings.headers)):
			for hed in xrange(0,len(header_list_len)):
				if header_list_len[hed] == src.settings.headers[val][0]:
				 	self.protocol = src.settings.header_list[val]
				 	if self.protocol == 'tcp':
				 		self.transport = 'tcp'
				 	elif self.protocol == 'udp':
				 		self.transport = 'udp'

		for val in xrange(0,len(src.settings.headers)):
			for hed in xrange(0,len(header_list_len)):
				if header_list_len[hed] == src.settings.headers[val][0]:
				 	src.settings.proto_p4 = src.settings.header_list[val]
				 	if src.settings.proto_p4 == 'tcp':
				 		src.settings.proto_p4_tr = 'tcp'
				 	elif src.settings.proto_p4 == 'udp':
				 		src.settings.proto_p4_tr = 'udp'

