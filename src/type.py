#!/usr/bin/env python

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
