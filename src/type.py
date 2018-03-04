#!/usr/bin/env python

import string
import sys
import random
from random import shuffle


class pkt_type:

	# print macsrc
	# print macdst
	# print macsrc_h
	# print macdst_h
	# print ipdst
	# print ipsrc
	def __init__(self, name):
		self.name = name
		self.pktsize = []
		self.prot = 0
		self.tra = 0

	def get_prot_type(self, data):
		#Protocols -p
		#0	IPv4
		#1	IPv6
		#2	VXLAN
		#3	GRE
		#4	L2
		if data == 'ipv6':
			self.pktsize = [6, 70, 198, 454, 966, 1222, 1460]
			self.prot = 1
		elif data == 'vxlan':
			self.pktsize = [0, 20, 148, 404, 916, 1172, 1460]
			self.prot = 2
		elif data == 'gre':
			self.pktsize = [0 ,46, 174,430 ,942, 1198, 1436]
			self.prot = 3
		elif data == 'l2':
			self.pktsize = [18, 82, 210, 466, 978, 1234, 1472]
			self.prot = 4
		else:
			self.pktsize = [18, 82, 210, 466, 978, 1234, 1472]
			self.prot = 0

	def get_tra_type(self, data):
		#Transport Protol -t
		#0	TCP
		#1	UDP
		if data == 'udp':
			self.tra = 1
		else:
			self.tra = 0