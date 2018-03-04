#!/usr/bin/env python

import string
import sys
import random
from random import shuffle


class generator:

	def __init__(self, name):
		self.name = name
		self.ipdst = []
		self.ipsrc = []
		self.macsrc = []
		self.macdst = []
		self.macsrc_h = []
		self.macdst_h = []
		self.portsrc = []
		self.portdst = []

	#If dist = 0 Generates randorm IP distibution
	#If dist = 1 Generates simple IP distibution
	def ip_gen(self, entries, dist):
		
		pkts = []
		
		r = []
		for i in range(1,254):
		    r.append(i)
		shuffle(r)
		u = []
		ipsrc_c = ""
		ipdst_c = ""
		s = 0
		for m in range(entries):
			if s == 0:
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
					if dist == 1:
						s = 1
			self.ipdst.append(ipdst_c)
			self.ipsrc.append(ipsrc_c)

	def mac_gen(self, entries, dist):
	
		pkts = []

		#The next code generates random IPv6 and MAC address
		#########
		k = []
		for i in range(16):
		    k.append(i)
		shuffle(k)
		l = 0
		macsrc_c = ""
		macdst_c = ""
		macsrc_hex = ""
		macdst_hex = ""
		s = 0
		for m in range(entries):
			if s == 0:
				macsrc_c = "f0:76:1c:"
				macdst_c = "f0:76:1c:"
				macsrc_hex = "0xf0:0x76:0x1c:"
				macdst_hex = "0xf0:0x76:0x1c:"
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
					if dist == 1:
						s = 1
			self.macdst.append(macdst_c)
			self.macsrc.append(macsrc_c)
			self.macdst_h.append(macdst_hex)
			self.macsrc_h.append(macsrc_hex)

	def port_gen(self, entries, dist):
		u = []
		portsrc_c = ""
		porrdst_c = ""
		for i in range(49152,65535):
		    u.append(i)
		shuffle(u)
		
		for m in range(entries):
			portsrc_c = str(u[0])
			porrdst_c = str(u[1])
			self.portsrc.append(portsrc_c)
			self.portdst.append(porrdst_c)
			if dist == 0:
				shuffle(u)