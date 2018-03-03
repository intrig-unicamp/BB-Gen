#!/usr/bin/env python
import os
import string
import sys
import random
from random import shuffle
import argparse

from scapy.all import *


class test:

	# print macsrc
	# print macdst
	# print macsrc_h
	# print macdst_h
	# print ipdst
	# print ipsrc
	def __init__(self, nombre):
		self.nombre = nombre

		pkts = []
		f = 0
		entries = 2
		self.ipdst = []
		self.ipsrc = []
		self.macsrc = []
		self.macdst = []
		self.macsrc_h = []
		self.macdst_h = []
		pktsize = [18, 82, 210, 466, 978, 1234, 1472] #Don't update the pktsizes

		#The next code generates random IPv6 and MAC address
		#########
		k = []
		for i in range(16):
		    k.append(i)
		shuffle(k)
		r = []
		i = 0
		for i in range(1,254):
		    r.append(i)
		shuffle(r)
		u = []
		i = 0
		for i in range(65535):
		    u.append(i)
		shuffle(u)
		v = []
		i = 0
		for i in range(65535):
		    v.append(i)
		shuffle(v)
		l = 0
		macsrc_c = ""
		macdst_c = ""
		macsrc_hex = ""
		macdst_hex = ""
		macsrc_hex2 = ""
		macdst_hex2 = ""
		ipsrc_c = ""
		ipdst_c = ""
		for m in range(entries):
			macsrc_c = "f0:76:1c:"
			macdst_c = "f0:76:1c:"
			macsrc_hex = "0xf0:0x76:0x1c:"
			macdst_hex = "0xf0:0x76:0x1c:"
			macsrc_hex2 = "f0:76:1c:"
			macdst_hex2 = "f0:76:1c:"
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
			self.macdst.append(macdst_c)
			self.macsrc.append(macsrc_c)
			self.macdst_h.append(macdst_hex)
			self.macsrc_h.append(macsrc_hex)
		for m in range(entries):
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
			self.ipdst.append(ipdst_c)
			self.ipsrc.append(ipsrc_c)
