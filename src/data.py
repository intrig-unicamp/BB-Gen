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

# The generator Class creates the list of IP address, MAC address and Port numbers
# with the defined distribution:
#		If dist = 0 Generates randorm distibution
#		If dist = 1 Generates simple distibution

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

	#Generates IP address
	def ip_gen(self, entries, dist, data):
		pkts = []
		r = []
		for i in range(1,254):
		    r.append(i)
		shuffle(r)
		k = []
		for i in range(16):
		    k.append(i)
		shuffle(k)
		ipsrc_c = ""
		ipdst_c = ""
		s = 0
		#For IPv6
		if data == 1:
			for m in range(entries):
				l = 0
				ipsrc_c = ""
				ipdst_c = ""
				for i in range(32):
					if l == 4:
						ipdst_c = ipdst_c + ":" + format(k[0], '01x')
						ipsrc_c = ipsrc_c + ":" + format(k[1], '01x')
						l = 0
					else:
						ipdst_c = ipdst_c + format(k[0], '01x')
						ipsrc_c = ipsrc_c + format(k[1], '01x')
					l = l + 1
					shuffle(k)
				self.ipdst.append(ipdst_c)
				self.ipsrc.append(ipsrc_c)
		#For ipv4
		else:
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
						#Disable main loop for simple traffic
						if dist == 1:
							s = 1
				self.ipdst.append(ipdst_c)
				self.ipsrc.append(ipsrc_c)

	#Generates MAC address
	def mac_gen(self, entries, dist):
		pkts = []
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
					#Disable main loop for simple traffic
					if dist == 1:
						s = 1
			self.macdst.append(macdst_c)
			self.macsrc.append(macsrc_c)
			self.macdst_h.append(macdst_hex)
			self.macsrc_h.append(macsrc_hex)

	#Generates Port numbers from 49152 to 65535
	def port_gen(self, entries, dist):
		u = []
		portsrc_c = 0
		porrdst_c = 0
		for i in range(49152,65535):
		    u.append(i)
		shuffle(u)
		for m in range(entries):
			portsrc_c = u[0]
			porrdst_c = u[1]
			self.portsrc.append(portsrc_c)
			self.portdst.append(porrdst_c)
			#Disable shuffle for simple traffic
			if dist == 0:
				shuffle(u)