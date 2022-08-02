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


import os
import string
import sys
import random
from random import shuffle
import argparse
from argparse import ArgumentParser
import subprocess

import src.settings 
from src.data import *
from src.type import *
from src.packets import *
from lib.arg_parse import *
from src.contrib.vxlan import *
# from src.p4_support.transpiler import *
from src.read_burst import *


src.settings.init()

debug_flag = False

def log(s):
    global debug_flag
    if debug_flag == True:
        print(s)

parser = ArgumentParser(description='BB-gen PCAP generator', formatter_class=SmartFormatter)

parser.add_argument('-p','--protocol', metavar='', 
				help="R|Type of packet:\n"
					" ipv4, ipv6, vxlan, gre, l2\n"
					" Default: ipv4", 
					dest='type', action="store", default='ipv4')
parser.add_argument('-t','--tansport', metavar='', 
				help="R|Specifies the transport protocol:\n"
					" tcp or udp\n"
					" For VXLAN and GRE is the encapsulated protocol\n"
					" Default: tcp", 
					dest='transport', action="store", 
					choices=['tcp', 'udp'], default='tcp')
parser.add_argument('-n','--number', metavar='', 
				help="R|Number of entries\n"
					" Default: 10", 
					dest='num', action="store", 
					type=int, default=10)
parser.add_argument('-nm','--name', metavar='', 
				help="R|PCAP name\n"
					" Default: ipv4", 
					dest='name', action="store", 
					default="noname")
parser.add_argument('-rnip',
				help="R|Random IP\n"
					" Default: False", 
					dest='rnip', action='store_true', 
					default=False)
parser.add_argument('-rnmac',
				help="R|Random MAC\n"
					" Default: False", 
					dest='rnmac', action='store_true', 
					default=False)
parser.add_argument('-rnport',
				help="R|Random Port\n"
					" Default: False", dest='rnport', action='store_true', 
					default=False)
parser.add_argument('-pkt','--packetsize',nargs=1, metavar='', 
				help="R|Specify here the required packetsize\n"
					" In case of more than one, separated the list with coma\n"
					" e.g. 64,215,514.\n" 
					" Default: 64",
					dest='packetsizes',
					required=False,
					default=['64'])
parser.add_argument('-p4',metavar='', 
				help="R|Specify a P4 code to autogenerates the traces\n"
					" Default: none", 
					dest='p4_code', action="store", 
					default="none")
parser.add_argument('-u', '--usecase',metavar='', 
				help="R|Use Case:\n"
					" macsad\n"
					" Default: none", 
					dest='use_case', action="store", 
					choices=['macsad'], default="none")
parser.add_argument('-udata', '--userdata', metavar='', 
				help="R|User Specified Data\n", 
					dest='udata', action="store", 
					default="")
parser.add_argument('-perf', '--performance',
				help="R|Performance PCAPs\n"
					" 64, 128, 254, 512, 1024, 1280, 1518 pkt size\n"
					" Default: False", 
					dest='performance', action='store_true', 
					default=False)
parser.add_argument('-b','--burst',metavar='', 
				help='R|Burst PCAP generation', 
					dest='burst', 
					action='store', 
					default="none")
parser.add_argument('-d','--debug', 
				help='Debug enable', 
					dest='debug_flag', 
					action='store_true', 
					default=False)


parser.add_argument('-v', action='version', version='BB-gen 1.0')

args = parser.parse_args()

#Number of Entries
entries = args.num
log("Number of Entries: %s" % (entries))

#PCAP name TODO
pname = args.name
log("PCAP and Trace name: %s" % (pname))

#Select random data
val_random = [args.rnip, args.rnmac, args.rnport] 

#Get Pakcet sizes
packet_sizes = [int(e) for e in (args.packetsizes[0]).split(',')]

#Enable debug
debug_flag = args.debug_flag

#P4 Code
p4_code = args.p4_code

#Use Case
use_case = args.use_case

#Performance 
performance = args.performance

#User specified data
#For this case the packet_sizes should have the default list i.e., ['64']
usr_data = args.udata
packet_sizes = [64]
log("User Specified Data: %s" % (usr_data))

#Get Protocol type, transport protocol and distribution
e = pkt_type('Protocol')

#Burst Code
burst = args.burst

if burst != 'none':
	b = run_getdata('B')
	b.principal(burst)
	p4_code = 'none'
else:
	src.settings.burst_len = [0]
	

#If P4 code is defined, then run the transpiler and get the Protocol
#The Headers information will be stored at src.settings
if p4_code != 'none':
	p = run_transpiler('A')
	p.principal(p4_code)

	e.get_prot(src.settings.header_list_len, src.settings.header_list_val)
	log("List of P4 headers lenght %s" % (src.settings.header_list_len))
	log("List of P4 headers values %s" % (src.settings.header_list_val))

	e.get_tra_type(e.transport)
	log("Transport: %s, reference value: %d" % (e.transport, e.tra))
	e.get_prot_type(e.protocol, e.tra)
	log("Protocol: %s, reference value: %d - %s" % (e.protocol, e.protoID, e.protoName))

#if is not a P4 code input
else:
	e.get_tra_type(args.transport)
	log("Transport: %s, reference value: %d" % (args.transport, e.tra))
	e.get_prot_type(args.type, e.tra)
	log("Protocol: %s, reference value: %d - %s" % (args.type, e.protoID, e.protoName))

e.get_random(val_random)
log("Random IP %s, Random MAC %s, Random Protocol %s" % (val_random[0], val_random[1], val_random[2]))
log("Random data size: %s" % (e.pktsize))

f = generator('principal')
g = generator('encap')
h = create_pkt('A')

for i in range(len(src.settings.burst_len)):
	if burst != 'none':
		entries = src.settings.burst_len[i]
		print(i)
		if src.settings.burst_len[i] == 0:
			continue
	#Get IP, MAC and Port list
	log("Principal Headers info")
	f.ip_gen(entries,e.ranip,e.protoID)
	log("IP source list: \n %s" % (f.ipsrc))
	log("IP destination list: \n %s" % (f.ipdst))
	f.mac_gen(entries,e.ranmac)
	log("MAC source list: \n %s" % (f.macsrc))
	log("MAC destination list: \n %s" % (f.macdst))
	f.port_gen(entries,e.ranport)
	log("Port source list: \n %s" % (f.portsrc))
	log("Port destination list: \n %s" % (f.portdst))

	#Get encapsulated IP, MAC and Port list, for VXLAN and GRE
	log("Encapsulated Headers info")
	g.ip_gen(entries,e.ranip,e.protoID)
	log("IP source list: \n %s" % (g.ipsrc))
	log("IP destination list: \n %s" % (g.ipdst))
	g.mac_gen(entries,e.ranmac)
	log("MAC source list: \n %s" % (g.macsrc))
	log("MAC destination list: \n %s" % (g.macdst))
	g.port_gen(entries,e.ranport)
	log("Port source list: \n %s" % (g.portsrc))
	log("Port destination list: \n %s" % (g.portdst))

	#Create PCAP
	h.pkt_gen(
				entries,
				packet_sizes, 
				f.macdst, 
				f.macsrc, 
				f.ipdst, 
				f.ipsrc, 
				f.portdst, 
				f.portsrc,
				e.protoID,
				e.protoName, 
				e.tra, 
				pname, 
				g.macdst, 
				g.macsrc, 
				g.ipdst, 
				g.ipsrc, 
				g.portdst, 
				g.portsrc,
				use_case,
				usr_data,
				f.macsrc_h,
				f.macdst_h,
				e.dist_name,
				performance,
				burst,
				i
			)
