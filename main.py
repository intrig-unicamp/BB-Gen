#!/usr/bin/env python

import os
import string
import sys
import random
from random import shuffle
import argparse

from src.data import *
from src.type import *
from src.packets import *


parser = argparse.ArgumentParser(description='BB-gen PCAP generator')

parser.add_argument('-p', metavar='', help='Type of packet: ipv4, ipv6, vxlan, gre, l2', dest='type', action="store", default='ipv4')
parser.add_argument('-t', metavar='', help='TCP or UDP', dest='transport', action="store", choices=['tcp', 'udp'], default='tcp')
parser.add_argument('-n', metavar='', help='Number of entries', dest='num', action="store", type=int, default=10)
parser.add_argument('-name', metavar='', help='PCAP name', dest='name', action="store", default="test")
parser.add_argument('--rnip', help='Random IP', dest='rnip', action='store_true', default=False)
parser.add_argument('--rnmac', help='Random MAC', dest='rnmac', action='store_true', default=False)
parser.add_argument('--rnport', help='Random Port', dest='rnport', action='store_true', default=False)

parser.add_argument('-A', action='append_const', dest='const_collection',
                    const='value-1-to-append',
                    default=[],
                    help='Add different values to list')

parser.add_argument('-B', action='append_const', dest='const_collection',
                    const='value-2-to-append',
                    help='Add different values to list')
parser.add_argument('-v', action='version', version='BB-gen 1.0')

args = parser.parse_args()

entries = args.num
pname = args.name

if args.rnip == True:
	ranip = 0
else:
	ranip = 1
if args.rnmac == True:
	ranmac = 0
else:
	ranmac = 1
if args.rnport == True:
	ranport = 0
else:
	ranport = 1

#Get Protocol type and transport protocol
e = pkt_type('A')
e.get_prot_type(args.type)
e.get_tra_type(args.transport)

#Get IP, MAC and Port list
f = generator('principal')
f.ip_gen(entries,ranip)
f.mac_gen(entries,ranmac)
f.port_gen(entries,ranport)

g = generator('encap')
g.ip_gen(entries,ranip)
g.mac_gen(entries,ranmac)
g.port_gen(entries,ranport)

print e.tra

#Create PCAP
h = create_pkt('A')
h.pkt_gen(entries, f.macdst, f.macsrc, f.ipdst, f.ipsrc, f.portdst, f.portsrc, e.pktsize, e.prot, e.tra, pname, g.macdst, g.macsrc, g.ipdst, g.ipsrc, g.portdst, g.portsrc)

print f.ipdst
print f.ipsrc
print f.macdst
print f.macsrc
print f.portsrc
print f.portdst

print g.ipdst
print g.ipsrc
print g.macdst
print g.macsrc
print g.portsrc
print g.portdst