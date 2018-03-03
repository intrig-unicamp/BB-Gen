#!/usr/bin/env python

import os
import string
import sys
import random
from random import shuffle
import argparse

from scapy.all import *
from src.data import *

parser = argparse.ArgumentParser(description='BB-gen PCAP generator')

parser.add_argument('-p', metavar='', help='Type of packet: ipv4, ipv6, vxlan, gre, l2', dest='type', action="store", default='ipv4')
parser.add_argument('-t', metavar='', help='TCP or UDP', dest='transport', action="store", choices=['tcp', 'udp'], default='tcp')
parser.add_argument('-n', metavar='', help='Number of entries', dest='num', action="store", type=int, default=10)
parser.add_argument('--name', metavar='', help='PCAP name', dest='name', action="store", default="test")

parser.add_argument('-A', action='append_const', dest='const_collection',
                    const='value-1-to-append',
                    default=[],
                    help='Add different values to list')

parser.add_argument('-B', action='append_const', dest='const_collection',
                    const='value-2-to-append',
                    help='Add different values to list')
parser.add_argument('-v', action='version', version='BB-gen 1.0')

args = parser.parse_args()

#Protocols -p
#0	IPv4
#1	IPv6
#2	VXLAN
#3	GRE
#4	L2

if args.type == 'ipv4':
	pktsize = [18, 82, 210, 466, 978, 1234, 1472]
	prot = 0
elif args.type == 'ipv6':
	pktsize = [6, 70, 198, 454, 966, 1222, 1460]
	prot = 1
elif args.type == 'vxlan':
	pktsize = [0, 20, 148, 404, 916, 1172, 1460]
	prot = 21
elif args.type == 'gre':
	pktsize = [0 ,46, 174,430 ,942, 1198, 1436]
	prot = 3
elif args.type == 'l2':
	pktsize = [18, 82, 210, 466, 978, 1234, 1472]
	prot = 4
else:
	pktsize = [18, 82, 210, 466, 978, 1234, 1472]
	prot = 0

#Transport Protol -t
#0	TCP
#1	UDP




print args.type
print args.transport
print args.num
print args.name
print args.const_collection


# e = generator('A')
# e.ip_gen(2)
# e.mac_gen(2)
# e.port_gen(2)
# print e.macsrc
# print e.macdst
# print e.macsrc_h
# print e.macdst_h
# print e.ipdst
# print e.ipsrc

# f = generator('B')
# f.ip_gen(2)
# f.mac_gen(2)
# f.port_gen(2)
# print f.macsrc
# print f.macdst
# print f.macsrc_h
# print f.macdst_h
# print f.ipdst
# print f.ipsrc

#print d.tipo