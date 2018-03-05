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

debug_flag = False

def log(s):
    global debug_flag
    if debug_flag == True:
        print s

parser = argparse.ArgumentParser(description='BB-gen PCAP generator')

parser.add_argument('-p', metavar='', help='Type of packet: ipv4, ipv6, vxlan, gre, l2', dest='type', action="store", default='ipv4')
parser.add_argument('-t', metavar='', help='TCP or UDP', dest='transport', action="store", choices=['tcp', 'udp'], default='tcp')
parser.add_argument('-n', metavar='', help='Number of entries', dest='num', action="store", type=int, default=10)
parser.add_argument('-name', metavar='', help='PCAP name', dest='name', action="store", default="test")
parser.add_argument('--rnip', help='Random IP', dest='rnip', action='store_true', default=False)
parser.add_argument('--rnmac', help='Random MAC', dest='rnmac', action='store_true', default=False)
parser.add_argument('--rnport', help='Random Port', dest='rnport', action='store_true', default=False)
parser.add_argument('--debug', help='Debug enable', dest='debug_flag', action='store_true', default=False)

parser.add_argument('-A', action='append_const', dest='const_collection',
                    const='value-1-to-append',
                    default=[],
                    help='Add different values to list')

parser.add_argument('-B', action='append_const', dest='const_collection',
                    const='value-2-to-append',
                    help='Add different values to list')
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

#Enable debug
debug_flag = args.debug_flag

#Get Protocol type, transport protocol and distribution
e = pkt_type('Protocol')
e.get_tra_type(args.transport)
log("Transport: %s, reference value: %d" % (args.transport, e.tra))
e.get_prot_type(args.type, e.tra)
log("Protocol: %s, reference value: %d" % (args.type, e.prot))
e.get_random(val_random)
log("Random IP %s, Random MAC %s, Random Protocol %s" % (val_random[0], val_random[1], val_random[2]))
log("Random data size: %s" % (e.pktsize))

#Get IP, MAC and Port list
log("Principal Headers info")
f = generator('principal')
f.ip_gen(entries,e.ranip,e.prot)
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
g = generator('encap')
g.ip_gen(entries,e.ranip,e.prot)
log("IP source list: \n %s" % (g.ipsrc))
log("IP destination list: \n %s" % (g.ipdst))
g.mac_gen(entries,e.ranmac)
log("MAC source list: \n %s" % (g.macsrc))
log("MAC destination list: \n %s" % (g.macdst))
g.port_gen(entries,e.ranport)
log("Port source list: \n %s" % (g.portsrc))
log("Port destination list: \n %s" % (g.portdst))

#Create PCAP
h = create_pkt('A')
h.pkt_gen(entries, f.macdst, f.macsrc, f.ipdst, f.ipsrc, f.portdst, f.portsrc, e.pktsize, e.prot, e.tra, pname, g.macdst, g.macsrc, g.ipdst, g.ipsrc, g.portdst, g.portsrc)
