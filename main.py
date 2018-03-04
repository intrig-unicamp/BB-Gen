#!/usr/bin/env python

import os
import string
import sys
import random
from random import shuffle
import argparse

from scapy.all import *
from src.data import *
from src.type import *
from src.packets import *


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

entries = args.num
pname = args.name
#Get Protocol type and transport protocol
e = pkt_type('A')
e.get_prot_type(args.type)
e.get_tra_type(args.transport)

#Get IP, MAC and Port list
f = generator('A')
f.ip_gen(entries)
f.mac_gen(entries)
f.port_gen(entries)

#Create PCAP
g = create_pkt('A')
g.pkt_gen(entries, f.macdst, f.macsrc, f.ipdst, f.ipsrc, f.portdst, f.portsrc, e.pktsize, e.prot, e.tra, pname)