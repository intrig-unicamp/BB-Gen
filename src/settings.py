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


#Definition and initialization all global variables
def init():

    #Input args
    global entries
    global pname
    global val_random
    global packet_sizes
    global debug_flag
    global p4_code
    global use_case
    global performance
    global usr_data

    #P4 Header list
    global header_list_len
    global header_list_val

    #Protocols supported
    global proto_list

    #Protocol selected
    global proto_selected
    global proto_selected_tr
    global proto_p4
    global proto_p4_tr

    #Distribution
    global dist_name
    global ranip
    global ranmac
    global ranport

    #Performance pkt sizes
    global pkt_size_list_performance

    #P4 Protocol definition
    global header_list
    global headers

    #Initial arguments
    entries = 10
    pname = ''
    val_random = []
    packet_sizes = []
    debug_flag = ''
    p4_code = ''
    use_case = ''
    performance = False
    usr_data = ''

    #P4 Header list
    header_list_len = []
    header_list_val = []

    #Supported protocols list
    proto_list = {
                'ipv4': 0,
                'ipv6': 1,
                'vxlan': 2,
                'gre': 3,
                'l2': 4,
                'tcp': 5,
                'udp': 6,
                'bb': 7}

    #Default values
    proto_selected = 'ipv4'
    proto_selected_tr = 1
    dist_name = 'simple'
    proto_p4 = ''
    proto_p4_tr = 'tcp'
    dist_name = "simple"
    ranip = 1
    ranmac = 1
    ranport = 1

    #Performance pkt sizes
    pkt_size_list_performance = [64, 128, 256, 512, 1024, 1280, 1518]

    #Protocol definition - for P4 use cases
    #Add the definition of the fields of the new protocol and include in headers and header_list

    ethernet = [['48', '48', '16'],
                ['dstAddr', 'srcAddr', 'etherType']]

    ipv4 = [['4', '4', '8', '16', '16', '3', '13', '8', '8', '16', '32', '32'],
            ['version', 'ihl', 'diffserv', 'totalLen', 'identification', 'frag', 'Offset', 'ttl', 'protocol', 'hdrChecksum', 'srcAddr', 'dstAddr']]

    ipv4_2 = [['8', '8', '16', '16', '16', '8', '8', '16', '32', '32'],
                ['versionIhl', 'diffserv', 'totalLen', 'identification', 'fragOffset', 'ttl', 'protocol', 'hdrChecksum', 'srcAddr', 'dstAddr']]

    ipv6 = [['4', '8', '20', '16', '8', '8', '128', '128'],
            ['version', 'trafficClass', 'flowLabel', 'payloadLen', 'nextHdr', 'hopLimit', 'srcAddr', 'dstAddr']]

    udp = [['16', '16', '16', '16'],
            ['srcPort', 'dstPort', 'length_', 'checksum']]

    tcp = [['16', '16', '32', '32', '4', '4', '8', '16', '16', '16'],
            ['srcPort', 'dstPort', 'seqNo', 'ackNo', 'dataOffset', 'res', 'flags', 'window', 'checksum', 'urgentPtr']]

    vxlan = [['8', '24', '24', '8'],
            ['flags', 'reserved', 'vni', 'reserved2']]

    arp_t = [['16', '16', '8', '8', '16'],
            ['htype', 'ptype', 'hlength', 'plength', 'opcode']]

    arp_ipv4_t = [['16', '16', '8', '8', '16'],
                    ['htype', 'ptype', 'hlength', 'plength', 'opcode']]

    gre = [['1', '1', '1', '1', '1', '3', '5', '3', '16'],
            ['C', 'R', 'K', 'S', 's', 'recurse', 'flags', 'ver', 'proto']]

    bb = [['16', '8', '8'],
            ['r2', 'c3', 'c2']]

    headers     = [ethernet, arp_t, arp_ipv4_t, ipv4,   ipv4_2, ipv6,   udp,   tcp,   vxlan,   gre,   bb]
    header_list = ['l2',     'arp', 'arp',      'ipv4', 'ipv4', 'ipv6', 'udp', 'tcp', 'vxlan', 'gre', 'bb']

    global ethL
    global tcpL

    ipL    = ['IP',['dst','src']]
    ip6L   = ['IPv6',['dst','src']]
#     vxlanL = [['VXLAN',['vni']],[100]]
#     greL   = [['GRE',[]],[]]
#     ethL   = [['Ether',['dst','src']],[macdst,macsrc]]
    ethL   = ['Ether',['dst','src']]
    tcpL   = ['TCP',['dport','sport']]
    udpL   = ['UDP',['dport','sport']]
    bbL    = ['BB',['r2','c3','c2']]

    global proto_list_temp
    proto_list_temp = {
    				'ipv4': [0,[ethL,ipL,'trL']],
    				'ipv6': [1,[ethL,ip6L,'trL']],
    				# 'vxlan': [2,[ethL]],
    				# 'gre': [3,[ethL]],
    				'l2': [4,[ethL]],
    				# 'tcp': [5,[ethL]],
    				# 'udp': [6,[ethL]],
    				'bb': [7,[bbL]]}
