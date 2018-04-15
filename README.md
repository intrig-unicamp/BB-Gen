BB-Gen
===

## About BB-Gen
BB-Gen is simple CLI based packet crafter written in Python over Scapy library. It can natively crafts packets for different standard and custom protocols. It aims to create PCAP files to be used with a wide set of Traffic Generators (e.g., pktgen-dpdk, NFPA, TCPDUMP, etc.) helping network developers to validate the network and execute performance tests over the targets.

[![Build Status](https://travis-ci.org/intrig-unicamp/BB-Gen.svg?branch=master)](https://travis-ci.org/intrig-unicamp/BB-Gen)
[![License: BSD v3](https://img.shields.io/badge/License-BSD%20v3-blue.svg)](LICENSE)

## Installation  
step 1: $ `sudo apt-get install git`  
step 2: $ `git clone https://github.com/intrig-unicamp/BB-Gen.git`  
step 3: $ `cd BB-Gen`    
step 4: $ `sudo ./dependencies.py`  
step 5: $ `python main.py`  

BB-Gen generates a PCAP and Trace files.
The PCAPs can be used for testing together with tools such as NFPA.

## Usage

    main.py [-h] [-p] [-t] [-n] [-nm] [-rnip] [-rnmac] [-rnport] [-pkt]
               [-u] [-udata] [-perf] [-d] [-v]

BB-Gen PCAP generator

    optional arguments:  
    -h, --help            show this help message and exit
    -p , --protocol       Type of packet:
                           ipv4, ipv6, vxlan, gre, l2
                           Default: ipv4
    -t , --tansport       Specifies the transport protocol:
                           tcp or udp
                           For VXLAN and GRE is the encapsulated protocol
                           Default: tcp
    -n , --number         Number of entries
                           Default: 100
    -nm , --name          PCAP name
                           Default: ipv4
    -rnip                 Random IP
                           Default: False
    -rnmac                Random MAC
                           Default: False
    -rnport               Random Port
                           Default: False
    -pkt , --packetsize   Specify here the required packetsize
                           In case of more than one, separated the list with coma
                           e.g. 64,215,514.
                           Default: 64
    -u , --usecase        Use Case:
                           macsad
                           Default: none
    -udata , --userdata   User Specified Data
    -perf, --performance  Performance PCAPs
                           64, 128, 254, 512, 1024, 1280, 1518 pkt size
                           Default: False
    -d, --debug           Debug enable
    -v                    show program's version number and exit

## Supported Protocols:
  - Ethernet
  - IPv4 / IPv6
  - UDP
  - TCP
  - GRE
  - VXLAN

## Team
Fabricio E Rodriguez Cesen (frodri@dca.fee.unicamp.br)  
P Gyanesh Kumar Patra (gyanesh@dca.fee.unicamp.br)  
Christian Rodolfo Esteve Rothenberg (chesteve@dca.fee.unicamp.br)  

We are members of [INTRIG (Information & Networking Technologies Research & Innovation Group)](http://intrig.dca.fee.unicamp.br) at University of Campinas - Unicamp, SP, Brazil.

## Acknowledgments
This work was supported by the Innovation Center, Ericsson Telecomunicações S.A., Brazil under grant agreement UNI.61.
