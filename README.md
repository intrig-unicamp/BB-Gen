BB-Gen
===

## About BB-Gen
BB-Gen is simple CLI based packet crafter written in Python over Scapy library to generate packet flows formatted as PCAP files by taking user-defined parameters as inputs based on the headers defined in a P4<sub>14</sub> program. It can natively crafts packets for different standard and custom protocols. It aims to create PCAP files to be used with a wide set of Traffic Generators (e.g., pktgen-dpdk, NFPA, TCPDUMP, etc.) helping network developers to validate the network and execute performance tests over the targets.

[![Build Status](https://travis-ci.org/intrig-unicamp/BB-Gen.svg?branch=master)](https://travis-ci.org/intrig-unicamp/BB-Gen)
[![License: BSD v3](https://img.shields.io/badge/License-BSD%20v3-blue.svg)](LICENSE)

<br>
<hr>
<p align="center">
If you find this useful, please don't forget to star ⭐️ the repo, as this will help to promote the project.<br>
Follow us on <a href="https://github.com/intrig-unicamp?tab=repositories">GitHub</a> to keep updated about this project and others</a>.
</p>
<hr>
<br>

## Installation  
step 1: $ `sudo apt-get install git`  
step 2: $ `git clone --recursive https://github.com/intrig-unicamp/BB-Gen.git`  
step 3: $ `cd BB-Gen`    
step 4: $ `sudo ./dependencies.py`  
step 5: $ `cd p4-hlir`    
step 6: $ `sudo python setup.py install`    
step 7: $ `cd ..`      
step 8: $ `python main.py`  

BB-Gen generates a PCAP and Trace files.
The PCAPs can be used for testing together with tools such as NFPA.

## Usage

    main.py [-h] [-p] [-t] [-n] [-nm] [-rnip] [-rnmac] [-rnport] [-pkt]
            [-p4] [-u] [-udata] [-perf] [-d] [-v]

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
    -p4                   Specify a P4 code to autogenerates the traces
                           Default: none
    -u , --usecase        Use Case:
                           macsad
                           Default: none
    -udata , --userdata   User Specified Data
    -perf, --performance  Performance PCAPs
                           64, 128, 254, 512, 1024, 1280, 1518 pkt size
                           Default: False
    -d, --debug           Debug enable
    -v                    show program's version number and exit

## Running BB-Gen

Designed for simplicity, BB-Gen delivers an intuitive CLI based interface. By specifying only a few flags, can be created a set of traces files.

### Examples:

Generation of 100 vxlan traces with packet size of 64B:

$ `python main.py -p vxlan -n 100`

Generation of random 1k IPv4 traces for performance test:

$ `python main.py -p ipv4 -n 1000 -rnip -rnmac -rnport --performance`

MACSAD use case:

$ `python main.py -u macsad`

Using a P4<sub>14</sub> code to autogenerate 100 traces:

$ `python main.py -p4 examples/p4_src/l3_fwd_ipv6.p4 -n 100`

## Supported Protocols:
  - Ethernet
  - IPv4 / IPv6
  - UDP
  - TCP
  - GRE
  - VXLAN

## Contributing
PRs are very much appreciated. For bugs/features consider creating an issue before sending a PR.

## Team
We are members of [INTRIG (Information & Networking Technologies Research & Innovation Group)](http://intrig.dca.fee.unicamp.br) at University of Campinas - Unicamp, SP, Brazil.
Thanks to all [contributors](https://github.com/intrig-unicamp/BB-Gen/graphs/contributors)!

<!-- Contributors table START -->
| .[<img src="https://avatars.githubusercontent.com/ecwolf?s=100" width="100" alt="Fabricio Rodríguez" /><br /><sub>Fabricio Rodríguez</sub>](https://github.com/ecwolf)<br />(frodri@dca.fee.unicamp.br)<br />[💻](https://github.com/intrig-unicamp/mac/commits?author=ecwolf) 🔌 👀 | .[<img src="https://avatars.githubusercontent.com/c3m3gyanesh?s=100" width="100" alt="Gyanesh Patra" /><br /><sub>Gyanesh Patra</sub>](https://github.com/c3m3gyanesh)<br />(gyanesh@dca.fee.unicamp.br)<br />[💻](https://github.com/intrig-unicamp/mac/commits?author=c3m3gyanesh) 🔌 👀 | .[<img src="https://avatars.githubusercontent.com/chesteve?s=100" width="100" alt="Christian Esteve Rothenberg" /><br /><sub>Christian Esteve Rothenberg</sub>](https://github.com/chesteve)<br />(chesteve@dca.fee.unicamp.br)<br />📢 🎨 |
| :---: | :---: | :---: |
<!-- Contributors table END -->
Team member list is generated by the [all-contributors](https://github.com/kentcdodds/all-contributors) specification ([emoji key](https://github.com/kentcdodds/all-contributors#emoji-key)).

<!--- Fabricio E Rodriguez Cesen (frodri@dca.fee.unicamp.br)  
P Gyanesh Kumar Patra (gyanesh@dca.fee.unicamp.br)  
Christian Rodolfo Esteve Rothenberg (chesteve@dca.fee.unicamp.br)  -->

## Acknowledgments
This work was supported by the Innovation Center, Ericsson Telecomunicações S.A., Brazil under grant agreement UNI.61.
