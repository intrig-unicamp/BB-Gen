BB-Gen
===

BB-Gen generates a PCAP and Trace files.
The PCAPs can be used for testing together with tools such as NFPA.

Usage:  

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

BB-Gen supports:
  - Ethernet
  - IPv4 / IPv6
  - UDP
  - TCP
  - GRE
  - VXLAN

