BB-gen
===

BB-gen generates a PCAP and Trace files.
The PCAPs can be used for testing together with tools such as NFPA.

Usage:  

    main.py [-h] [-p] [-t] [-n] [-name] [--rnip] [--rnmac] [--rnport]  
               [--debug] [-A] [-B] [-v]

BB-gen PCAP generator

    optional arguments:  
    -h, --help  show this help message and exit  
    -p          Type of packet: ipv4, ipv6, vxlan, gre, l2  
    -t          TCP or UDP  
    -n          Number of entries  
    -name       PCAP name  
    --rnip      Random IP  
    --rnmac     Random MAC  
    --rnport    Random Port  
    --debug     Debug enable  
    -A          Add different values to list  
    -B          Add different values to list  
    -v          show program's version number and exit  


BB-gen supports:
  - Ethernet
  - ICMP / ICMPv6
  - IPv4 / IPv6
  - UDP
  - TCP
  - GRE
  - VXLAN

Numerous examples are provided in the example dir.

Example:
