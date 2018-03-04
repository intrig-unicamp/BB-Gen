BB-gen
===

BB-gen generates a PCAP and Trace files.
The PCAPs can be used for testing together with tools such as NFPA.

usage: main.py [-h] [-p] [-t] [-n] [--name] [-A] [-B] [-v]

BB-gen PCAP generator

optional arguments:
  -h, --help  show this help message and exit
  -p          Type of packet: ipv4, ipv6, vxlan, gre, l2
  -t          TCP or UDP
  -n          Number of entries
  --name      PCAP name
  -A          Add different values to list
  -B          Add different values to list
  -v          show program's version number and exit

BB-gen supports:
- Ethernet
- GRE
- VXLAN
- Icmp
- IcmpV6
- IPv4
- IPv6
- TCP
- UDP

Numerous examples are provided in the example dir.

Example:
