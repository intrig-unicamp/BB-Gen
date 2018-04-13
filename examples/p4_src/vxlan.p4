//----------header----------//

header_type ethernet_t {
  fields {
    dstAddr : 48;
    srcAddr : 48;
    etherType : 16;
  }
}

header ethernet_t ethernet;

header_type ipv4_t {
  fields {
    version : 4;
    ihl : 4;
    diffserv : 8;
    totalLen : 16;
    identification : 16;
    flags : 3;
    fragOffset : 13;
    ttl : 8;
    protocol : 8;
    hdrChecksum : 16;
    srcAddr : 32;
    dstAddr: 32;
  }
}

header ipv4_t ipv4;

header_type udp_t {
  fields {
    srcPort : 16;
    dstPort : 16;
    length_ : 16;
    checksum : 16;
  }
}

header udp_t udp;

header_type vxlan_t {
  fields {
    flags : 8;
    reserved : 24;
    vni : 24;
    reserved2 : 8;
  }
}

header vxlan_t vxlan;

header_type arp_t {
  fields {
  htype : 16;
  ptype : 16;
  hlength : 8;
  plength: 8;
  opcode: 16;
  }
}

header arp_t arp;
header ethernet_t inner_ethernet;
header ipv4_t inner_ipv4;

//--------parser---------//

#define MAC_LEARN_RECEIVER     1024
#define ETHERTYPE_IPV4         0x0800
#define ETHERTYPE_ARP          0x0806

#define IP_PROTOCOLS_IPHL_UDP  0x511
#define UDP_PORT_VXLAN         4789

#define BONE 		       1 
#define BTWO      	       2
#define BTHREE	               3

#define BIT_WIDTH              16

parser start {
  return parse_ethernet;
}

parser parse_ethernet {
  extract(ethernet);
  return select(latest.etherType) {
    ETHERTYPE_IPV4 : parse_ipv4;
    ETHERTYPE_ARP : parse_arp;
    default: ingress;
  }
}

parser parse_arp{
  extract(arp);
  return ingress;
}

parser parse_ipv4 {
  extract(ipv4);
  return select(latest.fragOffset, latest.ihl, latest.protocol) {
    IP_PROTOCOLS_IPHL_UDP : parse_udp;
    default: ingress;
  }
}

parser parse_udp {
  extract(udp);
  return select (latest.dstPort) {
    UDP_PORT_VXLAN : parse_vxlan;
    default : ingress;
  }
}

parser parse_vxlan {
  extract(vxlan);
  return parse_inner_ethernet;
}

parser parse_inner_ethernet {
  extract(inner_ethernet);
  return select(latest.etherType) {
    ETHERTYPE_IPV4 : parse_inner_ipv4;
    default: ingress;
  }
}

parser parse_inner_ipv4 {
  extract(inner_ipv4);
  return ingress;
}

//--------action--------//

action _drop() {
  drop();
}

action _nop() {
}

field_list ipv4_checksum_list {
  ipv4.version;
  ipv4.ihl;
  ipv4.diffserv;
  ipv4.totalLen;
  ipv4.identification;
  ipv4.flags;
  ipv4.fragOffset;
  ipv4.ttl;
  ipv4.protocol;
  ipv4.srcAddr;
  ipv4.dstAddr;
}


field_list mac_learn_digest {
  ethernet.srcAddr;
  routing_metadata.ingress_port;
}

field_list inner_ipv4_checksum_list {
  inner_ipv4.version;
  inner_ipv4.ihl;
  inner_ipv4.diffserv;
  inner_ipv4.totalLen;
  inner_ipv4.identification;
  inner_ipv4.flags;
  inner_ipv4.fragOffset;
  inner_ipv4.ttl;
  inner_ipv4.protocol;
  inner_ipv4.srcAddr;
  inner_ipv4.dstAddr;
}

field_list_calculation inner_ipv4_checksum {
  input {
    inner_ipv4_checksum_list;
  }
  algorithm : csum16;
  output_width : 16;
}

action mac_learn() {
  generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table MAClearn {
  reads {
    ethernet.srcAddr : exact;
  }
  actions {
    mac_learn;
    _nop;
  }
  size : 512;
}

header_type routing_metadata_t {
  fields {
    outport: 2;
    res: 2;
    aux : 2;
    egress_port : 2;
    ingress_port : 8;
    lb_hash: 16;
  }
}

metadata routing_metadata_t routing_metadata;

action forward(port, nhop, mac) {
  modify_field(standard_metadata.egress_port, port);
  modify_field(ethernet.dstAddr, mac);
  modify_field(routing_metadata.res, BTHREE);
}

action Tcast() {
  modify_field(routing_metadata.res, BONE);
}

action Tmac() {
  modify_field(routing_metadata.res, BTWO);
}

table MACfwd {
  reads {
    ethernet.dstAddr : exact;
  }
  actions {
    forward;
    _drop;
    Tcast;
    Tmac;
  }
  size : 512;
}

table ownMAC{
  reads {
    ethernet.srcAddr : exact;
  }
  actions {
    _nop;
    forward;
  }
}

action arp() {
  generate_digest(ETHERTYPE_ARP, mac_learn_digest);
  modify_field(routing_metadata.res, BTWO);
}

table ARPselect {
  reads {
    ethernet.etherType: exact;
  }
  actions {
    arp;
    _nop;
  }
  size : 2;
}



action balancer(){
  modify_field(routing_metadata.aux, BONE);
  modify_field(routing_metadata.lb_hash,1);
}

action _pop(){
  modify_field(routing_metadata.aux, BTWO);
}

action jump(){
  modify_field(routing_metadata.aux, BTHREE);
}

table LBselector{
  reads {
    ipv4.dstAddr : exact;
  }
  actions {
    jump;
    _pop;
    balancer;
  }
  size: 128;
}

action _pop_vxlan(){
  remove_header(ethernet);
  remove_header(ipv4);
  remove_header(vxlan);
  modify_field(udp.dstPort, 700);
}

table vpop{
  reads {
    ipv4.srcAddr : exact;
  }
  actions {
    _pop_vxlan;
    _nop;
  }
}

action press(vnid, nhop, srcAddr){
  add_header(vxlan);
  add_header(udp);
  add_header(inner_ipv4);
  copy_header(inner_ipv4, ipv4);
  add_header(inner_ethernet);
  copy_header(inner_ethernet, ethernet);
  
  modify_field(ipv4.dstAddr, nhop);
  modify_field(ipv4.srcAddr, srcAddr);
  modify_field(ipv4.protocol, 0x11);
  modify_field(ipv4.ttl, 64);
  modify_field(ipv4.version, 0x4);
  modify_field(ipv4.ihl, 0x5);
  modify_field(ipv4.identification, 0);
  modify_field(inner_ipv4.totalLen, ipv4.totalLen);
  modify_field(ethernet.etherType, ETHERTYPE_IPV4);
  modify_field(udp.dstPort, UDP_PORT_VXLAN);
  modify_field(udp.checksum, 0);
  modify_field(udp.length_, ipv4.totalLen + 30);	
  modify_field(vxlan.flags, 0x8);
  modify_field(vxlan.reserved, 0);
  modify_field(vxlan.vni, vnid);
  modify_field(vxlan.reserved2, 0);
}

table LB{
  reads {
    ipv4.srcAddr : exact;
  }
  actions {
    press;
    _nop;
  }
  size:1024;
}

action nhop_ipv4(nhop_ipv4) {
  modify_field(ipv4.dstAddr, nhop_ipv4);
}

table LBipv4 {
  reads {
    routing_metadata.lb_hash : exact;
  }
  actions {
    nhop_ipv4;
    _nop;
  }
  size:1024;
}

action nhop(port, dmac){
  modify_field(standard_metadata.egress_port, port);
  modify_field(ethernet.dstAddr, dmac);
  modify_field(ipv4.ttl,ipv4.ttl - 1);
}

table L3{
  reads {
    inner_ipv4.dstAddr : lpm; 
  }
  actions {
    nhop;
    _nop;
  }
}

action rewrite_src_mac(smac) {
  modify_field(ethernet.srcAddr, smac);
}

table sendout {
  reads {
    standard_metadata.egress_port : exact;
  }
  actions {
    _nop;
    rewrite_src_mac;
  }
  size : 512;
}

//-------control-------//

control ingress {
  apply(MAClearn);
  apply(MACfwd);
  if (routing_metadata.res == BONE){
    apply(ARPselect);
  }
  else if (routing_metadata.res == BTWO){
    apply(ownMAC);
    apply(LBselector);
    
    if (routing_metadata.aux == BONE){
      apply(LB);
      apply(LBipv4);
    }
   
    apply(L3);
    apply(sendout); 
    if (routing_metadata.aux == BTWO){
      apply(vpop);
    }
  }
}

control egress {
}

