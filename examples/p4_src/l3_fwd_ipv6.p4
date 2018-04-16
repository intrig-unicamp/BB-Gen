header_type ethernet_t {
  fields {
    dstAddr : 48;
    srcAddr : 48;
    etherType : 16;
  }
}

header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

parser start {
  return parse_ethernet;
}

#define ETHERTYPE_IPV6 0x86DD

header ethernet_t ethernet;

parser parse_ethernet {
  extract(ethernet);
  return select(latest.etherType) {
    ETHERTYPE_IPV6 : parse_ipv6;
    default: ingress;
  }
}

header ipv6_t ipv6;

parser parse_ipv6 {
  extract(ipv6);
  return ingress;
}

action on_miss() {
}

action fib_hit_nexthop(dmac, port) {
  modify_field(ethernet.dstAddr, dmac);
  modify_field(standard_metadata.egress_port, port);
  add_to_field(ipv6.hopLimit, -1);
}

table ipv6_fib_lpm {
  reads {
    ipv6.dstAddr : lpm;
  }
  actions {
    fib_hit_nexthop;
    on_miss;
  }
  size : 512;
}

action rewrite_src_mac(smac) {
  modify_field(ethernet.srcAddr, smac);
}

table sendout {
  reads {
    standard_metadata.egress_port : exact;
  }
  actions {
    on_miss;
    rewrite_src_mac;
  }
  size : 512;
}

control ingress {
/* fib lookup, set dst mac and standard_metadata.egress_port */
  apply(ipv6_fib_lpm);

/* set smac from standard_metadata.egress_port */
  apply(sendout);
}

control egress {
}
