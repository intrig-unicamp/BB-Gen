header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

header_type vlan_tag_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 12;
        etherType : 16;
    }
}
#define VLAN_DEPTH 1
//header vlan_tag_t vlan_tag_[VLAN_DEPTH];
header vlan_tag_t vlan_tag_0;

header_type intrinsic_metadata_t {
    fields {
		vid : 16;
		vid_valid : 1;
    }
}
metadata intrinsic_metadata_t intrinsic_metadata;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return parse_vlan;
}

parser parse_vlan {
  //  extract(vlan_tag_[0]);
    extract(vlan_tag_0);
//	set_metadata(intrinsic_metadata.vid, vlan_tag_[0].vid);
	set_metadata(intrinsic_metadata.vid, vlan_tag_0.vid);
	set_metadata(intrinsic_metadata.vid_valid, 1);
    return ingress;
}

action _nop() {
}

#define MAC_LEARN_RECEIVER 1024
field_list mac_learn_digest {
    ethernet.srcAddr;
	intrinsic_metadata.vid;
    standard_metadata.ingress_port;
}

action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table smac {
    reads {
        ethernet.srcAddr : exact;
    }
    actions {mac_learn; _nop;}
    size : 512;
}

action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action bcast() {
	modify_field(standard_metadata.egress_port, 100); 
}

table dmac {
    reads {
        ethernet.dstAddr : exact;
        intrinsic_metadata.vid : exact;
    }
    actions {forward; bcast;}
    size : 512;
}

control ingress {
	apply(smac);
	apply(dmac);
}

control egress {
}
