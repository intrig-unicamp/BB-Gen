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
header vlan_tag_t vlan;

header_type intrinsic_metadata_t {
    fields {
        vlan_vid : 16;
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
    extract(vlan);
//  set_metadata(intrinsic_metadata.vid, vlan_tag_[0].vid);
    set_metadata(intrinsic_metadata.vlan_vid, vlan.vid);
    set_metadata(intrinsic_metadata.vid_valid, 1);
    return ingress;
}

action forward(port) {
    modify_field(standard_metadata.egress_port, port);
}

action broadcast() {
    modify_field(standard_metadata.egress_port, 100);
}

action unt_fwd() {
    remove_header(vlan);

}

action _drop() {
    drop();
}

action _nop() {
}

table isTagd {
    reads {
        intrinsic_metadata.vlan_vid : exact;
    }
    actions {_nop;}
}

table unTag {
    reads {
        intrinsic_metadata.vlan_vid : exact;
    }
    actions {unt_fwd; _drop;}
    size : 512;
}

table fwd {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {forward; broadcast;}
    size : 512;
}

control ingress {
    apply(isTagd){ // if valid(vlan_tag_0)
        hit {
            apply(unTag);
        }
    }
    apply(fwd);
}

control egress {
}
