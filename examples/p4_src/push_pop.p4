header_type ethernet_t {
    fields {
        dst   : 48;
        src   : 48;
        type_ : 16;
    }
}
header_type vlan_t {
    fields {
        prio  : 3;
        id    : 1;
        vlan  : 12;
        type_ : 16;
    }
}
header_type ipv4_t {
    fields {
        version : 4; 
        ihl     : 4;
        tos     : 8;
        Len     : 16;
        id      : 16;
        flags   : 3;
        frag    : 13;
        ttl     : 8;
        proto   : 8;
        chksum  : 16;
        src     : 32;
        dst     : 32;
    }
}
header ethernet_t ethernet;
header vlan_t vlan_0[3];
header ipv4_t ipv4;

parser start {
    return parse_ethernet;
}
parser parse_ethernet {
    extract(ethernet);
    return select(latest.type_) {
        0x8100  : parse_vlan_0;
        0x0800  : parse_ipv4;
        default : ingress;
    }
}
parser parse_vlan_0 {
    extract(vlan_0[next]);
    return select(latest.type_) {
        0x8100  : parse_vlan_0;
        0x0800  : parse_ipv4;
        default : ingress;
    }
}
parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}


action action_0() {
    pop(vlan_0, 1);
}
table table_0 {
    reads   { ethernet.dst : exact; }
    actions { action_0; }
    size    : 64;
}

action action_1() {
    push(vlan_0, 1);

    modify_field(vlan_0[0].prio, 0);
    modify_field(vlan_0[0].id, 0);
    modify_field(vlan_0[0].vlan, 1);
    modify_field(vlan_0[0].type_, ethernet.type_);
    modify_field(ethernet.type_, 0x8100);
}
table table_1 {
    reads   { ethernet.dst : exact; }
    actions { action_1; }
    size    : 64;
}

control ingress {
    if (valid(vlan_0[1])) {
        apply(table_0);     // pop
    }
    else {
        apply(table_1);     // push
    }
}
