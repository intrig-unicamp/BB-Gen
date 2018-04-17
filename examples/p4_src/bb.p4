header_type bb_t {
    fields {
        r2 : 16;
        c3 : 8;
        c2 : 8;
    }
}

header bb_t bb;

parser start {
    return parse_bb;
}

parser parse_bb {
    extract(bb);
    return ingress;
}

action _drop() {
    drop();
}

action _nop() {
}

#define NUM_LEARN_RECEIVER 1024

field_list num_learn_digest {
    bb.c3;
    standard_metadata.ingress_port;
}

action num_learn() {
    generate_digest(NUM_LEARN_RECEIVER, num_learn_digest);
}

table c3num {
    reads {
        bb.c3 : exact;
    }
    actions {num_learn; _nop;}
    size : 512;
}

action forward(port) {
    modify_field(standard_metadata.egress_port, port);
}

action bcast() {
    modify_field(standard_metadata.egress_port, 100);

}

table r2num {
    reads {
        bb.r2 : exact;
    }
    actions {forward; bcast;}
    size : 512;
}

control ingress {
    apply(c3num);
    apply(r2num);
}

control egress {
}
