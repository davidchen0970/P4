/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_RDH = 0x1212;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header RDH_t {
    bit<2> name;
    bit<6> isDup;
    bit<8> ackNum;
    bit<8> packetNum;
    bit<8> CPUackNum;
    bit<8> CPUpacketNum;
    bit<8> CPUvalidNum;
    bit<8> isRCV;
}

struct metadata {
    bit<8> pkt_tx_counter_reg;
    bit<8> pkt_tx_ack_reg;    
    bit<8> pkt_rx_counter_reg;
    bit<8> pkt_rx_valid_reg;
    bit<8> pkt_rx_ack_reg;
}


struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    RDH_t       RDH;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_RDH: parse_RDH;
            default: accept;
        }
    }

    state parse_RDH {
        packet.extract(hdr.RDH);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state start {
        transition parse_ethernet;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   **************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            true, 
            {
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /* ---- register ---- */
    register<bit<8>>(1) pkt_tx_counter_reg;
    register<bit<8>>(1) pkt_tx_ack_reg;    
    // count raw packet num
    register<bit<8>>(1) pkt_rx_counter_reg;
    // count ack packet num
    register<bit<8>>(1) pkt_rx_valid_reg;
    // record ack and check one packet is redundent
    register<bit<8>>(1) pkt_rx_ack_reg;

    /* ------ action ------ */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action add_tx_counter(bit <6> num) {
        bit<8> count;
        pkt_tx_counter_reg.read(count, 0);
        pkt_tx_counter_reg.write(0, count + (bit<8>)num);
    }

    action add_tx_ack() {
        bit<8> count;
        pkt_tx_ack_reg.read(count, 0);
        pkt_tx_ack_reg.write(0, count + 1);
    }


    action add_rx_counter() {
        bit<8> count;
        pkt_rx_counter_reg.read(count, 0);
        pkt_rx_counter_reg.write(0, count + 1);
    }

    action add_rx_valid() {
        bit<8> valid;
        pkt_rx_valid_reg.read(valid, 0);
        pkt_rx_valid_reg.write(0, valid + 1);
    }

    action isRCVReturnInfo(inout bit<2> isReturn) {
        bit<8> rx_ack;
        pkt_rx_ack_reg.read(rx_ack, 0);

        if(standard_metadata.instance_type == 0 &&
            (rx_ack == 0 || ( 0 < rx_ack && rx_ack<5 && rx_ack > 60))) {
            isReturn = 1;
        }
        else {
            isReturn = 0;
        }
    }

    action isSNDReturnInfo(inout bit<2> isReturn) {
        bit<8> tx_ack;
        pkt_tx_ack_reg.read(tx_ack, 0);
        if(standard_metadata.instance_type == 0 && tx_ack == 0) {
            isReturn = 1;
        }
        else {
            isReturn = 0;
        }
    }

    action insert_rx_cpuInfo() {
        hdr.RDH.CPUackNum = 0;
        hdr.RDH.CPUpacketNum = 0;
    }

    action insert_tx_cpuInfo() {
        hdr.RDH.CPUackNum = 0;
        hdr.RDH.CPUpacketNum = 0;
    }

    action handle_rx(inout bit<2>isDuplicated,inout bit<8> tx_ack) {
        bit<8> rx_ack;
        pkt_rx_ack_reg.read(rx_ack, 0);
        if(tx_ack > rx_ack || rx_ack >= 250 && tx_ack < 2) {
            isDuplicated = 0;
        }
        else{
            isDuplicated = 1;
        }
    }

    action insert_dupHeader(bit<6> dup_rate){
        bit<8> count;
        pkt_tx_ack_reg.read(count, 0);
        hdr.RDH.isDup = dup_rate;
        hdr.RDH.ackNum = count;
    }

    action multicast(bit<16> mcast_grp_id) {
        bit<8> count;
        standard_metadata.mcast_grp = mcast_grp_id;
        pkt_tx_counter_reg.read(count, 0);
        count = count + (bit<8>)mcast_grp_id;
        pkt_tx_counter_reg.write(0, count);
    }




    table ipv4_lpm {
        actions = {
            ipv4_forward;
            drop;
        }

        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 512;
        const default_action = drop();
    }

    table dup_rate_table {
        actions = {
            insert_dupHeader;
        }
        key = {
            hdr.ethernet.etherType: exact;
        }
        size = 512;
        default_action = insert_dupHeader(1);
    }

    table dup_multicast {
        key = {
            hdr.RDH.isDup: exact;
            standard_metadata.ingress_port: exact;
        }

        actions = {
            multicast;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply{
        hdr.RDH.setValid();
        if (hdr.ethernet.etherType == TYPE_RDH) {
            add_rx_counter();

            bit<2> ackIsDup = 0;
            handle_rx(ackIsDup, hdr.RDH.ackNum);
            if(ackIsDup == 1)  drop(); 
            else {
                add_rx_valid();
                pkt_rx_ack_reg.write(0, hdr.RDH.ackNum);
                hdr.ethernet.etherType = TYPE_IPV4;
                hdr.RDH.setInvalid();
                clone3(CloneType.I2E,100, meta);
            }
        }
        else {
            dup_rate_table.apply();
            add_tx_ack();
            add_tx_counter(hdr.RDH.isDup);
            dup_multicast.apply();
            hdr.ethernet.etherType = TYPE_RDH;
            clone3(CloneType.I2E,100, meta);
            // p4_logger(hdr.RDH.isDup);
        }
        
        pkt_tx_counter_reg.read(meta.pkt_tx_counter_reg, 0);
        pkt_tx_ack_reg.read(meta.pkt_tx_ack_reg, 0);
        pkt_rx_counter_reg.read(meta.pkt_rx_counter_reg, 0);
        pkt_rx_valid_reg.read(meta.pkt_rx_valid_reg, 0);
        pkt_rx_ack_reg.read(meta.pkt_rx_ack_reg, 0);

        ipv4_lpm.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                    
    apply{
        if(hdr.ethernet.etherType == TYPE_IPV4) {
            // 有兩個封包經過這裡
            if(standard_metadata.instance_type == 1) {
                hdr.RDH.setValid();
                hdr.ethernet.etherType = TYPE_RDH;
                hdr.RDH.CPUpacketNum = meta.pkt_tx_counter_reg;
                hdr.RDH.CPUackNum = meta.pkt_tx_ack_reg;
            }
        }
        else if (hdr.ethernet.etherType == TYPE_RDH) {
            hdr.RDH.setValid();
            hdr.RDH.CPUpacketNum = meta.pkt_rx_counter_reg;
            hdr.RDH.CPUvalidNum = meta.pkt_rx_valid_reg;
            hdr.RDH.CPUackNum = meta.pkt_rx_ack_reg;
            // 有一個封包經過這裡 (standard_metadata.instance_type == 5)
            // p4_logger(standard_metadata.instance_type);
            if(standard_metadata.instance_type == 0) {
                mark_to_drop(standard_metadata);
            }
        }

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
*************************  D E P A R S E R  ******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.RDH);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
****************************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
