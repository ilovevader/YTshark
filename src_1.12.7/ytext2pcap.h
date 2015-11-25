#ifndef __Y_TEXT2PCAP_H__
#define __Y_TEXT2PCAP_H__

#include "ytmode.h"
int main(int argc, char *argv[])
{
    return ytmodeMain(argc, argv);
}

void YtmodeReset()
{
    if (firstTime) {
        return;
    }

    optind = 1;

    //--- Options --------------------------------------------------------------------
    // File format
    use_pcapng = FALSE;

    // Debug level
    debug = 0;

    // Be quiet
    quiet = FALSE;

    // Dummy Ethernet header
    hdr_ethernet = FALSE;
    hdr_ethernet_proto = 0;

    // Dummy IP header
    hdr_ip = FALSE;
    hdr_ipv6 = FALSE;
    hdr_ip_proto = 0;

    // Destination and source addresses for IP header
    hdr_ip_dest_addr = 0;
    hdr_ip_src_addr = 0;
    for (int i = 0; i < 16; ++i) {
        hdr_ipv6_dest_addr[i] = 0;
        hdr_ipv6_src_addr[i] = 0;
        NO_IPv6_ADDRESS[i] = 0;
    }

    // Dummy UDP header
    hdr_udp = FALSE;
    hdr_dest_port = 0;
    hdr_src_port = 0;

    // Dummy TCP header
    hdr_tcp = FALSE;

    // TCP sequence numbers when has_direction is true
    tcp_in_seq_num = 0;
    tcp_out_seq_num = 0;

    // Dummy SCTP header
    hdr_sctp = FALSE;
    hdr_sctp_src = 0;
    hdr_sctp_dest = 0;
    hdr_sctp_tag = 0;

    // Dummy DATA chunk header
    hdr_data_chunk = FALSE;
    hdr_data_chunk_type = 0;
    hdr_data_chunk_bits = 0;
    hdr_data_chunk_tsn = 0;
    hdr_data_chunk_sid = 0;
    hdr_data_chunk_ssn = 0;
    hdr_data_chunk_ppid = 0;

    // ASCII text dump identification
    identify_ascii = FALSE;

    has_direction = FALSE;
    direction = 0;

    //--- Local date -----------------------------------------------------------------
    // This is where we store the packet currently being built
    max_offset = MAX_PACKET;
    packet_start = 0;

    // This buffer contains strings present before the packet offset 0
    packet_preamble_len = 0;

    // Number of packets read and written
    num_packets_read = 0;
    num_packets_written = 0;
    bytes_written = 0;

    // Time code of packet, derived from packet_preamble
    ts_sec = 0;
    ts_usec = 0;
    ts_fmt = NULL;

    // Input file
    input_file = NULL;

    // Output file
    output_file = NULL;

    // Offset base to parse
    offset_base = 16;

    // ----- State machine -----------------------------------------------------------
    // Current state of parser
    state = INIT;

    // ----- Skeleton Packet Headers --------------------------------------------------
    HDR_ETHERNET.dest_addr[0] = 0x0a;
    HDR_ETHERNET.src_addr[1] = 0x0a;
    for (int i = 1; i < 6; ++i) {
        HDR_ETHERNET.dest_addr[i] = 0x02;
        HDR_ETHERNET.src_addr[i] = 0x01;
    }

    HDR_ETHERNET.l3pid = 0;

    HDR_IP.ver_hdrlen = 0x45;
    HDR_IP.dscp = 0;
    HDR_IP.packet_length = 0;
    HDR_IP.identification = 0x3412;
    HDR_IP.flags = 0;
    HDR_IP.fragment = 0;
    HDR_IP.ttl = 0xff;
    HDR_IP.protocol = 0;
    HDR_IP.hdr_checksum = 0;
#ifdef WORDS_BIGENDIAN
    HDR_IP.src_addr = 0x0a010101;
    HDR_IP.dest_addr = 0x0a020202;
#else
    HDR_IP.src_addr = 0x0101010a;
    HDR_IP.dest_addr = 0x0202020a;
#endif
    HDR_UDP.source_port = 0;
    HDR_UDP.dest_port = 0;
    HDR_UDP.length = 0;
    HDR_UDP.checksum = 0;

    HDR_TCP.source_port = 0;
    HDR_TCP.dest_port = 0;
    HDR_TCP.seq_num = 0;
    HDR_TCP.ack_num = 0;
    HDR_TCP.hdr_length = 0x50;
    HDR_TCP.flags = 0;
    HDR_TCP.window = 0;
    HDR_TCP.checksum = 0;
    HDR_TCP.urg = 0;

    HDR_SCTP.src_port = 0;
    HDR_SCTP.dest_port = 0;
    HDR_SCTP.tag = 0;
    HDR_SCTP.checksum = 0;

    HDR_DATA_CHUNK.type = 0;
    HDR_DATA_CHUNK.bits = 0;
    HDR_DATA_CHUNK.length = 0;
    HDR_DATA_CHUNK.tsn = 0;
    HDR_DATA_CHUNK.sid = 0;
    HDR_DATA_CHUNK.ssn = 0;
    HDR_DATA_CHUNK.ppid = 0;

    // Link-layer type; see http://www.tcpdump.org/linktypes.html for details
    pcap_link_type = 1; // Default is LINKTYPE_ETHERNET
}

#endif
