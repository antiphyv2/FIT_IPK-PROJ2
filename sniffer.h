#ifndef SNIFFER_H
#define SNIFFER_H
#include "argparser.h"

#define ETH_HEADER_LEN 14 //Size of eth header
#define IPV4 4
#define IPV6 6
#define TCP_PROTOCOL 1
#define UDP_PROTOCOL 0
#define MAC_ADDR_LEN 6
#define HEX_PRINT_LEN 16 //Hex character to be printed
#define IPV6_HEADER_LEN 40 //Size of ipv6 header

/**
 * @brief Creates a pcap sniffer object
 * 
 * @param sniffer pointer to a pointer to the sniffer
 * @param info pointer to the structure with CLI parsed infomartion
 */
void create_pcap_sniffer(pcap_t** sniffer, parsed_info* info);


/**
 * @brief Applies filter from given CLI arguments to the sniffer
 * 
 * @param sniffer pointer to a pointer to the sniffer
 * @param info pointer to the structure with CLI parsed infomartion
 */
void apply_pcap_filter(pcap_t** sniffer, parsed_info* info);


/**
 * @brief Finds out packet type and prints it information to standard output
 * 
 * @param user pointer to user set data
 * @param pkthdr pointer to a packet time stamp and lengths
 * @param packet pointer to the first caplen bytes of packet data
 */
void packet_parser(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);


/**
 * @brief Sniffs packets on network
 * 
 * @param sniffer pointer to a pointer to the sniffer
 * @param info pointer to the structure with CLI parsed infomartion
 * @return int -1 if sniffing process failed
 */
int sniff(pcap_t** sniffer, parsed_info* info);

#endif