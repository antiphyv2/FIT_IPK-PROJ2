#ifndef SNIFFER_H
#define SNIFFER_H
#include "argparser.h"

#define ETH_HEADER_LEN 14 //Size of eth header
#define IPV4 4
#define IPV6 6
#define TCP_PROTOCOL 1
#define UDP_PROTOCOL 0
#define MAC_ADDR_LEN 6
#define HEX_PRINT_LEN 16

/**
 * @brief Prints out all available network interfaces
 * 
 * @param info pointer to the structure with CLI parsed infomartion
 */
void print_network_interfaces(parsed_info* info);

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


/**
 * @brief Prints timestamp from the packet
 * 
 * @param pkthdr pointer to a packet time stamp and lengths
 */
void print_packet_time(const struct pcap_pkthdr* pkthdr);


/**
 * @brief Prints source and destination address in hex format
 * 
 * @param eth_header pointer to the eth header with appropriate information
 */
void print_mac_addresses(struct ether_header* eth_header);


/**
 * @brief Print destination and source port of the packet
 * 
 * @param ip_header Pointer to the ip header
 * @param protocol 1 if protocol is TCP, 0 if UDP
 * @param ip_version 4 if ip protocol is IPV4, IPV6 otherwise
 */
void print_packet_ports(struct ip* ip_header, int protocol, int ip_version);


/**
 * @brief Prints ARP protocol addresses and operation
 * 
 * @param packet Pointer to the packet
 */
void print_arp_details(const u_char* packet);


/**
 * @brief Prints packet byte offset, hexadecimal and ascii representation
 * 
 * @param packet Pointer to the packet
 * @param packet_length Packet length
 */
void print_packet_hex_ascii(const u_char* packet, int packet_length);

#endif