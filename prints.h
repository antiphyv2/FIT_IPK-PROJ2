#ifndef PRINTS_H
#define PRINTS_H
#include "argparser.h"
#include "sniffer.h"

/**
 * @brief Prints out all available network interfaces
 * 
 * @param info pointer to the structure with CLI parsed infomartion
 */
void print_network_interfaces(parsed_info* info);

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
 * @brief Prints source and destination ip addresses in readable format
 * 
 * @param packet Pointer to the packet 
 * @param ip_version 4 if ip protocol is IPV4, IPV6 otherwise
 */
void print_ip_addresses(const u_char* packet, int ip_version);

/**
 * @brief Print destination and source port of the packet
 * 
 * @param packet Pointer to the packet
 * @param protocol 1 if protocol is TCP, 0 if UDP
 * @param ip_version 4 if ip protocol is IPV4, IPV6 otherwise
 */
void print_packet_ports(const u_char* packet, int protocol, int ip_version);


/**
 * @brief Prints packet byte offset, hexadecimal and ascii representation
 * 
 * @param packet Pointer to the packet
 * @param packet_length Packet length
 */
void print_packet_hex_ascii(const u_char* packet, int packet_length);

/**
 * @brief Prints ARP protocol addresses and operation
 * 
 * @param packet Pointer to the packet
 */
void print_arp_details(const u_char* packet);

/**
 * @brief Prints details about IGMP sniffed packet
 * 
 * @param packet Pointer to the packet
 */
void print_igmp_details(const u_char* packet);

/**
 * @brief 
 * 
 * @param packet Pointer to the packet
 * @param ip_version 4 if ip protocol is IPV4, IPV6 otherwise
 */
void print_icmp_details(const u_char* packet, int ip_version);

#endif