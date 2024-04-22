/**
 * @file argparser.h
 * @author Samuel Hejnicek xhejni00
 * @brief Header file defining functions for parsing CLI arguments
 
 */

#ifndef ARGPARSER_H
#define ARGPARSER_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#include <time.h>
#include <ctype.h>

//Structure for CLI arguments
typedef struct INFO {
    char* interface;
    bool protocol_tcp;
    bool protocol_udp;
    char* port;
    char* port_source;
    char* port_destination;
    bool icmp_4;
    bool icmp_6;
    bool arp;
    bool ndp;
    bool igmp;
    bool mld;
    int packets_to_display;
    bool filter_print;
} parsed_info;

/**
 * @brief Parses arguments from CLI input
 * 
 * @param argc number of arguments
 * @param argv array of arguments
 * @return info pointer to the allocated structure with parsed information
 */
parsed_info* parse_args(int argc, char* argv[]);

/**
 * @brief Prints help to user
 * 
 */
void print_help();

/**
 * @brief Prints out error occured in argparser and deallocs memory 
 * 
 * @param info pointer to allocated structure to be deleted
 * @param message message to be printed
 */
void argparse_error_dealloc(parsed_info* info, const char* message);

/**
 * @brief Checks if port is in range
 * 
 * @param port port number
 * @return true if port number is valid
 * @return false if port numbet isnt valid
 */
bool check_port_range(int port);


#endif