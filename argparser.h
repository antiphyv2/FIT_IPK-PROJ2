#ifndef ARGPARSER_H
#define ARGPARSER_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pcap/pcap.h>

typedef struct INFO {
    char* interface;
    bool protocol_tcp;
    bool protocol_udp;
    int port;
    int port_source;
    int port_destination;
    bool icmp_4;
    bool icmp_6;
    bool arp;
    bool ndp;
    bool igmp;
    bool mld;
    int packets_to_display;
    bool apply_filter;

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
 * @brief Prints out error occured in argparser and exits program
 * 
 * @param info pointer to allocated  structure to be deleted
 * @param message message to be printed
 */
void argparse_error_exit(parsed_info* info, const char* message);



#endif