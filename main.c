#include "argparser.h"
#include "sniffer.h"
#include "prints.h"
#include <signal.h>

//Global pointers to be cleaned after graceful exit
parsed_info* info;
pcap_t* sniffer;

//Prints info from argparser
void print_info(parsed_info* info){
    printf("Interface: %s\n", info->interface);
    printf("TCP on: %d\n", info->protocol_tcp);
    printf("TUDP on: %d\n", info->protocol_udp);
    printf("Port: %s\n", info->port);
    printf("Packets to display: %d\n", info->packets_to_display);
    printf("Port-dest: %s\n", info->port_destination);
    printf("Port-src: %s\n", info->port_source);
}

//Graceful exit called after CTRL+C
void graceful_exit(int signal){
    if(signal == SIGINT){
        if(info){
            free(info);
        }
        if(sniffer){
            pcap_close(sniffer);
        }
        exit(EXIT_SUCCESS);
    }

}

int main(int argc, char* argv[]) {
    //signal for CTRL+C exit
    signal(SIGINT, graceful_exit);
    //Obtain CLI args
    info = parse_args(argc, argv);
    if(!info){
        return EXIT_FAILURE;
    }

    if(!info->interface){
        //Interfaces will be printed only if zero or just one argument (-i||--interface) specified 
        if(argc <= 2){
            print_network_interfaces(info);
            free(info);
            return EXIT_SUCCESS;  
        }
        //Otherwise error will be printed since there is no interface
        fprintf(stderr, "ERR: [VALUE] Interface specification is missing.\n");
        free(info);
        return EXIT_FAILURE;
    }

    //print_info(info);

    //Start the sniffer
    if(sniff(&sniffer, info) == -1){
        return EXIT_FAILURE;
    }

    return 0;
}