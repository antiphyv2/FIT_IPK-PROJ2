#include "argparser.h"
#include "sniffer.h"
#include <signal.h>

parsed_info* info;
pcap_t* sniffer;

void print_info(parsed_info* info){
    printf("Interface: %s\n", info->interface);
    printf("TCP on: %d\n", info->protocol_tcp);
    printf("Port: %s\n", info->port);
    printf("Packets to display: %d\n", info->packets_to_display);
    printf("Port-dest: %s\n", info->port_destination);
    printf("Port-src: %s\n", info->port_source);
}


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
    signal(SIGINT, graceful_exit);
    info = parse_args(argc, argv);
    if(!info){
        return EXIT_FAILURE;
    }

    if(!info->interface){
        if(argc <= 2){
            print_network_interfaces(info);
            print_help();
            free(info);
            return EXIT_SUCCESS;  
        }
        fprintf(stderr, "ERR: [VALUE] Interface specification is missing.\n");
        free(info);
        return EXIT_FAILURE;
    }

    print_info(info);
    if(sniff(&sniffer, info) == -1){
        return EXIT_FAILURE;
    }

    return 0;
}