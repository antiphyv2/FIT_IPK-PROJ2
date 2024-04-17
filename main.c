#include "argparser.h"

parsed_info* info;

void list_network_interfaces() {
    pcap_if_t *network_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&network_devs, errbuf) == -1) {
        fprintf(stderr, "ERR: [PCAP_FINDALL] %s\n", errbuf);
        free(info);
        exit(EXIT_FAILURE);
    }

    printf("List of network interfaces:\n");
    pcap_if_t *dev = network_devs;
    while(dev != NULL){
        if(dev->description){
            printf("Interface: %s, Description: %s\n", dev->name, dev->description);
        } else {
            printf("Interface: %s\n", dev->name);
        }
        dev = dev->next;
    }
    pcap_freealldevs(network_devs);
}

int main(int argc, char* argv[]) {
    info = parse_args(argc, argv);
    if(!info->interface){
        list_network_interfaces();
        free(info);
        exit(EXIT_SUCCESS);
    }



    printf("Interface: %s\n", info->interface);
    printf("TCP on: %d\n", info->protocol_tcp);
    printf("Port: %d\n", info->port);
    printf("Packets to display: %d\n", info->packets_to_display);
    free(info);
    return 0;
}