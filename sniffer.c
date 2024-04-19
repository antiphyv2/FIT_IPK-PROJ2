#include "sniffer.h"

void print_network_interfaces(parsed_info* info) {
    pcap_if_t *network_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&network_devs, errbuf) == -1) {
        fprintf(stderr, "ERR: [PCAP_FINDALL] %s\n", errbuf);
        free(info);
        exit(EXIT_FAILURE);
    }

    printf("List of network interfaces:\n");
    pcap_if_t *dev = network_devs;
    int int_count = 1;
    while(dev != NULL){
        if(dev->description){
            printf("%d. interface: %s, Description: %s\n", int_count, dev->name, dev->description);
        } else {
            printf("%d. interface: %s\n", int_count, dev->name);
        }
        int_count++;
        dev = dev->next;
    }

    pcap_freealldevs(network_devs);
}


void create_pcap_sniffer(pcap_t** sniffer, parsed_info* info){
    char errbuf[PCAP_ERRBUF_SIZE];
    //Sniffer opened in promiscious mode
    *sniffer = pcap_open_live(info->interface, BUFSIZ, 1, 1000, errbuf);
    if(!(*sniffer)){
        fprintf(stderr, "ERR: [PCAP_CREATE] %s\n", errbuf);
        free(info);
        exit(EXIT_FAILURE);
    }

    int linktype = pcap_datalink(*sniffer);
    if(linktype != DLT_EN10MB && linktype != DLT_NULL){ //Interface must be LINKTYPE Ethernet or loopback 
        fprintf(stderr, "ERR: [DATALINK NOT ETHERNET]\n");
        pcap_close(*sniffer);
        free(info);
        exit(EXIT_FAILURE);
    }
}

void apply_pcap_filter(pcap_t** sniffer, parsed_info* info){
    bpf_u_int32 ip_address;
    bpf_u_int32 netmask;
    char errbuf[PCAP_ERRBUF_SIZE];

    int ret_code = pcap_lookupnet(info->interface, &ip_address, &netmask, errbuf);
    if (ret_code != 0) {
        fprintf(stderr, "ERR: [PCAP_LOOKUPNET] %s\n", errbuf);
        pcap_close(*sniffer);
        free(info);
        exit(EXIT_FAILURE);
    }

    char sniffer_filter[256];
    memset(sniffer_filter, 0, sizeof(sniffer_filter));

    if (info->protocol_tcp || info->protocol_udp) {
        if(info->port || info->port_destination || info->port_source){
                strcat(sniffer_filter, "(");
        }
        if(info->protocol_tcp && info->protocol_udp){
            strcat(sniffer_filter, "(");
            strcat(sniffer_filter, "tcp");
            strcat(sniffer_filter, " or ");
            strcat(sniffer_filter, "udp");
            strcat(sniffer_filter, ")");
        } else if(info->protocol_tcp){
            strcat(sniffer_filter, "tcp");

        } else if(info->protocol_udp){
            strcat(sniffer_filter, "udp");
        }

        if(info->port){
            strcat(sniffer_filter, " and ");
            strcat(sniffer_filter, "port ");
            strcat(sniffer_filter, info->port);
            strcat(sniffer_filter, ")");
        } else if(info->port_source){
            strcat(sniffer_filter, " and ");
            strcat(sniffer_filter, "src port ");
            strcat(sniffer_filter, info->port_source);
            strcat(sniffer_filter, ")");
        } else if(info->port_destination){
            strcat(sniffer_filter, " and ");
            strcat(sniffer_filter, "dst port ");
            strcat(sniffer_filter, info->port_destination);
            strcat(sniffer_filter, ")");
        }
        
    }

    if(info->arp){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "arp");
    }

    if(info->icmp_4){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "icmp");
    }

    if(info->icmp_6){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "icmp6");
    }

    if(info->igmp){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "igmp");
    }

    if(info->mld){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "icmp6 and ip6[40] == 130");
    }

    if(info->ndp){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "icmp6 and (ip6[40] == 135 or ip6[40] == 136)");
    }

    printf("Filter: %s\n", sniffer_filter);

    struct bpf_program bpf;
    ret_code = pcap_compile(*sniffer, &bpf, sniffer_filter, 0, netmask);
    if (ret_code != 0) {
        fprintf(stderr, "ERR: [PCAP_COMPILE] %s\n", pcap_geterr(*sniffer));
        pcap_close(*sniffer);
        free(info);
        exit(EXIT_FAILURE);
    }

    ret_code = pcap_setfilter(*sniffer, &bpf);
    if (ret_code != 0) {
        fprintf(stderr, "ERR: [PCAP_SETFILTER] %s\n", pcap_geterr(*sniffer));
        pcap_close(*sniffer);
        pcap_freecode(&bpf);
        free(info);
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&bpf);

}

void print_packet_time(const struct pcap_pkthdr* pkthdr){
    char time_buffer[40];
    struct tm *time_struct;

    //Get reprezentation in local timer zone
    time_struct = localtime(&pkthdr->ts.tv_sec);
    
    // Format date and time 
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%dT%H:%M:%S", time_struct);
    
    // Calculate the timezone and print offset in hours and minutes
    long tz_offset = time_struct->tm_gmtoff;
    char tz_sign = (tz_offset < 0) ? '-' : '+';
    tz_offset = abs(tz_offset);
    int tz_hours = (tz_offset / 3600);
    int tz_minutes = (tz_offset - (tz_hours * 3600)) / 60;
    int miliseconds = (int) pkthdr->ts.tv_usec / 1000;
    printf("timestamp: %s.%d%c%02d:%02d\n", time_buffer, miliseconds, tz_sign, tz_hours, tz_minutes);
}

void print_mac_addresses(struct ether_header* eth_header){
    char src_mac[MAC_ADDRESS_SIZE];
    char dest_mac[MAC_ADDRESS_SIZE];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth_header->ether_shost[0],
         eth_header->ether_shost[1],
         eth_header->ether_shost[2],
         eth_header->ether_shost[3],
         eth_header->ether_shost[4],
         eth_header->ether_shost[5]);

    snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth_header->ether_dhost[0],
         eth_header->ether_dhost[1],
         eth_header->ether_dhost[2],
         eth_header->ether_dhost[3],
         eth_header->ether_dhost[4],
         eth_header->ether_dhost[5]);

    printf("src MAC: %s\n", src_mac);
    printf("dst MAC: %s\n", dest_mac);
}

void packet_parser(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* eth_header;
    struct ip* ip_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct icmp* icmp_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int ip_header_length;

    //At first, print packet timestamp
    print_packet_time(pkthdr);

    //Secondly print mac addresses from the header
    print_mac_addresses((struct ether_header*) packet);

    //Print frame length
    printf("frame length %u\n", pkthdr->len);


    //We can skip the datalink ethernet header and get to the packet itself
    ip_header = (struct ip *)(packet + ETH_HEADER_LEN);
    ip_header_length = ip_header->ip_hl * 4;  // IP header length in 32-bit words

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETH_HEADER_LEN + ip_header_length);
        printf("Captured a TCP packet from %s to %s, Src Port: %d, Dst Port: %d\n",
            inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst),
            ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + ETH_HEADER_LEN + ip_header_length);
        printf("Captured a UDP packet from %s to %s, Src Port: %d, Dst Port: %d\n",
            inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst),
            ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
    } else {
        printf("Captured a non-TCP/UDP packet\n");
    }
    
}
    
int sniff(pcap_t** sniffer, parsed_info* info){
    create_pcap_sniffer(sniffer, info);
    apply_pcap_filter(sniffer, info);

    int ret_code = pcap_loop(*sniffer, info->packets_to_display, packet_parser, NULL);
    if(ret_code != 0){
        fprintf(stderr, "ERR: [PCAP_LOOP] %s\n", pcap_geterr(*sniffer));
        return -1;
    }
    pcap_close(*sniffer);
    free(info);
    return 0;
}