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
    if(linktype != DLT_EN10MB){ //Interface must be LINKTYPE Ethernet
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
        strcat(sniffer_filter, "icmp6 and (ip6[40] == 130 or ip6[40] == 131 or ip6[40] == 132 or ip6[40] == 143)");
    }

    if(info->ndp){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        strcat(sniffer_filter, "icmp6 and (ip6[40] == 133 or ip6[40] == 135 or ip6[40] == 135  or ip6[40] == 136 or ip6[40] == 137)");
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
    
    // Calculate the timezone offset and miliseconds
    int tz_offset = (int) time_struct->tm_gmtoff;
    char tz_sign = (tz_offset > 0) ? '+' : '-';
    tz_offset = abs(tz_offset);
    int tz_hours = (tz_offset / 3600);
    int tz_minutes = (tz_offset - (tz_hours * 3600)) / 60;
    int miliseconds = (int) pkthdr->ts.tv_usec / 1000;

    //Print the timestamp in RFC 3339
    printf("timestamp: %s.%d%c%02d:%02d\n", time_buffer, miliseconds, tz_sign, tz_hours, tz_minutes);
}

void print_mac_addresses(struct ether_header* eth_header){
    //Copy the mac address to an array and print bytes of the array in given format
    unsigned char address[MAC_ADDR_LEN] = {};
    memcpy(address, eth_header->ether_shost, MAC_ADDR_LEN);
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", address[0], address[1], address[2], address[3], address[4], address[5]);
    memcpy(address, eth_header->ether_dhost, MAC_ADDR_LEN);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", address[0], address[1], address[2], address[3], address[4], address[5]);
}

void print_packet_ports(const u_char* packet, int protocol, int ip_version){
    if(ip_version == IPV4){
        struct ip* ip_header = (struct ip*) packet;
        if(protocol == TCP_PROTOCOL){
            struct tcphdr* tcp_header = (struct tcphdr *) ((unsigned char*)ip_header + ip_header->ip_hl * 4); //Multiply by 4 to convert it to bytes (length in 32bit words)
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        } else {
            struct udphdr *udp_header = (struct udphdr *) ((unsigned char*)ip_header + ip_header->ip_hl * 4); //Multiply by 4 to convert it to bytes (length in 32bit words)
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
    }

}

void print_packet_hex_ascii(const u_char* packet, int packet_length){

    printf("\n");
    int i;
    for(i = 0; i < packet_length; i++){
        if(i % HEX_PRINT_LEN == 0){
            
            if(i != 0){
                printf(" ");
                for (int j = i - HEX_PRINT_LEN; j < i; j++) {
                    unsigned char character = packet[j];
                    if(!isprint(character)){
                        character = '.';
                    }
                    printf("%c", character);
                }
            printf("\n");
            }
            printf("0x%04x: ", i);
            
        }
        printf("%02x ", packet[i]);
    }

    int ascii_not_printed = i % HEX_PRINT_LEN;
    if(ascii_not_printed > 0){
        for(int i = 0; i < (HEX_PRINT_LEN - ascii_not_printed); i++){
            printf("   ");
        }
        printf(" ");
        for (int j = i - ascii_not_printed; j < i; j++) {
            unsigned char character = packet[j];
            if(!isprint(character)){
                character = '.';
            }
            printf("%c", character);
        }
    }
    printf("\n");
}


void print_arp_details(const u_char* packet){
    struct ether_arp* arp_header = (struct ether_arp*) packet;
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    //Convert ARP protocol addresses to readable format
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

    //Print addresses
    printf("sender protocol address: %s\n", sender_ip);
    printf("target protocol address: %s\n", target_ip);

    //Print type of arp op
    if(ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REPLY){
        printf("ARP operation: REPLY\n");
    } else {
        printf("ARP operation: REQUEST\n");
    }
}

void print_igmp_details(const u_char* packet){
    struct ip* ip_header = (struct ip*) packet;
    struct igmp* igmp_header = (struct igmp *)((unsigned char*)ip_header + ip_header->ip_hl * 4);
    switch (igmp_header->igmp_type){
    //all message types taken from igmp.h
    case IGMP_MEMBERSHIP_QUERY:
        printf("igmp type: MEMBERSHIP_QUERY\n");
        break;
    case IGMP_V1_MEMBERSHIP_REPORT:
        printf("igmp type: V1_MEMBERSHIP_REPORT\n");
        break;
    case IGMP_V2_MEMBERSHIP_REPORT:
        printf("igmp type: V2_MEMBERSHIP_REPORT\n");
        break;
    case IGMP_V2_LEAVE_GROUP:
        printf("igmp type: V2_LEAVE_GROUP\n");
        break;
    case IGMP_DVMRP:
        printf("igmp type: DVMRP routing message\n");
        break;
    case IGMP_PIM:
        printf("igmp type: PIM routing message\n");
        break;
    case IGMP_TRACE:
        printf("igmp type: TRACE\n");
        break;
    case IGMP_MTRACE_RESP:
        printf("igmp type: traceroute resp. (to sender)\n");
        break;
    case IGMP_MTRACE:
        printf("igmp type: mcast traceroute messages\n");
        break;
    default:
        printf("igmp type: unknown %d\n", igmp_header->igmp_type);
        break;
    }
    printf("igmp routing code: %d\n", igmp_header->igmp_code);
    printf("igmp group address: %s\n", inet_ntoa(igmp_header->igmp_group));
}

void print_ip_addresses(const u_char* packet, int ip_version){
    if(ip_version == IPV4){
        struct ip* ip_header = (struct ip*) packet;
        printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
    }
}

void print_icmp_details(const u_char* packet, int ip_version){
    if(ip_version == IPV4){
        struct ip* ip_header = (struct ip*) packet;
        struct icmp* icmp_header = (struct icmp*)((unsigned char*)ip_header + ip_header->ip_hl * 4);
        switch (icmp_header->icmp_type){
            //all message types taken from igmp.h
        case ICMP_ECHOREPLY:
            printf("icmp type: Echo reply\n");
            break;
        case ICMP_DEST_UNREACH:
            printf("icmp type: Destination Unreachable\n");
            break;
        case ICMP_REDIRECT:
            printf("icmp type: Redirect (change route)\n");
            break;
        case ICMP_ECHO:
            printf("icmp type: Echo request\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf("icmp type: Time Exceeded\n");
            break;
        case ICMP_PARAMETERPROB:
            printf("icmp type: Parameter problem\n");
            break;
        case ICMP_TIMESTAMP:
            printf("icmp type: Timestamp request\n");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("icmp type: Timestamp reply\n");
            break;
        case ICMP_INFO_REQUEST:
            printf("icmp type: Information Request\n");
            break;
        case ICMP_INFO_REPLY:
            printf("icmp type: Information Reply\n");
            break;
        case ICMP_ADDRESS:
            printf("icmp type: Information Request\n");
            break;
        case ICMP_ADDRESSREPLY:
            printf("icmp type: Information Reply\n");
            break;
        default:
            printf("icmp type: unknown %d\n", icmp_header->icmp_type);
            break;
        }
        printf("icmp code: %d\n", icmp_header->icmp_code);
        
    }
}

void packet_parser(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    
    //At first, print packet timestamp
    print_packet_time(pkthdr);

    //Secondly print mac addresses from the header
    print_mac_addresses((struct ether_header*) packet);

    //Print frame length
    printf("frame length %u\n", pkthdr->len);

    //Find out if type is IPV4, IPV6 or ARP
    int ethernet_type = ntohs(((struct ether_header*) packet)->ether_type);

    //Now we can skip the datalink ethernet header and get to the ip header
    packet += ETH_HEADER_LEN;

    switch (ethernet_type)
    {
    case ETHERTYPE_IP:
        struct ip* ip_header = (struct ip*) packet;
        if (ip_header->ip_p == IPPROTO_TCP) {
            print_ip_addresses(packet, IPV4);
            print_packet_ports(packet, TCP_PROTOCOL, IPV4);
            printf("Captured a TCP packet\n");
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            print_ip_addresses(packet, IPV4);
            print_packet_ports(packet, UDP_PROTOCOL, IPV4);
            printf("Captured a UDP packet\n");
        } else if(ip_header->ip_p == IPPROTO_ICMP) {
            print_ip_addresses(packet, IPV4);
            print_icmp_details(packet, IPV4);
            printf("Captured an ICMP packet\n");
        } else if(ip_header->ip_p == IPPROTO_IGMP){
            print_ip_addresses(packet, IPV4);
            print_igmp_details(packet);
            printf("Captured an IGMP packet\n");
        }
        break;
    
    case ETHERTYPE_IPV6:
        struct ip6_hdr* ipv6_header = (struct ip6_hdr*) packet;
        unsigned int nxt_header = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            if(nxt_header == IPPROTO_TCP){

            } else if(nxt_header == IPPROTO_UDP){

            } else if(nxt_header == IPPROTO_ICMPV6){

            }
        break;

    case ETHERTYPE_ARP:
        print_arp_details(packet);
        break;
    default:
        break;
    }
    print_packet_hex_ascii(packet, pkthdr->caplen);
    
}
    
int sniff(pcap_t** sniffer, parsed_info* info){
    create_pcap_sniffer(sniffer, info);
    apply_pcap_filter(sniffer, info);

    //start sniffer loop to capture spefific amount of packets
    int ret_code = pcap_loop(*sniffer, info->packets_to_display, packet_parser, NULL);
    if(ret_code != 0){
        fprintf(stderr, "ERR: [PCAP_LOOP] %s\n", pcap_geterr(*sniffer));
        return -1;
    }
    pcap_close(*sniffer);
    free(info);
    return 0;
}