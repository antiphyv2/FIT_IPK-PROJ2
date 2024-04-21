#include "prints.h"

void print_network_interfaces(parsed_info* info) {
    pcap_if_t *network_devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    //Get a list of all devices
    if (pcap_findalldevs(&network_devs, errbuf) == -1) {
        fprintf(stderr, "ERR: [PCAP_FINDALL] %s\n", errbuf);
        free(info);
        exit(EXIT_FAILURE);
    }

    printf("List of available network interfaces:\n");
    pcap_if_t *dev = network_devs;
    int int_count = 1;
    //Iterate through devices and print description if exists
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

void print_ip_addresses(const u_char* packet, int ip_version){
    if(ip_version == IPV4){
        struct ip* ip_header = (struct ip*) packet;
        //Print IP using inet_ntoa, it might be deprecated but should be fine (no buffer needs to be created)
        printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
    } else {
        struct ip6_hdr* ipv6_header = (struct ip6_hdr*) packet;
        char src_ipv6[INET6_ADDRSTRLEN];
        char dst_ipv6[INET6_ADDRSTRLEN];

        //Use inet_ntop since inet_ntoa is only used for ipv4 addresses, it should also be fine with RFC 5952 when reading this site: https://pubs.opengroup.org/onlinepubs/009604499/functions/inet_ntop.html
        inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_ipv6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dst_ipv6, INET6_ADDRSTRLEN);

        printf("src IP: %s\n", src_ipv6);
        printf("dst IP: %s\n", dst_ipv6);
    }
}

void print_packet_ports(const u_char* packet, int protocol, int ip_version){
    if(ip_version == IPV4){
        //IP header is just at the pointer to the packet (Eth Header added before)
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
    } else {
        packet += IPV6_HEADER_LEN; //ipv6 header is fixed size of 40 bytes, move to tcp or udp header
        if(protocol == TCP_PROTOCOL){
            struct tcphdr* tcp_header = (struct tcphdr*) packet;
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        } else {
            struct udphdr* udp_header = (struct udphdr*) packet;
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
    }
}

void print_packet_hex_ascii(const u_char* packet, int packet_length){
    //Format output to be wireshark like
    printf("\n");
    //We need the value later on so i must be outside of the for loop
    int i;
    bool print_ascii = false;
    for(i = 0; i < packet_length; i++){
        if(i % HEX_PRINT_LEN == 0){
            //Ascii isnt printed at the start before hex
            if(print_ascii){
                printf(" ");
                for (int j = i - HEX_PRINT_LEN; j < i; j++) {
                    //step back 16 characters and print every single one as an ascii character
                    unsigned char character = packet[j];

                    //replace nonprintable characters with a dot
                    if(!isprint(character)){
                        character = '.';
                    }
                    //Add space after 8 ASCII chars
                    if(j == (i - HEX_PRINT_LEN/2)){
                        printf(" ");
                    }
                    //Print byte offset ASCII
                    printf("%c", character);
                }
            printf("\n");
            }
            //Print byte offset
            printf("0x%04x: ", i);
            print_ascii = true;
            
        }
        //Print byte offset hexa
        printf("%02x ", packet[i]);
    }

    //Print the rest in ASCII (since ASCII is printed only after 16 hex characters)
    int ascii_not_printed = i % HEX_PRINT_LEN;
    if(ascii_not_printed > 0){
        for(int i = 0; i < (HEX_PRINT_LEN - ascii_not_printed); i++){
            //Print remaining spaces to be in same position where ascii starts
            printf("   ");
        }
        //Ascii delimiter
        printf(" ");
        int ascii_cnt = 0;
        for (int j = i - ascii_not_printed; j < i; j++) {
            unsigned char character = packet[j];
            if(!isprint(character)){
                character = '.';
            }
            if(ascii_cnt == HEX_PRINT_LEN/2){
                printf(" ");
            }
            ascii_cnt++;
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
    //IGMP is ipv4, headerlen must be added
    struct igmp* igmp_header = (struct igmp *)((unsigned char*)ip_header + ip_header->ip_hl * 4);
    switch (igmp_header->igmp_type){
    //all message types taken from igmp.h
    case IGMP_MEMBERSHIP_QUERY:
        printf("igmp type: membership query\n");
        break;
    case IGMP_V1_MEMBERSHIP_REPORT:
        printf("igmp type: membership report version 1\n");
        break;
    case IGMP_V2_MEMBERSHIP_REPORT:
        printf("igmp type: membership report version 2\n");
        break;
    case IGMP_V2_LEAVE_GROUP:
        printf("igmp type: leave-group message version 2\n");
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
        printf("igmp type: unknown to print%d\n", igmp_header->igmp_type);
        break;
    }
    printf("igmp routing code: %d\n", igmp_header->igmp_code);
    printf("igmp group address: %s\n", inet_ntoa(igmp_header->igmp_group));
}

void print_icmp_details(const u_char* packet, int ip_version){
    if(ip_version == IPV4){
        struct ip* ip_header = (struct ip*) packet;
        struct icmp* icmp_header = (struct icmp*)((unsigned char*)ip_header + ip_header->ip_hl * 4);
        switch (icmp_header->icmp_type){
            //all message types taken from icmp.h
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
            printf("icmp type: unknown to print %d\n", icmp_header->icmp_type);
            break;
        }
        printf("icmp code: %d\n", icmp_header->icmp_code);
        
    } else {
        packet += IPV6_HEADER_LEN;
        struct icmp6_hdr* icmp6_header = (struct icmp6_hdr*) packet;
        switch (icmp6_header->icmp6_type){
        //types were selected from icmp6.h
        case ICMP6_DST_UNREACH:
            printf("icmp6 type: Destination unreachable\n");
            break;
        case ICMP6_PACKET_TOO_BIG:
            printf("icmp6 type: Packet too big\n");
            break;
        case ICMP6_TIME_EXCEEDED:
            printf("icmp6 type: Time Exceeded\n");
            break;
        case ICMP6_PARAM_PROB:
            printf("icmp6 type: Parameter problem\n");
            break;
        case ICMP6_ECHO_REQUEST:
            printf("icmp6 type: Echo request\n");
            break;
        case ICMP6_ECHO_REPLY:
            printf("icmp6 type: Echo reply\n");
            break;
        case MLD_LISTENER_QUERY:
            printf("icmp6 type: [MLD] Listener query\n");
            break;
        case MLD_LISTENER_REDUCTION:
            printf("icmp6 type: [MLD] Listener reduction\n");
            break;
        case MLD_LISTENER_REPORT:
            printf("icmp6 type: [MLD] Listener report\n");
            break;
        case ND_ROUTER_SOLICIT:
            printf("icmp6 type: [NDP] Router solicitation\n");
            break;
        case ND_ROUTER_ADVERT:
            printf("icmp6 type: [NDP] Router advert\n");
            break;
        case ND_NEIGHBOR_SOLICIT:
            printf("icmp6 type: [NDP] Neighbor solicitation\n");
            break;
        case ND_NEIGHBOR_ADVERT:
            printf("icmp6 type: [NDP] Neighbor advert\n");
            break;
        case ND_REDIRECT:
            printf("icmp6 type: [NDP] Redirect\n");
            break;
        default:
            printf("icmp type: unknown to print %d\n", icmp6_header->icmp6_type);
            break;
        }
        printf("icmp6 code: %d\n", icmp6_header->icmp6_code);
        printf("icmp6 checksum: %d\n", icmp6_header->icmp6_cksum);
    }
}