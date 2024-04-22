/**
 * @file sniffer.c
 * @author Samuel Hejnicek xhejni00
 * @brief File containing functions for building up the sniffer
 */

#include "sniffer.h"
#include "prints.h"

//All functions needed to create the sniffer are based on an example from
//https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#build-and-run-the-sniffer

void create_pcap_sniffer(pcap_t** sniffer, parsed_info* info){
    char errbuf[PCAP_ERRBUF_SIZE];
    //All values for pcap_open_live are set according to an example on https://www.tcpdump.org/pcap.html (open device for sniffing)
    *sniffer = pcap_open_live(info->interface, BUFSIZ, 1, 1000, errbuf);
    if(!(*sniffer)){
        fprintf(stderr, "ERR: [PCAP_CREATE] %s\n", errbuf);
        free(info);
        exit(EXIT_FAILURE);
    }

    int linktype = pcap_datalink(*sniffer);
    if(linktype != DLT_EN10MB){ //No support for link types other than ethernet
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

    //Obtain netmask of the interface needed later for pcap_compile
    int ret_code = pcap_lookupnet(info->interface, &ip_address, &netmask, errbuf);
    if (ret_code != 0) {
        fprintf(stderr, "ERR: [PCAP_LOOKUPNET] %s\n", errbuf);
        pcap_close(*sniffer);
        free(info);
        exit(EXIT_FAILURE);
    }

    //Prepare buffer for sniffer filter
    char sniffer_filter[512];
    memset(sniffer_filter, 0, sizeof(sniffer_filter));

    //Add values to sniffer filter, due to precedence, parentheses are added
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
        } 
        if(info->port_source && info->port_destination){
            strcat(sniffer_filter, " and ");
            strcat(sniffer_filter, "(");
            strcat(sniffer_filter, "src port ");
            strcat(sniffer_filter, info->port_source);
            strcat(sniffer_filter, " or ");
            strcat(sniffer_filter, "dst port ");
            strcat(sniffer_filter, info->port_destination);
            strcat(sniffer_filter, ")");
            strcat(sniffer_filter, ")");
        } else {
            if(info->port_source){
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
        strcat(sniffer_filter, "icmp6 and (ip6[40] == 128 or ip6[40] == 129)");
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
        //Values for filter added according to MLD wikipedia site: https://en.wikipedia.org/wiki/Multicast_Listener_Discovery
        strcat(sniffer_filter, "icmp6 and (ip6[40] == 130 or ip6[40] == 131 or ip6[40] == 132 or ip6[40] == 143)");
    }

    if(info->ndp){
        if(sniffer_filter[0] != '\0'){
            strcat(sniffer_filter, " or ");
        }
        //Values for filter added according to NDP wikipedia site: https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
        strcat(sniffer_filter, "icmp6 and (ip6[40] == 133 or ip6[40] == 135 or ip6[40] == 135 or ip6[40] == 136 or ip6[40] == 137)");
    }

    if(info->filter_print){
        printf("filter arguments: %s\n", sniffer_filter);
    }

    struct bpf_program bpf;
    //Transform filter to bpf program
    ret_code = pcap_compile(*sniffer, &bpf, sniffer_filter, 0, netmask);
    if (ret_code != 0) {
        fprintf(stderr, "ERR: [PCAP_COMPILE] %s\n", pcap_geterr(*sniffer));
        pcap_close(*sniffer);
        free(info);
        exit(EXIT_FAILURE);
    }

    //Apply filter on sniffer
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

void packet_parser(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    
    //At first, print packet timestamp
    print_packet_time(pkthdr);

    //Secondly print mac addresses from the ethernet header
    print_mac_addresses((struct ether_header*) packet);

    //Print frame length
    printf("frame length: %u\n", pkthdr->len);

    //Find out if type is IPV4, IPV6 or ARP
    int ethernet_type = ntohs(((struct ether_header*) packet)->ether_type);

    //Now we can skip the datalink ethernet header and get to the ip header
    packet += ETH_HEADER_LEN;

    switch (ethernet_type)
    {
    //ipv4
    case ETHERTYPE_IP:
        //Get the ip header to determine protocol
        struct ip* ip_header = (struct ip*) packet;
        if (ip_header->ip_p == IPPROTO_TCP) {
            print_ip_addresses(packet, IPV4);
            printf("packet type: ipv4 TCP\n");
            print_packet_ports(packet, TCP_PROTOCOL, IPV4);
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            print_ip_addresses(packet, IPV4);
            printf("packet type: ipv4 UDP\n");
            print_packet_ports(packet, UDP_PROTOCOL, IPV4);
        } else if(ip_header->ip_p == IPPROTO_ICMP) {
            print_ip_addresses(packet, IPV4);
            printf("packet type: ipv4 ICMP\n");
            print_icmp_details(packet, IPV4);
        } else if(ip_header->ip_p == IPPROTO_IGMP){
            print_ip_addresses(packet, IPV4);
            printf("packet type: IGMP\n");
            print_igmp_details(packet);
        }
        break;
    //ipv6
    case ETHERTYPE_IPV6:
    //Get the ipv6 header (next_header) to determine protocol
        struct ip6_hdr* ipv6_header = (struct ip6_hdr*) packet;
        unsigned int nxt_header = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            if(nxt_header == IPPROTO_TCP){
                print_ip_addresses(packet, IPV6);
                printf("packet type: ipv6 TCP\n");
                print_packet_ports(packet, TCP_PROTOCOL, IPV6);
                print_ip_addresses(packet, IPV6);
                printf("packet type: ipv6 UDP\n");
                print_packet_ports(packet, UDP_PROTOCOL, IPV6);
            } else if(nxt_header == IPPROTO_ICMPV6){
                print_ip_addresses(packet, IPV6);
                printf("packet type: ipv6 ICMP\n");
                print_icmp_details(packet, IPV6);
            }
        break;
    //arp
    case ETHERTYPE_ARP:
        printf("packet type: ARP\n");
        print_arp_details(packet);
        break;
    default:
        break;
    }
    packet -= ETH_HEADER_LEN; //Eth header will be printed as well
    print_packet_hex_ascii(packet, pkthdr->caplen); //Print packet data details
    
}
    
int sniff(pcap_t** sniffer, parsed_info* info){
    //Create and activate pcap sniffer and create a filter
    create_pcap_sniffer(sniffer, info);
    //Apply rules from CLI to pcap filter
    apply_pcap_filter(sniffer, info);

    //start sniffer loop to capture spefific amount of packets
    int ret_code = pcap_loop(*sniffer, info->packets_to_display, packet_parser, NULL);
    if(ret_code != 0){
        fprintf(stderr, "ERR: [PCAP_LOOP] %s\n", pcap_geterr(*sniffer));
        return -1;
    }
    //Close sniffer and free memory
    pcap_close(*sniffer);
    free(info);
    return 0;
}