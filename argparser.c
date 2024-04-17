#include "argparser.h"

void print_help(){
    printf("Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
}

void argparse_error_exit(parsed_info* info, const char* message){
    fprintf(stderr, "%s\n", message);
    free(info);
    exit(EXIT_FAILURE);
}

struct option long_args[] = {
    {"interface", optional_argument, NULL, 'i'},
    {"tcp", no_argument, 0, 't'},
    {"udp", no_argument, 0, 'u'},
    {"port-source", required_argument, 0, 'p'},
    {"port-destination", required_argument, 0, 'p'},
    {"arp", no_argument, 0, 'a'},
    {"icmp4", no_argument, 0, 'b'},
    {"icmp6", no_argument, 0, 'c'},
    {"igmp", no_argument, 0, 'd'},
    {"mld", no_argument, 0, 'e'},
    {0, 0, 0, 0}
};


parsed_info* parse_args(int argc, char* argv[]){
    parsed_info* info = malloc(sizeof(parsed_info));
    memset(info, 0, sizeof(parsed_info));
    info->port = -1;
    info->port_source = -1;
    info->port_destination = -1;

    int cli_arg;
    char *end_ptr;
    int option_index = 0;
    bool interface_set = false;
    bool port_set = false;
    bool packets_set = false;

    //getopt arg parsing
    while((cli_arg = getopt_long(argc, argv, "i::p:n:uth", long_args, &option_index)) != -1){
    switch (cli_arg){
        case 'i':
            if(interface_set){
                argparse_error_exit(info, "ERR: interface already set in other argument.\n");
            }
            interface_set = true;
            if (optarg) {
                info->interface = optarg;
            } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                info->interface = argv[optind++];
            }
            break;
        case 'p':
            if(port_set){
                argparse_error_exit(info, "ERR: Port already set in other argument.\n");
            }

            if (strcmp(long_args[option_index].name, "port-source") == 0){
                info->port_source = (int) strtol(optarg, &end_ptr, 10);
            } else if(strcmp(long_args[option_index].name, "port-destination") == 0){
                info->port_destination = (int) strtol(optarg, &end_ptr, 10);
            } else {
                info->port = (int) strtol(optarg, &end_ptr, 10);
            }

            port_set = true;
            info->apply_filter = true;

            if(*end_ptr != 0){
                argparse_error_exit(info, "ERR: Wrong number format in port.\n");
            }
            break;
        case 'n':
            info->packets_to_display = (int) strtol(optarg, &end_ptr, 10);
            if(*end_ptr != 0){
                argparse_error_exit(info, "ERR: Wrong number format in packets to display.\n");
            }
            packets_set = true;
            break;
        case 'u':
            if(info->protocol_udp){
                argparse_error_exit(info, "ERR: UDP already set in other argument.\n");
            }
            info->protocol_udp = true;
            info->apply_filter = true;
            break;
        case 't':
            if(info->protocol_tcp){
                argparse_error_exit(info, "ERR: TCP already set in other argument.\n");
            }
            info->protocol_tcp = true;
            info->apply_filter = true;
            break;
        case 'h':
            print_help();
            free(info);
            exit(EXIT_SUCCESS);
        case 'a':
            info->arp = true;
            info->apply_filter = true;
            break;
        case 'b':
            info->icmp_4 = true;
            info->apply_filter = true;
            break;
        case 'c':
            info->icmp_6 = true;
            info->apply_filter = true;
            break;
        case 'd':
            info->igmp = true;
            info->apply_filter = true;
            break;
        case 'e':
            info->mld = true;
            info->apply_filter = true;
            break;
        default:
            break;
        }
    }

    if(!packets_set){
        info->packets_to_display = 1;
    }
    return info;
}