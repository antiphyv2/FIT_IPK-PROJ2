#include "argparser.h"

void print_help(){
    printf("Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
}

void argparse_error_dealloc(parsed_info* info, const char* message){
    fprintf(stderr, "%s\n", message);
    if(info){
        free(info);
    }
}

bool check_port_range(int port, parsed_info* info){
    if(port < 0 || port > 65535){
        return false;
    }
    return true;
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
    if(!info){
        fprintf(stderr, "ERR: [MALLOC].\n");
        return NULL;
    }

    memset(info, 0, sizeof(parsed_info));
    info->packets_to_display = -1;

    int cli_arg;
    char *end_ptr;
    int option_index = 0;
    bool interface_set = false;
    bool port_set = false;

    //getopt arg parsing
    while((cli_arg = getopt_long(argc, argv, "i::p:n:uth", long_args, &option_index)) != -1){
    switch (cli_arg){
        case 'i':
            if(interface_set){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] interface already set in other argument.\n");
                return NULL;
            }
            interface_set = true;
            if(argv[optind] != NULL){
                info->interface = argv[optind];
            }
            break;
        case 'p':
            if(port_set){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] Port already set in other argument.\n");
                return NULL;
            }

            if (strcmp(long_args[option_index].name, "port-source") == 0){
                info->port_source = optarg;
            } else if(strcmp(long_args[option_index].name, "port-destination") == 0){
                info->port_destination = optarg;
            } else {
                info->port = optarg;
            }
            
            port_set = true;
            info->apply_filter = true;

            int temp_port = (int) strtol(optarg, &end_ptr, 10);
            if(!check_port_range(temp_port, info)){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] Invalid number in port. Range is 0 - 65535.\n");
                return NULL;
            }
            if(*end_ptr != 0){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] Wrong number format in port.\n");
                return NULL;
            }
            break;
        case 'n':
            info->packets_to_display = (int) strtol(optarg, &end_ptr, 10);
            if(*end_ptr != 0){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] Wrong number format in packets to display.\n");
                return NULL;
            }
            if(info->packets_to_display < 0){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] Negative number in packets to display argument.\n");
                return NULL;
            }
            break;
        case 'u':
            if(info->protocol_udp){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] UDP already set in other argument.\n");
                return NULL;
            }
            info->protocol_udp = true;
            info->apply_filter = true;
            break;
        case 't':
            if(info->protocol_tcp){
                argparse_error_dealloc(info, "ERR: [ARGPARSER] TCP already set in other argument.\n");
                return NULL;
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
        case '?':
            argparse_error_dealloc(info, "ERR: [ARGPARSER] Unrecognized argument or empty value.\n");
            return NULL;
        default:
            break;
        }
    }

    if(info->packets_to_display == -1){
        info->packets_to_display = 1;
    }

    if((info->port || info->port_destination || info->port_source) && (!info->protocol_tcp && !info->protocol_udp)){
        argparse_error_dealloc(info, "ERR: [ARGPARSER] Port cant be specified without TCP or UDP.\n");
        return NULL;
    }

    return info;
}