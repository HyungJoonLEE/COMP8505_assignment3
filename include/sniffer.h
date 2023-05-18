#ifndef COMP8505_ASSIGNMENT3_SNIFFER_H
#define COMP8505_ASSIGNMENT3_SNIFFER_H

#include "common.h"

struct options_sniffer {
    char sniff_ip[16];
    uint16_t sniff_port;
    char sniff_protocol[5];
    unsigned int sniff_count;
    char command[64];
    char encrypt_command[64];
    int sniffer_socket;
    unsigned int dest_ip;
};


void options_sniffer_init(struct options_sniffer *opts);
void get_user_input(struct options_sniffer *opts);
void get_ip_address(struct options_sniffer *opts);
void get_port(struct options_sniffer *opts);
void get_protocol(struct options_sniffer *opts);
bool confirm_user_input(struct options_sniffer *opts);
bool is_valid_ipaddress(char *ip_address);
bool is_valid_port(char *port);
void encrypt_and_create_instruction_file(struct options_sniffer *opts);
void send_instruction(struct options_sniffer *opts);

#endif //COMP8505_ASSIGNMENT3_SNIFFER_H
