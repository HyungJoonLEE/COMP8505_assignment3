#ifndef COMP8505_ASSIGNMENT3_SNIFFER_H
#define COMP8505_ASSIGNMENT3_SNIFFER_H

#include "common.h"

struct options_sniffer {
    char sniff_ip[16];
    char sniff_instruction[128];
    char command[128];
    char encrypt_command[128];
    int sniffer_socket;
};


void options_sniffer_init(struct options_sniffer *opts);
void get_user_input(struct options_sniffer *opts);
void get_ip_address(struct options_sniffer *opts);
void get_instruction(struct options_sniffer *opts);
void get_protocol(struct options_sniffer *opts);
bool confirm_user_input(struct options_sniffer *opts);
bool is_valid_ipaddress(char *ip_address);
void encrypt_and_create_instruction_file(struct options_sniffer *opts);
void send_instruction(struct options_sniffer *opts);
void sig_handler(int signum);

#endif //COMP8505_ASSIGNMENT3_SNIFFER_H
