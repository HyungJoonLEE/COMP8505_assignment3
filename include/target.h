#ifndef COMP_8005_ASSIGNMENT3_TARGET_H
#define COMP_8005_ASSIGNMENT3_TARGET_H

#include "common.h"

#define BACKLOG 5
#define DEFAULT_DATA_SEND_RATE 100
#define DEFAULT_ACK_RECEIVE_RATE 100


struct options_target {
    in_port_t port;
    int target_socket;
    int sniffer_count;
    int sniffer_socket[2];
};


void options_target_init(struct options_target *opts);
void parse_target_command(int argc, char *argv[], struct options_target *opts);
void options_target_process(struct options_target *opts);
void add_new_sniffer(struct options_target *opts, int sniffer_socket, struct sockaddr_in *sniffer_address);
int get_max_socket_number(struct options_target *opts);
void remove_sniffer(struct options_target *opts, int sniffer_socket);

#endif //COMP_8005_ASSIGNMENT3_TARGET_H
