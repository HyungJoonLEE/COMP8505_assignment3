#ifndef PROJECT_SENDER_H
#define PROJECT_SENDER_H

#include "common.h"



struct options_sniffer {
    char *target;
    in_port_t port;
    char protocol[5];
    int sniffer_socket;
    int target_socket;
    char file_name[20];
    int fd_in;
    int fd_out;
};


void options_sniffer_init(struct options_sniffer *opts);
void parse_sniffer_command(int argc, char *argv[], struct options_sniffer *opts);
int options_sniffer_process(struct options_sniffer *opts);
void cleanup(struct options_sniffer *opts);
void get_file_list(struct options *opts);


void send_file(struct options *opts, fd_set* read_fds);


#endif //PROJECT_SENDER_H
