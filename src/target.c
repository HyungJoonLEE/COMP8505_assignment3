#include "common.h"
#include "target.h"
#include "conversion.h"
#include "error.h"


int main(int argc, char *argv[]) {
    struct options_target opts;
    struct sockaddr_in sniffer_address;
    struct sockaddr_in serv_addr, clnt_addr;
    char buffer[256] = {0};
    char receive[256] = {0};
    int sniffer_address_size = sizeof(struct sockaddr_in);
    fd_set read_fds, copy_fds;
    int fd_max, fd_num;
    struct timeval timeout;
    int exit_flag = 0;

    options_target_init(&opts);
    parse_target_command(argc, argv, &opts);
    options_target_process(&opts);

    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(opts.target_socket, &read_fds);
    fd_max = opts.target_socket;

    while (1) {
        if (exit_flag == 1) break;
        copy_fds = read_fds;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        fd_num = select(fd_max + 1, &copy_fds, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        } else if (fd_num == 0) continue; // time out

        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &copy_fds)) {
                if (i == opts.target_socket) {
                    opts.sniffer_socket = accept(opts.target_socket, (struct sockaddr *) &sniffer_address,
                                                 &sniffer_address_size);
                    FD_SET(opts.sniffer_socket, &read_fds);
                    if (fd_max < opts.sniffer_socket) fd_max = opts.sniffer_socket;
                    add_new_sniffer(&opts, opts.sniffer_socket, &sniffer_address);
                    write(opts.sniffer_socket, CONNECTION_SUCCESS, strlen(CONNECTION_SUCCESS));
                }
                if (i == STDIN_FILENO) {
                    if (fgets(buffer, sizeof(buffer), stdin)) {
                        buffer[strlen(buffer) - 1] = 0;
                        if (strcmp(buffer, EXIT) == 0) {
                            printf("EXIT program");
                            exit_flag = 1;
                            break;
                        }
                        write(opts.sniffer_socket, buffer, sizeof(buffer));
                        memset(buffer, 0, sizeof(char) * 256);
                    }
                }
                if (i == opts.sniffer_socket) {
                    read(opts.sniffer_socket, receive, sizeof(receive));
                    printf("PACKET = [ %s ]\n", receive);
                    memset(receive, 0, sizeof(char) * 256);
                }
            }
        }
    }
    close(opts.target_socket);
    return EXIT_SUCCESS;
}

void options_target_init(struct options_target *opts) {
    memset(opts, 0, sizeof(struct options_target));
    opts->port = DEFAULT_PORT;
}


void parse_target_command(int argc, char *argv[], struct options_target *opts) {
    int c;
    int option_index = 0;

    static struct option long_options[] = {
            {"port", required_argument, 0, 'd'},
            {0, 0, 0, 0}
    };

    while((c = getopt_long(argc, argv, "p:", long_options, &option_index)) != -1) {  // NOLINT(concurrency-mt-unsafe)
        switch(c) {
            case 'd': {
                opts->port = parse_port(optarg, 10);
                break;
            }
            default:
                printf("Usage: %s [-d | --port PORT] ", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}


void options_target_process(struct options_target *opts) {
    struct sockaddr_in proxy_address;
    int option = TRUE;

    opts->target_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (opts->target_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    proxy_address.sin_family = AF_INET;
    proxy_address.sin_port = htons(opts->port);
    proxy_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (proxy_address.sin_addr.s_addr == (in_addr_t) -1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }

    option = 1;
    setsockopt(opts->target_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));


    if (bind(opts->target_socket, (struct sockaddr *) &proxy_address, sizeof(struct sockaddr_in)) == -1) {
        perror("bind() ERROR\n");
        exit(EXIT_FAILURE);
    }


    if (listen(opts->target_socket, BACKLOG) == -1) {
        perror("listen() ERROR\n");
        exit(EXIT_FAILURE);
    }
}


void add_new_sniffer(struct options_target *opts, int sniffer_socket, struct sockaddr_in *sniffer_address) {
    char buffer[20];

    inet_ntop(AF_INET, &sniffer_address->sin_addr, buffer, sizeof(buffer));
    printf("New sniffer: [ %s ]\n", buffer);
}

