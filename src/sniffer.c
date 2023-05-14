#include "sniffer.h"
#include "conversion.h"
#include "error.h"
#include "common.h"


int main(int argc, char *argv[]) {
    unsigned int expected_ack = 0;
    char buffer[256] = {0};
    char receive[256] = {0};
    fd_set read_fds, copy_fds;
    int fd_max, fd_num;
    int exit_flag = 0;
    struct timeval timeout;
    struct options_sniffer opts;


    options_sniffer_init(&opts);
    parse_sniffer_command(argc, argv, &opts);
    opts.target_socket = options_sniffer_process(&opts);

    fd_max = opts.target_socket;
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(opts.target_socket, &read_fds);

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
                    read(opts.target_socket, receive, sizeof(receive));
                    printf("PACKET = [ %s ]\n", receive);
                    memset(receive, 0, sizeof(char) * 256);
                }
                if (i == STDIN_FILENO) {
                    if (fgets(buffer, sizeof(buffer), stdin)) {
                        buffer[strlen(buffer) - 1] = 0;
                        if (strcmp(buffer, EXIT) == 0) {
                            printf("EXIT program");
                            close(opts.target_socket);
                            exit_flag = 1;
                            break;
                        }
                        write(opts.target_socket, buffer, sizeof(buffer));
                        memset(buffer, 0, sizeof(char) * 256);
                    }
                }
            }
        }
    }

    close(opts.sniffer_socket);
    return EXIT_SUCCESS;
}

void options_sniffer_init(struct options_sniffer *opts) {
    memset(opts, 0, sizeof(struct options_sniffer));
    opts->fd_in  = STDIN_FILENO;
    opts->fd_out = STDOUT_FILENO;
    opts->port   = DEFAULT_PORT;
}


void parse_sniffer_command(int argc, char *argv[], struct options_sniffer *opts) {
    int c;
    int option_index = 0;

    static struct option long_options[] = {
            {"target", required_argument, 0, 't'},
            {"port", required_argument, 0, 'd'},
            {"protocol", required_argument, 0, 'p'},
            {0, 0, 0, 0}
    };


    while((c = getopt_long(argc, argv, "t:d:p:", long_options, &option_index)) != -1) {  // NOLINT(concurrency-mt-unsafe)
        switch(c) {
            case 't': {
                opts->target = optarg;
                break;
            }
            case 'd': {
                opts->port = parse_port(optarg, 10);
                break;
            }
            case 'p': {
                strcpy(opts->protocol, optarg);
                if (strlen(opts->protocol) == 0) {
                    // TODO: ANY protocol
                }
                break;
            }
            default:
                printf("Usage: %s "
                       "[-t | --target IP] "
                       "[-d | --port PORT] "
                       "[-p | --protocol PROTOCOL] ", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}


int options_sniffer_process(struct options_sniffer *opts) {
    char message[50] = {0};
    ssize_t target_connection_test;
    struct sockaddr_in server_addr;

    if(opts->target) {
        opts->target_socket = socket(AF_INET, SOCK_STREAM, 0);

        if (opts->target_socket == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(opts->port);
        server_addr.sin_addr.s_addr = inet_addr(opts->target);

        if (server_addr.sin_addr.s_addr ==  (in_addr_t) - 1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        opts->sniffer_socket = connect(opts->target_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));

        if (opts->sniffer_socket == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        target_connection_test = read(opts->target_socket, message, sizeof(message));
        if (target_connection_test == -1) {
            perror("FAILED TO CONNECT TARGET\n");
            exit(EXIT_FAILURE);
        }
        else
            printf("%s\n", message);
    }
    return opts->target_socket;
}

