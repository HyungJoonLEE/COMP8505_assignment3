#include "common.h"
#include "target.h"
#include "conversion.h"
#include "error.h"


int main(int argc, char *argv[]) {
    pid_t pid;
    struct options_target opts;
    struct sockaddr_in sniffer_address;
    int sniffer_socket;
    int max_socket_num; // IMPORTANT Don't forget to set +1
    char buffer[256] = {0};
    char response[256] = {0};
    int sniffer_address_size = sizeof(struct sockaddr_in);
    ssize_t received_data;
    fd_set read_fds; // fd_set chasing reading status

    options_target_init(&opts);
    parse_target_command(argc, argv, &opts);
    options_target_process(&opts);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(opts.target_socket, &read_fds);
        FD_SET(opts.sniffer_socket[0], &read_fds);
        max_socket_num = get_max_socket_number(&opts) + 1;
//        printf("wait for sniffer\n");
        if (select(max_socket_num, &read_fds, NULL, NULL, NULL) < 0) {
            printf("select() error");
            exit(1);
        }

        if (FD_ISSET(opts.target_socket, &read_fds)) {
            sniffer_socket = accept(opts.target_socket, (struct sockaddr *)&sniffer_address, &sniffer_address_size);
            if (sniffer_socket == -1) {
                perror("accept() error");
                exit(EXIT_FAILURE);
            }

            add_new_sniffer(&opts, sniffer_socket, &sniffer_address);
            write(sniffer_socket, CONNECTION_SUCCESS, strlen(CONNECTION_SUCCESS));
            printf("Successfully added sniffer_fd to sniffer_socket[%d]\n", opts.sniffer_count - 1);
        }

        // RECEIVE DATA FROM SNIFFER
        if (FD_ISSET(opts.sniffer_socket[0], &read_fds)) {
            received_data = read(opts.sniffer_socket[0], buffer, sizeof(buffer));
            buffer[received_data] = 0;
            // when user type "exit"
            if (strlen(buffer) != 0)
                printf("\n[ sniffer ]: %s", buffer);
            if (received_data < 0) {
                remove_sniffer(&opts, opts.sniffer_socket[0]);
                break;
            }
            if (strcmp(buffer, EXIT) == 0) {
                close(opts.sniffer_socket[0]);
            }
        }
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(buffer, sizeof(buffer), stdin)) {
                if (strcmp(buffer, EXIT) != 0) {
                    write(opts.target_socket, buffer, sizeof(buffer));
                    printf("EXIT program");
                    if (opts.sniffer_socket[0] == 0) {
                        close(opts.target_socket);
                        break;
                    }
                    else puts("Sniffer is still connected");
                }
            }
        }
    }
    close(opts.sniffer_count);
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

    for (int i = 0; i < opts->sniffer_count; i++) {
        opts->sniffer_socket[i] = 0;
    }

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

    opts->sniffer_socket[opts->sniffer_count] = sniffer_socket;
    opts->sniffer_count++;
    printf("Current sniffer count = %d\n", opts->sniffer_count);
}


void remove_sniffer(struct options_target *opts, int sniffer_socket) {
    close(opts->sniffer_socket[sniffer_socket]);

    if (sniffer_socket != opts->sniffer_count - 1)
        opts->sniffer_socket[sniffer_socket] = opts->sniffer_socket[opts->sniffer_count - 1];

    opts->sniffer_count--;
    printf("Current sniffer count = %d\n", opts->sniffer_count);
}

// Finding maximum socket number
int get_max_socket_number(struct options_target *opts) {
    // Minimum socket number start with server socket(opts->proxy_socket)
    int max = opts->target_socket;
    int i;

    for (i = 0; i < opts->sniffer_count; i++)
        if (opts->sniffer_socket[i] > max)
            max = opts->sniffer_socket[i];

    return max;
}
