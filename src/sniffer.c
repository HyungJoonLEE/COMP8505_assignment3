#include "sniffer.h"


int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    bpf_u_int32 maskp;          // subnet mask
    bpf_u_int32 netp;           // ip
    char* nic_device;
    pcap_t* nic_fd;
    u_char* args = NULL;

    // Options must be passed in as a string
    if (argc < 2) {
        fprintf(stdout,"Usage: %s <Number of Packets> \"<Filter String>\"\n",argv[0]);
        return 0;
    }

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

    pcap_loop(nic_fd, atoi(argv[1]), pkt_callback, args);


    return EXIT_SUCCESS;
}


void program_setup(int argc, char *argv[]) {
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);

    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


