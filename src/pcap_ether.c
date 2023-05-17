#include "target.h"

struct options_sniffer opts;

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN) {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    // Start with the Ethernet header
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    if (opts.sniffer_flag == 1) {
        // Print SOURCE DEST TYPE LENGTH fields
        printf("[ Ethernet Header ]\n");
        printf("    %s -> ", ether_ntoa((struct ether_addr *) eptr->ether_shost));
        printf("%s\n", ether_ntoa((struct ether_addr *) eptr->ether_dhost));

        // Check to see if we have an IP packet
        if (ether_type == ETHERTYPE_IP) printf("[ IPv4 Header ]\n");
        else if (ether_type == ETHERTYPE_IPV6) printf("[ IPV6 Header ]\n");
        else if (ether_type == ETHERTYPE_ARP) printf("[ ARP Header ]\n");
        else if (ether_type == ETHERTYPE_REVARP) printf("[ RARP Header ]\n");
        else if (ether_type == ETHERTYPE_LOOPBACK) printf("[ Loopback ]\n");
        else printf("[ Unknown ]\n");
        printf("    Total length: %d\n", length);
    }
    return ether_type;
}
