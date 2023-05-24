/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_ether.c -   Process Ethernet packets
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 15, 2023
--				    Added personal function for assignment
--
--	REVISIONS:		(Date and nic_description)
--
--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
--					Also code was taken from tcpdump source, namely the following files..
--					print-ether.c
--					print-ip.c
--					ip.h
--					Modified & redesigned: Aman Abdulla: April 23, 2006
--
--	STUDENT:		HyungJoon LEE
-------------------------------------------------------------------------------------------------*/

#include "target.h"
#include "extern.h"

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
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

    if (opts.pcap2_flag == TRUE) {
        // Print SOURCE DEST TYPE LENGTH fields
        printf("[ Ethernet Header ]\n");
        printf("    %s -> ", ether_ntoa((struct ether_addr *) eptr->ether_shost));
        printf("%s\n", ether_ntoa((struct ether_addr *) eptr->ether_dhost));
        sprintf(opts.buffer, "[ Ethernet Header ]\n    %s -> ",
                ether_ntoa((struct ether_addr *) eptr->ether_shost));
        sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
        memset(opts.buffer, 0, sizeof(opts.buffer));
        sprintf(opts.buffer, "%s\n",
                ether_ntoa((struct ether_addr *) eptr->ether_dhost));
        sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
        memset(opts.buffer, 0, sizeof(opts.buffer));

        // IPv4 packet
        if (ether_type == ETHERTYPE_IP) {
            printf("[ IPv4 Header ]\n");
            strcpy(opts.buffer, "[ IPv4 Header ]\n");
        }
        // IPv6 packet
        else if (ether_type == ETHERTYPE_IPV6) {
            printf("[ IPV6 Header ]\n");
            strcpy(opts.buffer, "[ IPv6 Header ]\n");
        }
        // ARP packet
        else if (ether_type == ETHERTYPE_ARP) {
            printf("[ ARP Header ]\n");
            strcpy(opts.buffer, "[ ARP Header ]\n");
        }
        // Reversed ARP packet
        else if (ether_type == ETHERTYPE_REVARP) {
            printf("[ RARP Header ]\n");
            strcpy(opts.buffer, "[ RARP Header ]\n");
        }
        // Loopback packet
        else if (ether_type == ETHERTYPE_LOOPBACK) {
            printf("[ Loopback ]\n");
            strcpy(opts.buffer, "[ Loopback ]\n");
        }
        else {
            printf("[ Unknown ]\n");
            strcpy(opts.buffer, "[ Unknown ]\n");
        }
        sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
        memset(opts.buffer, 0, sizeof(opts.buffer));


        printf("    Total length: %d\n", length);
        sprintf(opts.buffer, "    Total length: %d\n", length);
        sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
        memset(opts.buffer, 0, sizeof(opts.buffer));
    }
    return ether_type;
}
