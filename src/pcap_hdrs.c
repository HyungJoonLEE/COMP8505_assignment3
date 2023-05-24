/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_hdrs.c -   program to process the packet headers
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
--	DESIGNERS:		Based on the code by Martin Casado Aman Abdulla, Aman Abdulla
--					Also code was taken from tcpdump source, namely the following files..
--					print-ether.c
--					print-ip.c
--					ip.h
--					Modified & redesigned: Aman Abdulla: 2006, 2014, 2016
--
--	STUDENT:		HyungJoon LEE
-------------------------------------------------------------------------------------------------*/

#include "target.h"
#include "extern.h"

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int16_t type = handle_ethernet(args, pkthdr, packet);

    /* handle the IP packet */
    if(type == ETHERTYPE_IP) handle_IP(args, pkthdr, packet);

    /* handle the ARP packet */
    else if (type == ETHERTYPE_ARP) {}

    /* handle reverse arp packet */
    else if (type == ETHERTYPE_REVARP){}
}


// This function will parse the IP header and print out selected fields of interest
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;

    ip = (struct my_ip*) (packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);
    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip);
    version = IP_V(ip);

    // make sure that the packet is of a valid length
    if (length < sizeof(struct my_ip)) {
        if (opts.pcap2_flag == TRUE) printf("   Truncated IP %d", length);
        exit (1);
    }

    // verify version
    if(version != 4) {
        if (opts.pcap2_flag == TRUE) printf("    Unknown version %d\n", version);
        exit (1);
    }

    // verify the header length */
    if(hlen < 5 ) {
        if (opts.pcap2_flag == TRUE) printf("  Bad header length %d \n", hlen);
    }

    // Ensure that we have as much of the packet as we should
    if (length < (u_int)len) {
        if (opts.pcap2_flag == TRUE)
            printf("\n  Truncated IP - %d bytes missing\n", (u_int) len - length);
    }

    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0 ) {	// i.e, no 1's in first 13 bits
        if (opts.pcap2_flag == TRUE) {
            printf("    Version: %d\n", version);
            printf("    Header Length: %d\n", hlen);
            printf("    Fragment Offset: %d\n", off);
            printf("    IP: %s -> ", inet_ntoa(ip->ip_src));
            printf("%s\n", inet_ntoa(ip->ip_dst));

            // Make payload
            sprintf(opts.buffer, "    Version: %d\n"
                                 "    Header Length: %d\n"
                                 "    Fragment Offset: %d\n"
                                 "    IP: %s -> ", version, hlen, off,
                    inet_ntoa(ip->ip_src));
            sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                    ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
            memset(opts.buffer, 0, sizeof(opts.buffer));

            sprintf(opts.buffer, "%s\n", inet_ntoa(ip->ip_dst));
            sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                    ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
            memset(opts.buffer, 0, sizeof(opts.buffer));
        }
        if (opts.target_flag != TRUE)
            strcpy(opts.temp_ip, inet_ntoa(ip->ip_src));
    }

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            if (opts.pcap2_flag == TRUE) {
                printf("    Protocol: TCP\n");
                strcpy(opts.buffer, "    Protocol: TCP\n");
                sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                       (struct sockaddr *) &serv_addr, sizeof(serv_addr));
                memset(opts.buffer, 0, sizeof(opts.buffer));
                handle_TCP(args, pkthdr, packet);
            }
            break;
        case IPPROTO_UDP:
            if (opts.pcap2_flag == TRUE) {
                printf("    Protocol: UDP\n");
                strcpy(opts.buffer, "    Protocol: UDP\n");
                sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                       (struct sockaddr *) &serv_addr, sizeof(serv_addr));
                memset(opts.buffer, 0, sizeof(opts.buffer));
            }
            handle_UDP(args, pkthdr, packet);
            break;
        case IPPROTO_ICMP:
            if (opts.pcap2_flag == TRUE) {
                printf("    Protocol: ICMP\n");
                strcpy(opts.buffer, "    Protocol: ICMP\n");
                sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                       (struct sockaddr *) &serv_addr, sizeof(serv_addr));
                memset(opts.buffer, 0, sizeof(opts.buffer));
            }
            break;
        case IPPROTO_IP:
            if (opts.pcap2_flag == TRUE) {
                printf("    Protocol: IP\n");
                strcpy(opts.buffer, "    Protocol: IP\n");
                sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                       (struct sockaddr *) &serv_addr, sizeof(serv_addr));
                memset(opts.buffer, 0, sizeof(opts.buffer));
            }
            break;
        default:
            if (opts.pcap2_flag == TRUE) {
                printf("    Protocol: unknown\n");
                strcpy(opts.buffer, "    Protocol: unknown\n");
                sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                       (struct sockaddr *) &serv_addr, sizeof(serv_addr));
                memset(opts.buffer, 0, sizeof(opts.buffer));
            }
            break;
    }
}


// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct sniff_tcp *tcp = 0;          // The TCP header
	const struct my_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload

  	int size_ip;
    int size_tcp;
    int size_payload;


    if (opts.pcap2_flag == TRUE) printf ("[ TCP Header ]\n");

    ip = (struct my_ip*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip) * 4;

    // define/compute tcp header offset
    tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20) {
        if (opts.pcap2_flag == TRUE) printf("   * Control Packet? length: %u bytes\n", size_tcp);
        exit(1);
    }

    if (opts.pcap2_flag == TRUE) {
        printf("    Src port: %d\n", ntohs(tcp->th_sport));
        printf("    Dst port: %d\n", ntohs(tcp->th_dport));

        sprintf(opts.buffer, "[ TCP Header ]\n"
                             "    Src port: %d\n"
                             "    Dst port: %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
               (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        memset(opts.buffer, 0, sizeof(opts.buffer));

    }


    // define/compute tcp payload (segment) offset
    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);


    // Print payload data, including binary translation
    if (size_payload > 0) {
        if (opts.pcap2_flag == TRUE) {
            printf("    Payload (%d bytes):\n", size_payload);
            sprintf(opts.buffer, "    Payload (%d bytes):\n", size_payload);
            sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                   (struct sockaddr *) &serv_addr, sizeof(serv_addr));
            memset(opts.buffer, 0, sizeof(opts.buffer));
        }
        print_payload(payload, size_payload);
    }
}


void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct sniff_udp *udp = 0;
    const struct my_ip *ip;              	// The IP header
    const char *payload;

    int size_ip;
    int size_udp;
    int size_payload;

    if (opts.pcap2_flag == TRUE) printf ("[ UDP Header ]\n");

    ip = (struct my_ip*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip) * 4;


    // define/compute udp header offset
    udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
    size_udp = 8;

    if (opts.pcap2_flag == TRUE) {
        printf("    Src port: %d\n", ntohs(udp->uh_sport));
        printf("    Dst port: %d\n", ntohs(udp->uh_dport));

        sprintf(opts.buffer, "[ UDP Header ]\n"
                             "    Src port: %d\n"
                             "    Dst port: %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
        sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
               (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        memset(opts.buffer, 0, sizeof(opts.buffer));
    }

    // define/compute tcp payload (segment) offset
    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_udp);

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);


    // Print payload data, including binary translation
    if (size_payload > 0) {
        if (opts.target_flag == TRUE) {
            if (opts.pcap2_flag == TRUE) {
                printf("    Payload (%d bytes):\n", size_payload);
                sprintf(opts.buffer, "    Payload (%d bytes):\n", size_payload);
                sendto(opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
                       (struct sockaddr *) &serv_addr, sizeof(serv_addr));
                memset(opts.buffer, 0, sizeof(opts.buffer));
            }
            print_payload(payload, size_payload);
        }
        else decrypt_payload(payload);
    }
}


void pkt_callback2(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    printf("\n=========================================================\n");
    strcpy(opts.buffer, "\n=========================================================\n");
    sendto( opts.target_socket, opts.buffer, strlen(opts.buffer), 0,
            ( struct sockaddr*)&serv_addr, sizeof(serv_addr));
    memset(opts.buffer, 0, sizeof(opts.buffer));

    u_int16_t type = handle_ethernet(args, pkthdr, packet);

    /* handle the IP packet */
    if(type == ETHERTYPE_IP) handle_IP(args, pkthdr, packet);
}
