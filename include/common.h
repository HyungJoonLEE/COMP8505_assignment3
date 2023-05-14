#ifndef PROJECT_COMMON_H
#define PROJECT_COMMON_H


#include <stdio.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stddef.h>
#include <limits.h>
#include <sys/types.h>
#include <getopt.h>
#include <regex.h>
#include <inttypes.h>
#include <pcap.h>


#define DEFAULT_PORT 53000
#define TRUE 1
#define FALSE 0
#define START "start"
#define STOP "stop"
#define EXIT "exit"
#define CONNECTION_SUCCESS "Successfully connected to the proxy"



/**
 * A function to be documented.
 *
 * @param str a parameter to be documented.
 * @return a return value to be documented.
 */
int display(const char *str);


#endif //PROJECT_COMMON_H
