#include "common.h"


void check_root_user(void) {
    if(geteuid() != 0) {
        printf("\nYou need to be root to run this.\n\n");
        exit(0);
    }
}


char encrypt_decrypt(char input) {
    uint8_t key = 'Z';
    return (char) (input ^ key);
}
