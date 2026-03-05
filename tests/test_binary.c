#include <stdio.h>
#include <string.h>

int encrypt(char* buf, int len) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= 0x42;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <string>\n", argv[0]);
        return 1;
    }
    
    char buffer[256];
    strncpy(buffer, argv[1], 255);
    buffer[255] = '\0';
    
    encrypt(buffer, strlen(buffer));
    
    printf("Encrypted: ");
    for(int i = 0; i < strlen(buffer); i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
    
    return 0;
}
