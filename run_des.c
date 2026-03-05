#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/*
 * des.h provides the following functions and constants:
 *
 * generate_key, generate_sub_keys, process_message, ENCRYPTION_MODE, DECRYPTION_MODE
 *
 */
#include "des.h"

void ntlm_make_des_key(unsigned char *key56, unsigned char *key);

// Declare file handlers
static FILE *key_file, *input_file, *output_file;

// Declare action parameters
#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"

// DES key is 8 bytes long
#define DES_KEY_SIZE 8

int main(int argc, char* argv[]) {
    unsigned char nthash[16] = {0xfb,0xdc,0xd5,0x04,0x1c,0x96,0xdd,0xbd,0x82,0x22,0x42,0x70,0xb5,0x7f,0x11,0xfc};
    unsigned char challenge[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    unsigned char response[24] = {0};
    unsigned char key56[7];
    unsigned char des_key[8];
    unsigned char encrypted[8];
    key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

    printf("NT Hash: FBDCD5041C96DDBD82224270B57F11FC\n");

    for (int i = 0; i < 3; i++) {
        if (i == 0) memcpy(key56, nthash, 7);
        else if (i == 1) memcpy(key56, nthash + 7, 7);
        else {
            memcpy(key56, nthash + 14, 2);
            memset(key56 + 2, 0, 5);
        }

        printf("Key %d raw chunk: ", i+1);
        for (int j = 0; j < 7; j++) printf("%02X", key56[j]);
        printf("\n");

        ntlm_make_des_key(key56, des_key);

        printf("Key %d full DES key: ", i+1);
        for (int j = 0; j < 8; j++) printf("%02X", des_key[j]);
        printf("\n");

        generate_sub_keys(des_key, key_sets);
        process_message(challenge, encrypted, key_sets, ENCRYPTION_MODE);

        printf("DES(Key %d, Challenge): ", i+1);
        for (int j = 0; j < 8; j++) printf("%02X", encrypted[j]);
        printf("\n");

        memcpy(response + i*8, encrypted, 8);
    }

    printf("NTLMv1 Response: ");
    for (int i = 0; i < 24; i++) printf("%02X", response[i]);
    printf("\n");

    free(key_sets);
    return 0;
}