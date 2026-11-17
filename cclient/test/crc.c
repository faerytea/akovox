/**
 * This code mimics `cksum` program
 * using POSIX CRC32 calculation from
 * `akomsgparser.c`, but with lots
 * of limitations.
 */
#include "../akomsgparser.h"

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    int opt;
    char format[] = "%u\n";
    FILE *stream = stdin;
	while ((opt = getopt(argc, argv, "hndxXi:")) != -1) {
        switch (opt) {
            case 'n':
                format[2] = '\0';
                break;
            case 'd':
                format[1] = 'u';
                break;
            case 'x':
                format[1] = 'x';
                break;
            case 'X':
                format[1] = 'X';
                break;
            case 'i':
                stream = fopen(optarg, "rb");
                break;
            default:
                fprintf(
                    stderr, 
                    "Usage: %s [-ndxX] [-i file]\n"
                    "Options:\n"
                    "\t-n     \tNo newline\n"
                    "\t-d     \tDecimal sum (default)\n"
                    "\t-x     \tHex sum\n"
                    "\t-X     \tHex sum (uppercase)\n"
                    "\t-i file\tRead data from file (default: stdin)\n"
                    ,
                    argv[0]
                );
                return 1;
        }
    }
    uint8_t *buffer = malloc(0x10000); // up to 64k
    size_t len = 0, read;
    while (0 < (read = fread(buffer, sizeof(char), 0x10000 - len, stream))) {
        len += read;
    }
    if (feof(stream))
        printf(format, posix_crc32(buffer, len));
    else if (ferror(stream)) 
        perror("Read failed: ");
    else 
        fprintf(stderr, "Unknown problem (probable file is bigger than 64k)\n");
    if (stream != stdin) fclose(stream);
    return 0;
}