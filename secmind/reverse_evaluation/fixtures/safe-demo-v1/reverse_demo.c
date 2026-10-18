#include <stdio.h>
#include <string.h>

#define XOR_KEY 0x5Au

/* These bytes decode to the training token and a reserved test domain. */
static const unsigned char encoded_token[] = {
    0x09, 0x1F, 0x19, 0x17, 0x13, 0x14, 0x1E, 0x77, 0x08,
    0x1F, 0x0C, 0x1F, 0x08, 0x09, 0x1F, 0x77, 0x15, 0x11
};

static const unsigned char encoded_domain[] = {
    0x2E, 0x28, 0x3B, 0x33, 0x34, 0x33, 0x34, 0x3D, 0x74,
    0x3F, 0x22, 0x3B, 0x37, 0x2A, 0x36, 0x3F, 0x74, 0x33,
    0x34, 0x2C, 0x3B, 0x36, 0x33, 0x3E
};

static void xor_decode(const unsigned char *encoded, size_t length, char *decoded) {
    size_t index;

    for (index = 0; index < length; ++index) {
        decoded[index] = (char)(encoded[index] ^ XOR_KEY);
    }
    decoded[length] = '\0';
}

static int token_matches(const char *input) {
    char token[sizeof(encoded_token) + 1];

    xor_decode(encoded_token, sizeof(encoded_token), token);
    return input != NULL && strcmp(input, token) == 0;
}

static int write_local_report(const char *domain) {
    FILE *report = fopen("reverse_demo_result.txt", "w");

    if (report == NULL) {
        return 0;
    }

    fprintf(report, "safe reverse training sample\n");
    fprintf(report, "reserved test domain: %s\n", domain);
    fprintf(report, "network access: disabled\n");
    fclose(report);
    return 1;
}

int main(int argc, char **argv) {
    char domain[sizeof(encoded_domain) + 1];

    xor_decode(encoded_domain, sizeof(encoded_domain), domain);

    if (argc != 2) {
        fprintf(stderr, "usage: %s <training-token>\n", argv[0]);
        return 1;
    }

    if (!token_matches(argv[1])) {
        puts("token rejected; no file was created");
        return 2;
    }

    if (!write_local_report(domain)) {
        fputs("could not write the local report\n", stderr);
        return 3;
    }

    puts("token accepted; local report created");
    return 0;
}
