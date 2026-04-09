#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/select.h>

/* ─────────────────────────────────────────────
   CONFIGURATION  — match server.c exactly
   ───────────────────────────────────────────── */
#define SERVER_IP    "127.0.0.1"   /* change to your server IP */
#define PORT         9000
#define BUFFER_SIZE  2048

static const unsigned char AES_KEY[32] = {
    0x4a,0x61,0x79,0x61,0x6e,0x74,0x68,0x4b,
    0x4c,0x6f,0x67,0x41,0x67,0x67,0x72,0x65,
    0x67,0x61,0x74,0x69,0x6f,0x6e,0x53,0x79,
    0x73,0x74,0x65,0x6d,0x32,0x30,0x32,0x35
};

/* ─────────────────────────────────────────────
   AES-256-CBC ENCRYPT
   Output layout: [ IV (16 bytes) | ciphertext ]
   Returns total bytes, or -1 on error.
   ───────────────────────────────────────────── */
static int aes_encrypt(const unsigned char *in,  int in_len,
                        unsigned char       *out) {
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;
    memcpy(out, iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }

    int len = 0, total = 0;
    if (EVP_EncryptUpdate(ctx, out + 16, &len, in, in_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    total += len;

    if (EVP_EncryptFinal_ex(ctx, out + 16 + total, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return 16 + total;
}

/* ─────────────────────────────────────────────
   AES-256-CBC DECRYPT
   Returns plaintext length, or -1 on error.
   ───────────────────────────────────────────── */
static int aes_decrypt(const unsigned char *in,  int in_len,
                        unsigned char       *out, int *out_len) {
    if (in_len <= 16) return -1;

    const unsigned char *iv         = in;
    const unsigned char *ciphertext = in + 16;
    int                  ct_len     = in_len - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }

    int len = 0;
    *out_len = 0;
    if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    *out_len += len;

    if (EVP_DecryptFinal_ex(ctx, out + *out_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    *out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    out[*out_len] = '\0';
    return 0;
}

/* ─────────────────────────────────────────────
   MAIN
   Usage:  ./client <client_id> auto
           ./client <client_id> manual
   ───────────────────────────────────────────── */
int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage: ./client <client_id> auto|manual\n");
        return 1;
    }

    char *client_id = argv[1];
    char *mode      = argv[2];

    /* ── socket setup ── */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    struct sockaddr_in srv = {0};
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons(PORT);
    srv.sin_addr.s_addr = inet_addr(SERVER_IP);

    /* ── non-blocking check for backpressure signals ── */
    /* We use select() with timeout=0 to poll without blocking */

    srand(time(NULL) ^ (unsigned)getpid());

    char *logs[] = {
        "User logged in",
        "File uploaded successfully",
        "CPU usage high — 92%",
        "Disk almost full — 95% used",
        "Network connection established",
        "Unauthorized access attempt detected",
        "Service restarted",
        "Memory usage normal"
    };
    int log_count = 8;

    int   seq          = 0;          /* sequence number, increments per send  */
    float send_delay   = 1.0f;       /* seconds between sends (backpressure)  */

    unsigned char enc_buf[BUFFER_SIZE];
    unsigned char plain[BUFFER_SIZE];
    char          msg[BUFFER_SIZE];

    printf("Client %s started in %s mode\n", client_id, mode);
    printf("Server: %s:%d\n\n", SERVER_IP, PORT);

    while (1) {

        /* ────────────────────────────────────────────
           CHECK FOR BACKPRESSURE SIGNAL FROM SERVER
           Uses select() so we never block here.
           ──────────────────────────────────────────── */
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        struct timeval tv = {0, 0};   /* timeout = 0 → pure poll */

        if (select(sockfd + 1, &readfds, NULL, NULL, &tv) > 0) {
            unsigned char raw[BUFFER_SIZE];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(sockfd, raw, sizeof(raw), 0,
                             (struct sockaddr *)&from, &from_len);
            if (n > 0) {
                int plain_len = 0;
                if (aes_decrypt(raw, n, plain, &plain_len) == 0) {
                    if (strcmp((char *)plain, "SLOW_DOWN") == 0) {
                        send_delay *= 2.0f;   /* double the delay */
                        if (send_delay > 10.0f) send_delay = 10.0f;
                        printf("[BACKPRESSURE] SLOW_DOWN received — delay now %.1fs\n",
                               send_delay);
                    } else if (strcmp((char *)plain, "OK") == 0) {
                        send_delay = 1.0f;    /* reset to normal */
                        printf("[BACKPRESSURE] OK received — delay reset to 1.0s\n");
                    }
                }
            }
        }

        /* ────────────────────────────────────────────
           BUILD AND SEND LOG MESSAGE
           Format:  SEQ:<num>|Client<id>: <message>
           ──────────────────────────────────────────── */
        if (strcmp(mode, "auto") == 0) {

            int idx = rand() % log_count;
            snprintf(msg, sizeof(msg), "SEQ:%d|Client%s: %s",
                     seq, client_id, logs[idx]);

        } else if (strcmp(mode, "manual") == 0) {

            printf("Enter message (or 'exit'): ");
            fflush(stdout);

            char input[900];
            if (fgets(input, sizeof(input), stdin) == NULL) break;
            input[strcspn(input, "\n")] = '\0';

            if (strcmp(input, "exit") == 0) {
                printf("Client exiting.\n");
                break;
            }

            snprintf(msg, sizeof(msg), "SEQ:%d|Client%s: %s",
                     seq, client_id, input);

        } else {
            printf("Invalid mode. Use 'auto' or 'manual'\n");
            break;
        }

        /* ── encrypt ── */
        int enc_len = aes_encrypt(
            (unsigned char *)msg, strlen(msg), enc_buf);

        if (enc_len < 0) {
            printf("[ERROR] Encryption failed\n");
            continue;
        }

        /* ── send ── */
        sendto(sockfd, enc_buf, enc_len, 0,
               (struct sockaddr *)&srv, sizeof(srv));

        printf("[SENT] seq=%-4d  delay=%.1fs  %s\n", seq, send_delay, msg);

        seq++;

        /* ── respect backpressure delay ── */
        if (strcmp(mode, "auto") == 0) {
            /* sleep in small increments so backpressure check stays responsive */
            int ticks = (int)(send_delay * 10);
            for (int t = 0; t < ticks; t++) {
                usleep(100000);   /* 100ms per tick */
            }
        }
    }

    close(sockfd);
    return 0;
}
