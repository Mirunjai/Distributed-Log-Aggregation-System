#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* ─────────────────────────────────────────────
   CONFIGURATION
   ───────────────────────────────────────────── */
#define PORT              9000
#define BUFFER_SIZE       2048
#define MAX_CLIENTS       50
#define BACKPRESSURE_HIGH 20      /* packets/sec threshold → send SLOW_DOWN  */
#define BACKPRESSURE_LOW  10      /* packets/sec threshold → send OK          */

/* AES-256 pre-shared key — must be exactly 32 bytes, same in client.c */
static const unsigned char SECRET_KEY[32] = {
    0x4a,0x61,0x79,0x61,0x6e,0x74,0x68,0x4b,
    0x4c,0x6f,0x67,0x41,0x67,0x67,0x72,0x65,
    0x67,0x61,0x74,0x69,0x6f,0x6e,0x53,0x79,
    0x73,0x74,0x65,0x6d,0x32,0x30,0x32,0x35
};

/* ─────────────────────────────────────────────
   CLIENT TRACKING
   ───────────────────────────────────────────── */
typedef struct {
    struct sockaddr_in addr;
    int                active;
    int                expected_seq;   /* next expected sequence number      */
    int                pkt_count;      /* packets received in current window */
    time_t             window_start;   /* start of 1-second window           */
    int                throttled;      /* 1 = currently in SLOW_DOWN state   */
} ClientInfo;

static ClientInfo clients[MAX_CLIENTS];
static int        client_count = 0;

/* ─────────────────────────────────────────────
   FIND OR REGISTER CLIENT
   ───────────────────────────────────────────── */
static ClientInfo *get_client(struct sockaddr_in *addr) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i].active &&
            clients[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            clients[i].addr.sin_port        == addr->sin_port) {
            return &clients[i];
        }
    }
    if (client_count >= MAX_CLIENTS) return NULL;
    ClientInfo *c        = &clients[client_count++];
    c->addr              = *addr;
    c->active            = 1;
    c->expected_seq      = 0;
    c->pkt_count         = 0;
    c->window_start      = time(NULL);
    c->throttled         = 0;
    printf("[NEW CLIENT] %s:%d\n",
           inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    return c;
}

/* ─────────────────────────────────────────────
   AES-256-CBC DECRYPT
   Returns plaintext length, or -1 on error.
   Input  layout: [ IV (16 bytes) | ciphertext ]
   ───────────────────────────────────────────── */
static int aes_decrypt(const unsigned char *in,  int in_len,
                        unsigned char       *out, int *out_len) {
    if (in_len <= 16) return -1;

    const unsigned char *iv         = in;
    const unsigned char *ciphertext = in + 16;
    int                  ct_len     = in_len - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SECRET_KEY, iv) != 1) {
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
   AES-256-CBC ENCRYPT
   Output layout: [ IV (16 bytes) | ciphertext ]
   Returns total bytes written, or -1 on error.
   ───────────────────────────────────────────── */
static int aes_encrypt(const unsigned char *in,  int in_len,
                        unsigned char       *out) {
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;
    memcpy(out, iv, 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SECRET_KEY, iv) != 1) {
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
    return 16 + total;   /* IV + ciphertext */
}

/* ─────────────────────────────────────────────
   TIMESTAMP HELPER
   ───────────────────────────────────────────── */
static void get_time_str(char *buf, int size) {
    time_t now = time(NULL);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", localtime(&now));
}

/* ─────────────────────────────────────────────
   MAIN
   ───────────────────────────────────────────── */
int main(void) {

    /* ── open log file ── */
    FILE *fp = fopen("logs.txt", "a");
    if (!fp) { perror("fopen"); exit(1); }

    /* ── create UDP socket ── */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); exit(1); }

    /* ── bind ── */
    struct sockaddr_in srv = {0};
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons(PORT);
    srv.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("bind"); exit(1);
    }

    printf("=== Secure Log Aggregation Server ===\n");
    printf("Listening on port %d  (AES-256-CBC)\n\n", PORT);

    unsigned char raw[BUFFER_SIZE];
    unsigned char plain[BUFFER_SIZE];
    unsigned char resp_enc[BUFFER_SIZE];

    while (1) {

        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);

        /* ── receive encrypted packet ── */
        int n = recvfrom(sockfd, raw, sizeof(raw), 0,
                         (struct sockaddr *)&cli_addr, &cli_len);
        if (n < 0) { perror("recvfrom"); continue; }

        /* ── look up / register client ── */
        ClientInfo *client = get_client(&cli_addr);
        if (!client) {
            printf("[WARN] Max clients reached, dropping packet\n");
            continue;
        }

        /* ── decrypt ── */
        int plain_len = 0;
        if (aes_decrypt(raw, n, plain, &plain_len) != 0) {
            printf("[ERROR][%s] Decryption failed — bad key or corrupted packet\n",
                   inet_ntoa(cli_addr.sin_addr));
            continue;
        }

        /* ── parse:  SEQ:<num>|<message> ── */
        if (strncmp((char *)plain, "SEQ:", 4) != 0 ||
            strchr((char *)plain, '|') == NULL) {
            printf("[ERROR][%s] Invalid packet format\n",
                   inet_ntoa(cli_addr.sin_addr));
            continue;
        }

        int   seq_num = atoi((char *)plain + 4);
        char *msg_ptr = strchr((char *)plain, '|') + 1;

        char timebuf[30];
        get_time_str(timebuf, sizeof(timebuf));

        /* ── time ordering check ── */
        if (seq_num < client->expected_seq) {
            printf("[OUT-OF-ORDER][%s] expected %d got %d — dropped\n",
                   inet_ntoa(cli_addr.sin_addr),
                   client->expected_seq, seq_num);
            fprintf(fp, "[OUT-OF-ORDER][%s][%s] seq=%d (expected %d)\n",
                    inet_ntoa(cli_addr.sin_addr), timebuf,
                    seq_num, client->expected_seq);
            fflush(fp);
            continue;
        }
        if (seq_num > client->expected_seq) {
            printf("[GAP DETECTED][%s] missing seq %d..%d\n",
                   inet_ntoa(cli_addr.sin_addr),
                   client->expected_seq, seq_num - 1);
        }
        client->expected_seq = seq_num + 1;

        /* ── log the message ── */
        printf("[LOG][%s:%d][%s] seq=%-4d  %s\n",
               inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port),
               timebuf, seq_num, msg_ptr);
        fprintf(fp, "[LOG][%s:%d][%s] seq=%d  %s\n",
                inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port),
                timebuf, seq_num, msg_ptr);
        fflush(fp);

        /* ── backpressure ──────────────────────────────────────────
           Count packets in a 1-second sliding window.
           If rate > BACKPRESSURE_HIGH  →  send encrypted "SLOW_DOWN"
           If rate < BACKPRESSURE_LOW   →  send encrypted "OK"
           ────────────────────────────────────────────────────────── */
        client->pkt_count++;
        time_t now = time(NULL);

        if (now - client->window_start >= 1) {
            int rate = client->pkt_count;
            client->pkt_count    = 0;
            client->window_start = now;

            const char *signal = NULL;

            if (rate > BACKPRESSURE_HIGH && !client->throttled) {
                signal           = "SLOW_DOWN";
                client->throttled = 1;
                printf("[BACKPRESSURE] Sending SLOW_DOWN to %s (rate=%d pkt/s)\n",
                       inet_ntoa(cli_addr.sin_addr), rate);
            } else if (rate <= BACKPRESSURE_LOW && client->throttled) {
                signal           = "OK";
                client->throttled = 0;
                printf("[BACKPRESSURE] Sending OK to %s (rate=%d pkt/s)\n",
                       inet_ntoa(cli_addr.sin_addr), rate);
            }

            if (signal) {
                int enc_len = aes_encrypt(
                    (unsigned char *)signal, strlen(signal), resp_enc);
                if (enc_len > 0) {
                    sendto(sockfd, resp_enc, enc_len, 0,
                           (struct sockaddr *)&cli_addr, cli_len);
                }
            }
        }
    }

    fclose(fp);
    close(sockfd);
    return 0;
}
