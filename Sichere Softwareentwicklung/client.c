#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// Include OpenSSL libraries
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h> // Required for loading credentials from memory

#define SERVER_IP "127.0.0.1"
#define PORT 8888
#define BUFFER_SIZE 1024

// Client Certificate (for Mutual TLS Identity)
const char *CLIENT_CERT_PEM =
"-----BEGIN CERTIFICATE-----\n"
"DUMMY CLIENT CERTIFICATE CONTENT\n"
"Replace this with your actual client certificate in production.\n"
"-----END CERTIFICATE-----\n";

const char *CLIENT_KEY_PEM =
"-----BEGIN RSA PRIVATE KEY-----\n"
"DUMMY CLIENT PRIVATE KEY CONTENT\n"
"Replace this with your actual client private key in production.\n"
"-----END RSA PRIVATE KEY-----\n";

const char *SERVER_CA_PEM =
"-----BEGIN CERTIFICATE-----\n"
"DUMMY SERVER CA (ROOT) CERTIFICATE CONTENT\n"
"This is needed for the client to verify the server's identity.\n"
"-----END CERTIFICATE-----\n";

// Helper function to load certificate/key
int load_cert_key_from_mem(SSL_CTX *ctx) {
    // 1. Load client certificate
    BIO *bio_cert = BIO_new_mem_buf((void*)CLIENT_CERT_PEM, -1);
    X509 *cert = PEM_read_bio_X509(bio_cert, NULL, 0, NULL);
    BIO_free(bio_cert);

    if (!cert) {
        fprintf(stderr, "Error loading client certificate from memory.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        fprintf(stderr, "Error setting client certificate.\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 0;
    }
    X509_free(cert);

    // 2. Load client private key
    BIO *bio_key = BIO_new_mem_buf((void*)CLIENT_KEY_PEM, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio_key, NULL, 0, NULL);
    BIO_free(bio_key);

    if (!key) {
        fprintf(stderr, "Error loading client private key from memory.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        fprintf(stderr, "Error setting client private key.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(key);
        return 0;
    }
    EVP_PKEY_free(key);

    printf("[Client Init] Loading Server CA certificate into trust store.\n");
    BIO *bio_ca = BIO_new_mem_buf((void*)SERVER_CA_PEM, -1);
    X509 *ca_cert = PEM_read_bio_X509(bio_ca, NULL, 0, NULL);
    BIO_free(bio_ca);
    if (!ca_cert) {
        fprintf(stderr, "Error loading server CA certificate from memory.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (X509_STORE_add_cert(store, ca_cert) <= 0) {
        fprintf(stderr, "Error adding server CA certificate to store.\n");
        ERR_print_errors_fp(stderr);
        X509_free(ca_cert);
        return 0;
    }
    X509_free(ca_cert);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return 1;
}

int main() {
    int sock = -1;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char buffer[BUFFER_SIZE];
    int ret;
    const char *message = "Hello Server, this is the client requesting a secure transaction.";

    // --- OpenSSL Initialization ---
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context object (using TLS v1.2/1.3 protocol)
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!load_cert_key_from_mem(ctx)) {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // --- Standard Socket Setup ---
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convert IP string to binary format
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid hardcoded server address/ Address not supported");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // 1. Ping Check (TCP Reachability Check)
    printf("[Client] Performing TCP reachability check on %s:%d...\n", SERVER_IP, PORT);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        // This acts as the "ping" failure if the server is unreachable
        perror("[Client] ERROR: Hardcoded Server IP unreachable (TCP Check failed)");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("[Client] TCP reachability check successful. Connection established.\n");

    // 2. Create SSL structure and attach socket
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "SSL_new failed.\n");
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl, sock);

    // 3. Perform the SSL Handshake (includes server verification and client auth)
    printf("[Client] Handshaking...\n");
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[Client] SSL Handshake failed!\n");
        ERR_print_errors_fp(stderr);
        // Fall through to cleanup
    } else {
        printf("[Client] TLS connection established successfully.\n");

        // 4. Data Exchange (Write to server)
        printf("[Client] Sending: \"%s\"\n", message);
        SSL_write(ssl, message, strlen(message));

        // 5. Data Exchange (Read response from server)
        memset(buffer, 0, BUFFER_SIZE);
        ret = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

        if (ret > 0) {
            printf("[Client] Received: \"%s\"\n", buffer);
        } else if (ret == 0) {
            printf("[Client] Server closed the connection unexpectedly.\n");
        } else {
            fprintf(stderr, "[Client] Error during SSL_read.\n");
            ERR_print_errors_fp(stderr);
        }

        // 6. Graceful Disconnection
        ret = SSL_shutdown(ssl);
        if (ret == 0) {
            // Need a second call if the first one was non-blocking or only sent close_notify
            SSL_shutdown(ssl);
        } else if (ret < 0) {
            fprintf(stderr, "[Client] SSL_shutdown failed.\n");
            ERR_print_errors_fp(stderr);
        }
        printf("[Client] SSL Session shut down.\n");
    }

    // 7. Cleanup
    if (ssl) SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    printf("[Client] Disconnected.\n");

    return 0;
}
