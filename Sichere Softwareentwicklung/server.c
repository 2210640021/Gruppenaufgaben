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

#define SERVER_BIND_IP "127.0.0.1"
#define PORT 8888
#define BUFFER_SIZE 1024

// Server Certificate Chain (Identity)
const char *SERVER_CERT_PEM =
"-----BEGIN CERTIFICATE-----\n"
"DUMMY SERVER CERTIFICATE CONTENT\n"
"Replace this with your actual server certificate in production.\n"
"-----END CERTIFICATE-----\n";

// Server Private Key
const char *SERVER_KEY_PEM =
"-----BEGIN RSA PRIVATE KEY-----\n"
"DUMMY SERVER PRIVATE KEY CONTENT\n"
"Replace this with your actual server private key in production.\n"
"-----END RSA PRIVATE KEY-----\n";

// Client CA/Certificate to trust (Server's trust store for client verification)
const char *CLIENT_CA_PEM =
"-----BEGIN CERTIFICATE-----\n"
"DUMMY CLIENT CA (ROOT) CERTIFICATE CONTENT\n"
"This is needed for the server to verify the connecting client's identity.\n"
"-----END CERTIFICATE-----\n";

int load_cert_key_from_mem(SSL_CTX *ctx) {
    // 1. Load Server Certificate
    BIO *bio_cert = BIO_new_mem_buf((void*)SERVER_CERT_PEM, -1);
    X509 *cert = PEM_read_bio_X509(bio_cert, NULL, 0, NULL);
    BIO_free(bio_cert);

    if (!cert) {
        fprintf(stderr, "Error loading server certificate from memory.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        fprintf(stderr, "Error setting server certificate.\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 0;
    }
    X509_free(cert);

    // 2. Load Server Private Key
    BIO *bio_key = BIO_new_mem_buf((void*)SERVER_KEY_PEM, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio_key, NULL, 0, NULL);
    BIO_free(bio_key);

    if (!key) {
        fprintf(stderr, "Error loading server private key from memory.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        fprintf(stderr, "Error setting server private key.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(key);
        return 0;
    }
    EVP_PKEY_free(key);

    // 3. Load Client CA for Mutual TLS verification (Trust Store)
    printf("[Server Init] Loading hardcoded Client CA certificate into trust store.\n");
    BIO *bio_ca = BIO_new_mem_buf((void*)CLIENT_CA_PEM, -1);
    X509 *ca_cert = PEM_read_bio_X509(bio_ca, NULL, 0, NULL);
    BIO_free(bio_ca);
    if (!ca_cert) {
        fprintf(stderr, "Error loading client CA certificate from memory.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (X509_STORE_add_cert(store, ca_cert) <= 0) {
        fprintf(stderr, "Error adding client CA certificate to store.\n");
        ERR_print_errors_fp(stderr);
        X509_free(ca_cert);
        return 0;
    }
    X509_free(ca_cert);

    // Set context to require client certificate verification (Mutual TLS)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    return 1;
}

void handle_client(int client_sock, SSL_CTX *ctx) {
    SSL *ssl = NULL;
    char buffer[BUFFER_SIZE] = {0};
    int bytes_read;
    int ret = 0;

    // 1. Create a new SSL structure for the connection
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "SSL_new failed.\n");
        ERR_print_errors_fp(stderr);
        close(client_sock);
        return;
    }

    // 2. Attach the socket descriptor to the SSL structure
    if (SSL_set_fd(ssl, client_sock) == 0) {
        fprintf(stderr, "SSL_set_fd failed.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_sock);
        return;
    }

    printf("[Server] Handshaking...\n");

    // 3. Perform the SSL Handshake
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "[Server] SSL Handshake failed!\n");
        ERR_print_errors_fp(stderr);
        // Fall through to cleanup
    } else {
        printf("[Server] Client connected and verified successfully.\n");

        // 4. Data Exchange (Read from client)
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = 0;
            printf("[Server] Received: \"%s\"\n", buffer);

            // 5. Data Exchange (Write response)
            const char *response = "Message received. Initiating disconnect.";
            SSL_write(ssl, response, strlen(response));
        } else if (bytes_read == 0) {
             printf("[Server] Connection closed by client.\n");
        } else {
            fprintf(stderr, "[Server] Error during SSL_read.\n");
            ERR_print_errors_fp(stderr);
        }

        // 6. Graceful Disconnection
        ret = SSL_shutdown(ssl);
        if (ret < 0) {
            // Handle error during shutdown
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_R_MIGHT_RETRY) {
                 // Try again if the client sent a close_notify but the server hasn't sent its yet
                ret = SSL_shutdown(ssl);
                if (ret < 0) {
                    fprintf(stderr, "[Server] SSL_shutdown error after retry.\n");
                    ERR_print_errors_fp(stderr);
                }
            } else {
                fprintf(stderr, "[Server] SSL_shutdown failed.\n");
                ERR_print_errors_fp(stderr);
            }
        }
        printf("[Server] SSL Session shut down.\n");
    }

    // 7. Cleanup
    if (ssl) SSL_free(ssl);
    close(client_sock);
    printf("[Server] Socket closed. Waiting for new connection...\n");
}


int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx = NULL;

    // --- OpenSSL Initialization ---
    // Initialize OpenSSL libraries
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context object (using TLS v1.2/1.3 protocol)
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load certificate, key, and client CA into the context
    if (!load_cert_key_from_mem(ctx)) {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // --- Standard Socket Setup ---
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Unable to create socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Reuse port for quick restarts
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_BIND_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid server bind address");
        close(server_sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to bind socket");
        close(server_sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 1) < 0) {
        perror("Unable to listen on socket");
        close(server_sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on %s:%d (TLS with Mutual Authentication)...\n", SERVER_BIND_IP, PORT);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        char *client_ip = inet_ntoa(client_addr.sin_addr);
        printf("\n[Server] Connection accepted from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        handle_client(client_sock, ctx);
    }

    // Cleanup (This part is unreachable in the current infinite loop, but good practice)
    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
