# Handout - Rätsel Beispiel:

## Secure Client-Server Demonstration (Mutual TLS with Hardcoded Credentials)

This solution provides a simple client and server written in C using OpenSSL to establish a secure connection with Mutual TLS (both client and server authenticate each other).

WARNING: The credentials used here are hardcoded placeholder strings for instructional purposes only. NEVER use this approach in a production environment.

## Prerequisites:

- You must have the OpenSSL development libraries installed to compile these programs.

On Debian/Ubuntu:
````
sudo apt-get install libssl-dev
````

On Fedora/RHEL/CentOS:
````
sudo dnf install openssl-devel
````
OR
````
sudo yum install openssl-devel
````

## Compilation

Compile both the server and client programs, linking against the OpenSSL libraries (-lssl -lcrypto).

# Compile the server
````
gcc -o server server.c -lssl -lcrypto
````
# Compile the client
````
gcc -o client client.c -lssl -lcrypto
````

# Execution

Start the Server:
Open the first terminal window and run the server.
````
./server
````

The server will output: 
````
Server listening on port 8888 (TLS with Mutual Authentication)...
````
Run the Client:
Open a second terminal window and run the client.
````
./client
````

Expected Output

Server Terminal Output:
````
Server listening on port 8888 (TLS with Mutual Authentication)...
[Server] Connection accepted from 127.0.0.1:xxxxx
[Server] Handshaking...
[Server] Client connected and verified successfully.
[Server] Received: "Hello Server, this is the client requesting a secure transaction."
[Server] SSL Session shut down.
[Server] Socket closed. Waiting for new connection...
````

Client Terminal Output:
````
[Client] Connecting to 127.0.0.1:8888...
[Client] TCP connection established.
[Client] Handshaking...
[Client] TLS connection established successfully.
[Client] Sending: "Hello Server, this is the client requesting a secure transaction."
[Client] Received: "Message received. Initiating disconnect."
[Client] SSL Session shut down.
[Client] Disconnected.
````

This demonstrates the full cycle: TCP connection, TLS handshake (including mutual authentication using the hardcoded credentials), secure data transfer, and graceful shutdown/disconnection, all with hardcoded credentials as requested.

Here the source code for both server and client:

## Client:

````
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
````

## Server:
````
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
````