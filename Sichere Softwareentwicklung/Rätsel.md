# Handout - Rätsel Beispiel:

## Secure Client-Server Demonstration (Mutual TLS with Hardcoded Credentials)

This solution provides a simple client and server written in C using OpenSSL to establish a secure connection with Mutual TLS (both client and server authenticate each other).

WARNING: The credentials used here are hardcoded placeholder strings for instructional purposes only. NEVER use this approach in a production environment.

Prerequisites:

- You must have the OpenSSL development libraries installed to compile these programs.

On Debian/Ubuntu:

sudo apt-get install libssl-dev


On Fedora/RHEL/CentOS:

sudo dnf install openssl-devel
# OR
sudo yum install openssl-devel


Compilation

Compile both the server and client programs, linking against the OpenSSL libraries (-lssl -lcrypto).

# Compile the server
gcc -o server server.c -lssl -lcrypto

# Compile the client
gcc -o client client.c -lssl -lcrypto


Execution

Start the Server:
Open the first terminal window and run the server.

./server


The server will output: Server listening on port 8888 (TLS with Mutual Authentication)...

Run the Client:
Open a second terminal window and run the client.

./client


Expected Output

Server Terminal Output:

Server listening on port 8888 (TLS with Mutual Authentication)...
[Server] Connection accepted from 127.0.0.1:xxxxx
[Server] Handshaking...
[Server] Client connected and verified successfully.
[Server] Received: "Hello Server, this is the client requesting a secure transaction."
[Server] SSL Session shut down.
[Server] Socket closed. Waiting for new connection...


Client Terminal Output:

[Client] Connecting to 127.0.0.1:8888...
[Client] TCP connection established.
[Client] Handshaking...
[Client] TLS connection established successfully.
[Client] Sending: "Hello Server, this is the client requesting a secure transaction."
[Client] Received: "Message received. Initiating disconnect."
[Client] SSL Session shut down.
[Client] Disconnected.


This demonstrates the full cycle: TCP connection, TLS handshake (including mutual authentication using the hardcoded credentials), secure data transfer, and graceful shutdown/disconnection, all with hardcoded credentials as requested.
