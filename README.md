Name: Corey Sather
Username: Sathercd3383
Assignment: Secure Inter-process Communication (IPC)

### How to Compile
make sendfile

OR

gcc -Wall -Wextra sendfile.cpp -o sendfile -lstdc++

### Description
Securely transfers a file from a client to the server with an XOR-based encryption scheme.

### Execution
./sendfile [--verbose] [--server] [--ip <ip address>] [--port <port>] [--file <FILE>] [--pkt <packet size (KB)>] [--key <KEY>]

### Note
- sendfile defaults to running as the client though passing client or --client via the command-line will work as well
- IP address is optional; defaulting to 127.0.0.1
- Key is optional; resulting in file being sent insecurely