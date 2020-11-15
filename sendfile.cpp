#define __POSIX_SOURCE
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

#define KB 1024

enum Role { CLIENT, SERVER };
bool VERBOSE = false;

int openConnection(string ipAddress, int port);
int startServer(string ipAddress, int port);
void toggleEncryption(char *buffer, string key);
string checkSum(string data);


int main(int argc, char *argv[]) {
  int pktNum = 0;
  int sockfd;
  Role role = CLIENT;
  string ipAddress;
  string port;
  string file;
  string pktSize = "32";
  string key;
  FILE *pFile;

  // Parse command-line arguments 
  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      printf("%s\n", argv[i]);
      if (strcmp(argv[i], "--server") == 0 || strcmp(argv[i], "server") == 0) {
        role = SERVER;
      }

      if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "verbose") == 0) {
        printf("Verbose: ON\n");
        VERBOSE = true;
      }
    }
  }

  if (VERBOSE) {
    if (role == CLIENT) {
      printf("Role: Client\n");
    } else {
      printf("Role: Server\n");
    }
  }

  
  printf("Connect to IP address: ");
  getline(cin, ipAddress);

  printf("Port #: ");
  getline(cin, port);

  if (role == CLIENT) {
    printf("File to be sent: ");
    getline(cin, file);

    printf("Pkt Size: ");
    getline(cin, pktSize);
  } else {
    printf("Save file to (default: stdout): ");
    getline(cin, file);

    if (file.empty()) {
      file = "stdout";
    }
  }

  printf("Enter encryption key: ");
  getline(cin, key);

  printf("\n");

  if (VERBOSE) {
    printf("Entered Values:\n");
    printf("Role: %d\n", role);
    printf("IP Address: %s\n", ipAddress.c_str());
    printf("Port: %s\n", port.c_str());
    
    if (role == CLIENT) {
      printf("Pkt Size (KB): %s\n", pktSize.c_str());
      printf("From File: %s\n", file.c_str());
    } else {
      printf("Save File To: %s\n", file.c_str());
    }

    printf("Encryption key: %s\n", key.c_str());
  }

  char *fileBuffer = (char *) calloc(KB, stoi(pktSize));

  if (fileBuffer == NULL) {
    fprintf(stderr, "Internal error: Unable to initialize file buffer");
    exit(1);
  }

  // Open file for read/writing as necessary
  if (role == SERVER) {
    if (strcmp(file.c_str(), "stdout") == 0) {
      // Store incoming packets in a temporary file for md5 and then forward along to stdout afterwards
      pFile = std::fopen("./.sendFile_tmp", "w+");
    } else {
      pFile = std::fopen(file.c_str(), "w");
    }
  } else {
    pFile = std::fopen(file.c_str(), "r");
  }

  if (pFile == NULL) {
    fprintf(stderr, "File error: Unable to open %s", file.c_str());
    exit(1);
  }

  if (role == CLIENT) {
    // If client, read data from provided file and send each packet along to it's destination
    size_t kbytesRead = 0;
    kbytesRead = std::fread(fileBuffer, KB, stoi(pktSize), pFile);

    // Connect to server
    sockfd = openConnection(ipAddress, stoi(port));
    if (sockfd < 0) {
      // openConnection would've already printed the error so just exit
      exit(-1);
    }

    do {
      // TODO: Test that this actually works
      // if (kbytesRead < stoi(pktSize)) {
      //   // If the current read length was less than the packet size, we'll need to zero out the remainder of the buffer
      //   memset(fileBuffer + (kbytesRead * KB), 0, ((stoi(pktSize) - kbytesRead) * KB));
      // }

      if (VERBOSE) {
        printf("Pkt Content #%d: %s \n", pktNum, fileBuffer);
      }

      toggleEncryption(fileBuffer, key);
      if (VERBOSE) {
        printf("Encrypted content: %s", fileBuffer);
      }

      // Send data
      // write(sockfd, fileBuffer, KB * stoi(pktSize));
      // Send only data read from file -- confirm if this is OK
      write(sockfd, fileBuffer, kbytesRead * KB);

      if (pktNum <= 10) {
        string sbuffer = fileBuffer;
        printf("Sent encrypted packet#%d - ", pktNum);
        printf("%02hhX%02hhX ... %02hhX%02hhX\n", sbuffer[0], sbuffer[1], sbuffer[sbuffer.length() - 2], sbuffer[sbuffer.length() - 1]);
      }

      pktNum++;
      kbytesRead = std::fread(fileBuffer, KB, stoi(pktSize), pFile);
    } while (kbytesRead == stoi(pktSize));

    printf("Send Success!\n");
  } else {
    // Server stuff
    sockfd = startServer(ipAddress, stoi(port));

    if (sockfd < 0) {
      // startServer would've already printed the error so just exit
      exit(-1);
    }

    while (read(sockfd, fileBuffer, stoi(pktSize) * KB)) {
      string sbuffer = fileBuffer;
      printf("Rec encrypted packet#%d - ", pktNum);
      printf("%02hhX%02hhX ... %02hhX%02hhX\n", sbuffer[0], sbuffer[1], sbuffer[sbuffer.length() - 2], sbuffer[sbuffer.length() - 1]);
      pktNum++;

      // TODO: Needs logic for stdout
      toggleEncryption(fileBuffer, key);
      std::fwrite(fileBuffer, sizeof(char), stoi(pktSize) * KB, pFile);      
    }
  }

  // TODO: Adjust logic to accomidate server and stdout
  string result = checkSum(file);
  printf("MD5:\n%s\n", result.c_str());

  fclose(pFile);
  free(fileBuffer);
}

// Open socket and connect with server and returns socket file descriptor. If return < 0, then an error occurred
int openConnection(string ipAddress, int port) {
  struct sockaddr_in serverAddr;
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    fprintf(stderr, "Socket creation error\n");
    return -1;
  }

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);

  if (inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr) < 1) {
    fprintf(stderr, "Invalid IP address provided\n");
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0 ) {
    fprintf(stderr, "Failed to connect to %s:%d", ipAddress.c_str(), port);
    return -1;
  }

  return sockfd;
}

// Open socket to receive data and return socket file descriptor. If return < 0, then an error occurred
int startServer(string ipAddress, int port) {
  int option = 1;
  struct sockaddr_in serverAddr;
  int sockfd = socket(AF_INET, SOCK_STREAM, 0), acceptfd;

  if (sockfd < 0) {
    fprintf(stderr, "Socket creation error\n");
    return -1;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option))) {
    fprintf(stderr, "Failed to set socket options\n");
    return -1;
  }

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = INADDR_ANY;
  serverAddr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
    fprintf(stderr, "Failed to bind socket to the port %d", port);
    return -1;
  }

  if (listen(sockfd, 0) < 0) {
    fprintf(stderr, "Failed to begin listening on port %d", port);
    return -1;
  }

  acceptfd = accept(sockfd, (struct sockaddr *) & serverAddr, (socklen_t *) sizeof(&serverAddr));
  if (acceptfd < 0) {
    fprintf(stderr, "Failed to accept connection on port %d", port);
    return -1;
  }

  return acceptfd;
}

// Encrypt or decrypt provided data by XOR'ing data with provided key
void toggleEncryption(char *buffer, string key) {
  if (VERBOSE) {
    printf("Key: %s, Key length: %lu\n", key.c_str(), key.length());
  }

  int i = 0;
  while (buffer[i] != '\n') {
    buffer[i] = buffer[i] ^ key[i % key.length()];
    i++;
  }
}

// Invoke local md5sum to get digital signature of provided file
string checkSum(string data) {
  string command = "/usr/bin/md5sum " + data;
  FILE *pipe = popen(command.c_str(), "r");

  if (pipe == NULL) {
    fprintf(stderr, "Error opening pipe.");
    exit(1);
  }

  char buffer[64];
  string md5;

  while (!feof(pipe)) {
    if (std::fgets(buffer, 64, pipe) != NULL) {
      md5 += buffer;
    }
  }

  md5 = md5.substr(0, 33);
  pclose(pipe);

  return md5;
}