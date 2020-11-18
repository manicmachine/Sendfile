#define __POSIX_SOURCE
#include <iostream>
#include <iomanip>
#include <netdb.h>
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
int toggleEncryption(char *buffer, int length, string key, int offset);
string getLocalAddress();
string checkSum(string data);


int main(int argc, char *argv[]) {
  int offset = 0; // used to keep track of the modulus for encrypting packets that aren't divisble by pktSize
  int sockfd;
  unsigned int pktNum = 0;
  unsigned int pktSizeBytes = 0;
  size_t bytesRead = 0;
  Role role = CLIENT;
  string pktSize = "";
  string ipAddress = "";
  string localIPAddress = "";
  string port = "";
  string file = "";
  string key = "";
  FILE *pFile;

  // Parse command-line arguments 
  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--server") == 0 || strcmp(argv[i], "server") == 0) {
        role = SERVER;
      }

      if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "verbose") == 0) {
        printf("Verbose: ON\n");
        VERBOSE = true;
      }

      if (strcmp(argv[i], "--ip") == 0 || strcmp(argv[i], "ip") == 0) {
        ipAddress = argv[i + 1];
      }

      if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "port") == 0) {
        port = argv[i + 1];
      }

      if (strcmp(argv[i], "--file") == 0 || strcmp(argv[i], "file") == 0) {
        file = argv[i + 1];
      }

      if (strcmp(argv[i], "--pkt") == 0 || strcmp(argv[i], "pkt") == 0) {
        pktSize = argv[i + 1];
      }

      if (strcmp(argv[i], "--key") == 0 || strcmp(argv[i], "key") == 0) {
        key = argv[i + 1];
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

  localIPAddress = getLocalAddress();
  if (VERBOSE) {
    printf("Discovered local IP Address: %s\n", localIPAddress.c_str());
  }

  if (ipAddress.empty()) {
    printf("Connect to IP address: ");
    getline(cin, ipAddress);
  }

  // Since the application recognizes connections from the same host as coming from 0.0.0.0, we should check
  // if the user is expecting a connection from itself. If so, set ipAddress to 0.0.0.0 so it'll accept local connections
  if ((strcmp(ipAddress.c_str(), localIPAddress.c_str()) == 0)|| ipAddress.empty()) {
    if (VERBOSE && !ipAddress.empty()) {
      printf("Local IP address provided; Remapping to 127.0.0.1 for simplicity\n");
    }

    ipAddress = "127.0.0.1";
  }

  if (port.empty()) {
    printf("Port #: ");
    getline(cin, port);
  }

  if (role == CLIENT) {
    if (file.empty()) {
      printf("File to be sent: ");
      getline(cin, file);
    }

    if (pktSize.empty()) {
      printf("Pkt Size: ");
      getline(cin, pktSize);

      if (pktSize.empty()) {
        pktSize = "32"; // set default packet size if none provided
      }
    }
  } else {
    pktSize = "32";

    if (file.empty()) {
      printf("Save file to (default: stdout): ");
      getline(cin, file);
    }

    // If nothing is provided, default to stdout. As such, we'll need a temp file to collect the incoming data before
    // it can be processes. Once finished, the temp file will then be deleted
    if (file.empty() || strcmp(file.c_str(), "stdout") == 0) {
      file = "./.sendfile_tmp";
    }
  }

  if (key.empty()) {
    printf("Enter encryption key: ");
    getline(cin, key);
  }

  pktSizeBytes = KB * stoi(pktSize);
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

    printf("Encryption key: %s, Key length: %lu\n", key.c_str(), key.length());
  }

  char *fileBuffer = (char *) calloc(KB, stoi(pktSize));

  if (fileBuffer == NULL) {
    fprintf(stderr, "Internal error: Unable to initialize file buffer\nError #: %d\n", errno);
    exit(-1);
  }

  // Open file for read/writing as necessary
  if (role == SERVER) {
    // Store incoming packets in a temporary file for md5 and then forward along to stdout
    pFile = std::fopen(file.c_str(), "w+");
  } else {
    pFile = std::fopen(file.c_str(), "r");
  }

  if (pFile == NULL) {
    fprintf(stderr, "File error: Unable to open %s\nError #: %d\n", file.c_str(), errno);
    exit(-1);
  }

  if (role == CLIENT) {
    // If client, read data from provided file and send each packet along to it's destination
    sockfd = openConnection(ipAddress, stoi(port));

    // Send pktsize to server
    if (write(sockfd, pktSize.c_str(), sizeof(pktSize)) < 0) {
      fprintf(stderr, "Error writing data to socket\nError #: %d", errno);
      exit(-1);
    }

    if (sockfd < 0) {
      // Socket failed to open; openConnection would've already printed the error so just exit
      exit(-1);
    }

    do {
      bytesRead = std::fread(fileBuffer, sizeof(char), pktSizeBytes, pFile);
      // If the number of bytes read is less than the size of a packet, we'll need to be sure to zero out the difference
      if (bytesRead == 0) {
        break;
      } else if (bytesRead < pktSizeBytes) {
        memset(fileBuffer + bytesRead, 0, (pktSizeBytes - bytesRead));
      }

      if (VERBOSE) {
        printf("Bytes read: %lu\n", bytesRead);
      }

      if (!key.empty()) {
        offset = toggleEncryption(fileBuffer, bytesRead, key, offset);
      }

      // Send data
      if (write(sockfd, fileBuffer, bytesRead) < 0) {
        fprintf(stderr, "Error writing data to socket\nError #: %d", errno);
        exit(-1);
      }

      if (pktNum <= 10 || VERBOSE) {
        printf("Sent encrypted packet#%d - ", pktNum);
        printf("%02hhX%02hhX ... %02hhX%02hhX\n", (unsigned char) fileBuffer[0],(unsigned char) fileBuffer[1], (unsigned char) fileBuffer[bytesRead - 2], (unsigned char) fileBuffer[bytesRead - 1]);
      }

      pktNum++;
    } while (bytesRead == pktSizeBytes);

    printf("\nSend Success!\n");
  } else {
    // If server, read incoming data from open socket and write to file
    sockfd = startServer(ipAddress, stoi(port));

    // The first 32 bytes sent from the client is the packet size. Read and configure as appropriate
    read(sockfd, fileBuffer, sizeof(pktSize));
    pktSize = fileBuffer;

    if ((unsigned int) (KB * stoi(pktSize)) != pktSizeBytes) {
      pktSizeBytes = KB * stoi(pktSize);
      fileBuffer = (char *) realloc(fileBuffer, pktSizeBytes);

      if (fileBuffer == NULL) {
        fprintf(stderr, "Internal error: Unable to initialize file buffer\nError #: %d\n", errno);
        exit(-1);
      }
    }

    if (VERBOSE) {
      printf("Received packet size: %d KB\n", stoi(pktSize));
    }

    if (sockfd < 0) {
      // Socket failed to open; startServer would've already printed the error so just exit
      exit(-1);
    }

    do {
      bytesRead = read(sockfd, fileBuffer, pktSizeBytes);
      // If the number of bytes read is less than the size of a packet, we'll need to be sure to zero out the difference
      if (bytesRead == 0) {
        break;
      } else if (bytesRead < pktSizeBytes) {
        memset(fileBuffer + bytesRead, 0, (pktSizeBytes - bytesRead));
      }

      if (VERBOSE) {
        printf("Bytes read: %lu\n", bytesRead);
      }

      if (pktNum <= 10 || VERBOSE) {
        printf("Rec encrypted packet#%d - ", pktNum);
        printf("%02hhX%02hhX ... %02hhX%02hhX\n", (unsigned char) fileBuffer[0],(unsigned char) fileBuffer[1], (unsigned char) fileBuffer[bytesRead - 2], (unsigned char) fileBuffer[bytesRead - 1]);
      }

      pktNum++;

      if (!key.empty()) {
        offset = toggleEncryption(fileBuffer, bytesRead, key, offset);
      }

      fwrite(fileBuffer, sizeof(char), bytesRead, pFile);
    } while (bytesRead > 0);

    printf("\nReceive success!\n");
  }

  // If file destination is stdout, reset file cursor and read the entirity of the tmp file
  if (role == SERVER && strcmp(file.c_str(), "./.sendfile_tmp") == 0) {
    fseek(pFile, 0, SEEK_SET);
    
    do {
      bytesRead = fread(fileBuffer, sizeof(char), pktSizeBytes, pFile);

      if (bytesRead < pktSizeBytes) {
        memset(fileBuffer + bytesRead, 0, (pktSizeBytes - bytesRead));
      }

      fprintf(stdout, "%s", fileBuffer);
    } while (bytesRead == pktSizeBytes);

    printf("\n");
  }

  close(sockfd);
  fclose(pFile);
  free(fileBuffer);

  printf("MD5:\n%s\n", checkSum(file).c_str());
  
  // Delete temp file when everything is said and done
  if (role == SERVER && (strcmp(file.c_str(), "./.sendfile_tmp") == 0)) {
    remove(file.c_str());
  }
}

// Open socket and connect with server, returning the socket file descriptor. If return < 0, then an error occurred
int openConnection(string ipAddress, int port) {
  struct sockaddr_in serverAddr = {0,0,0,0};
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    fprintf(stderr, "Socket creation error\nError #: %d\n", errno);
    return -1;
  }

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);

  if (inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr) < 1) {
    fprintf(stderr, "Invalid IP address provided\nError #: %d\n", errno);
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0 ) {
    fprintf(stderr, "Failed to connect to %s:%d\nError #: %d\n", ipAddress.c_str(), port, errno);
    return -1;
  }

  if (VERBOSE) {
    printf("Connection made to %s:%d\n", ipAddress.c_str(), port);
  }

  return sockfd;
}

// Open socket to receive data and return socket file descriptor. If return < 0, then an error occurred
int startServer(string ipAddress, int port) {
  int option = 1;
  char *clientIP;
  struct sockaddr_in serverAddr = {0,0,0,0};
  struct sockaddr_in connInfo = {0,0,0,0};
  socklen_t connInfoSize = sizeof(connInfo);
  int sockfd = socket(AF_INET, SOCK_STREAM, 0), acceptfd;

  if (sockfd < 0) {
    fprintf(stderr, "Socket creation error\nError #: %d\n", errno);
    return -1;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option))) {
    fprintf(stderr, "Failed to set socket options\nError #: %d\n", errno);
    return -1;
  }

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = INADDR_ANY;
  serverAddr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
    fprintf(stderr, "Failed to bind socket to the port %d\nError #: %d\n", port, errno);
    return -1;
  }

  if (listen(sockfd, 1) < 0) {
    fprintf(stderr, "Failed to begin listening on port %d\nError #: %d\n", port, errno);
    return -1;
  }

  if (VERBOSE) {
    printf("Server bound and listening on port %d\n", port);
  }

  // Loop over incoming connections until a connection arrives from the specified ip address
  do {
    acceptfd = accept(sockfd, (struct sockaddr *) &connInfo, &connInfoSize);
    clientIP = inet_ntoa(connInfo.sin_addr);

    if (VERBOSE) {
      printf("Attempted connection from %s\n", clientIP);
    }

    if (acceptfd < 0) {
      fprintf(stderr, "Failed to accept connection on port %d\nError #: %d\n", port, errno);
      return -1;
    }

    if (inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr) < 1) {
      fprintf(stderr, "Invalid IP address provided\nError #: %d\n", errno);
      return -1;
    }

    if (VERBOSE && (connInfo.sin_addr.s_addr == serverAddr.sin_addr.s_addr)) {
      printf("Connection established.\n");
    }
  } while (connInfo.sin_addr.s_addr != serverAddr.sin_addr.s_addr);

  close(sockfd);
  return acceptfd;
}

// Encrypt or decrypt provided data by XOR'ing data with provided key
int toggleEncryption(char *buffer, int length, string key, int offset) {
  int i;
  for (i = 0; i < length; i++) {
    buffer[i] = buffer[i] ^ key[(i + offset) % key.length()];
  }

  return (i + offset) % key.length();
}

// Discover the localhost's ip address by resolving it's hostname
string getLocalAddress() {
  char hostname[256];
  char *ipAddress;

  gethostname(hostname, sizeof(hostname));
  ipAddress = inet_ntoa(*((struct in_addr*) gethostbyname(hostname)->h_addr_list[0])); // returns a static char array so no need to free

  return ipAddress;
}

// Invoke local md5sum to get digital signature of provided file
string checkSum(string data) {
  string command = "/usr/bin/md5sum " + data;
  FILE *pipe = popen(command.c_str(), "r");

  if (pipe == NULL) {
    fprintf(stderr, "Error opening pipe\nError #: %d\n", errno);
    exit(1);
  }

  char buffer[64];
  string md5;

  while (!feof(pipe)) {
    if (fgets(buffer, 64, pipe) != NULL) {
      md5 += buffer;
    }
  }

  md5 = md5.substr(0, 33);
  pclose(pipe);

  return md5;
}