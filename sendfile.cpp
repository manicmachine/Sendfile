#include <iostream>
#include <stdio.h>
#include <string.h>
using namespace std;

#define KB 1024

enum Role { CLIENT, SERVER };

bool VERBOSE = false;

string checkSum(string data);

int main(int argc, char *argv[]) {
  Role role = CLIENT;
  string ipAddress;
  string port;
  string file;
  string pktSize;
  string key;

  // Parse command-line arguments 
  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      printf("%s\n", argv[i]);
      if (strcmp(argv[i], "-server") == 0) {
        role = SERVER;
      }

      if (strcmp(argv[i], "-verbose") == 0) {
        printf("Verbose: ON\n");
        VERBOSE = true;
      }
    }
  }

  if (role == CLIENT) {
    printf("Role: Client\n");
  } else {
    printf("Role: Server\n");
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

  if (VERBOSE) {
    printf("<--- VERBOSE --->\n");
    printf("Entered Values:\n");
    printf("Role: %d\n", role);
    printf("IP Address: %s\n", ipAddress.c_str());
    printf("Port: %s\n", port.c_str());
    
    if (role == CLIENT) {
      printf("Pkt Size (KB): %s\n", pktSize.c_str());
      printf("From File: %s\n", file.c_str());
    } else {
      printf("Save To: %s\n", file.c_str());
    }

    printf("Encryption key: %s\n", key.c_str());
    printf("<--- VERBOSE --->\n");
  }

  char *fileBuffer = (char *) calloc(KB, stoi(pktSize));

  if (fileBuffer == NULL) {
    fprintf(stderr, "Internal error: Unable to initialize file buffer");
    exit(1);
  }

  FILE *pFile = std::fopen(file.c_str(), "r");

  if (pFile == NULL) {
    fprintf(stderr, "File error: Unable to open %s", file.c_str());
    exit(1);
  }


  size_t bytesRead = std::fread(fileBuffer, KB, stoi(pktSize), pFile);

  if (VERBOSE) {
    printf("<--- VERBOSE --->\n");
    printf("Bytes Read: %zu, File Buffer: %s\n", bytesRead, fileBuffer);
    printf("<--- VERBOSE --->\n");
  }

  string result = checkSum(file);
  printf("MD5: %s\n", result.c_str());

  fclose(pFile);
  free(fileBuffer);
}

void openConnection();

string encrypt(string data);

string decrypt(string data);

void sendData();

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