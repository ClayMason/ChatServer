#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _WIN32_WINNT _WIN32_WINNT_WINXP

#include <string>
#include <cstdlib>
#include <cstdint>
#include <stdio.h>
#include <sstream>
#include <windows.h>
#include <winsock2.h> //
#include <ws2tcpip.h> // libws232.a
#include <process.h> // _beginthread ()
#include <fstream>
#include <iostream>
#include <cassert>
#include <limits>
#include <stdexcept>
#include <cctype>
#include "SHA1-983/sha1.hpp"

#define PORT      "80"    // port listen to
#define BACKLOG   10      // passed to listen()

static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void handle (void *pParam);

int main () {

  // set version to 2.2
  WORD wVersion = MAKEWORD(2, 2);
  WSADATA wsData;
  int iResult;
  SOCKET sock;

  struct addrinfo hints, *res;
  int reuseaddr = 1;

  if ( (iResult = WSAStartup(wVersion, &wsData)) != 0 ) {
    printf ("WSAStartup failed: %d\n", iResult);
    return 1;
  }

  ZeroMemory (&hints, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ( getaddrinfo(NULL, PORT, &hints, &res) != 0 ) {
    perror("getaddrinfo");
    return 1;
  }

  sock = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
  if ( sock == INVALID_SOCKET ) {
    perror("socket");
    WSACleanup();
    return 1;
  }

  if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseaddr, sizeof(int)) == SOCKET_ERROR ) {
    perror("setsocketopt");
    WSACleanup();
    return 1;
  }

  if ( bind(sock, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR ) {
    perror("bind");
    WSACleanup();
    return 1;
  }

  if ( listen(sock, BACKLOG) == SOCKET_ERROR ) {
    perror("listen");
    WSACleanup();
    return 1;
  }

  freeaddrinfo(res);

  while (1) {
    int size = sizeof(struct sockaddr);
    struct sockaddr_in their_addr;
    SOCKET newsock;

    ZeroMemory(&their_addr, sizeof(struct sockaddr));
    newsock = accept (sock, (struct sockaddr*)&their_addr, &size);
    if ( newsock == INVALID_SOCKET ) {
      perror("accept\n");
    }
    else {

      // handle multithreading for multiple client connections
      uintptr_t thread;
      printf ("Connection recieved => %s:%d\n",
        inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));

      printf("New socket is %d\n", newsock);

      SOCKET* safesock = (SOCKET*) malloc(sizeof(SOCKET));
      if (safesock) {
        *safesock = newsock;
        thread = _beginthread(handle, 0, (void*) safesock);
        if ( thread == -1 ) {
          fprintf(stderr, "Couldn't create thread: %d", GetLastError());
          closesocket(newsock);
        }
      }
      else {
        printf("malloc");
      }


    }

  }

  closesocket(sock);
  WSACleanup();
}

void fill_response(char* response, const char* type, char* secret_out);
std::string base64_encode(const std::string &bindata);
void find_secret_in(char* secret, unsigned char* inb_header);
void get_secret(const char* secret_in, char* secret_out);

void handle (void *pParam) {
  printf("Handling a socket.\n");

  SOCKET* client = (SOCKET*) pParam;

  int MSG_IN_LEN = 524;
  unsigned char msg_in[MSG_IN_LEN];
  bool handshake_sent = false;

  while(1) {
    if ( !handshake_sent ) {
      ZeroMemory(&msg_in, MSG_IN_LEN);
      int rResult = recv(*client, (char*) msg_in, MSG_IN_LEN, 0);
      if ( rResult > 0 ) {
        printf("Client:\t%s (%d bytes)\n", msg_in, rResult);

        /*
        * each line of the request recieved ends with
        *CR(13) LF(10) -- use this to parse each line of the request
        */

        // send(*client, "Ok sir.\n", 9, 0);

        // write output to file
        char response[255];
        ZeroMemory(&response, 255);
        char secret_in[200];
        char secret_out[200];
        find_secret_in(secret_in, msg_in);
        get_secret((const char*) secret_in, secret_out);
        fill_response(response, "101", secret_out);
        printf("\nResponse:\n%s\n", response);

        // Send the response to the client
        int sendResult = send(*client, response, strlen(response) + 1, 0);
        if ( sendResult == SOCKET_ERROR ) {
          printf("Socket Error Recieved (code %d)\n", WSAGetLastError());
        }
        else {
          printf("Allegedly, successfully sent ¯\\_(ツ)_/¯\n");
          handshake_sent = true;
        }

      }
    }
    else {

    }
  }

  printf("Sent data back to socket\n");
  free(pParam);
}

void find_secret_in(char* secret, unsigned char* inb_header) {
  /*
  * Given a header string (http request), find the websocket-key stored in the header,
  * if there is one.
  */

  printf("Trying to find secret\n");
  std::stringstream s((char*) inb_header);
  std::string line;
  while(std::getline(s, line, '\n')) {
    // DO SOMETHING
    char mod_line[ (int) strlen(line.c_str()) - 1 ];
    strcpy(mod_line, line.c_str());

    // new line is now stored in mod_line. Needed to remove the /r that was left at the end
    if ( strcmp(std::string(mod_line).substr(0, 17).c_str(), "Sec-WebSocket-Key") == 0 ) {
      printf ("Found the websocket key! => %s\n", mod_line);
      // Extract the socket key...
      std::string secret_str = std::string(mod_line).substr(19, strlen(mod_line) - 19 );
      printf("Secret = %s\n", secret_str.c_str());
      printf("Secret Length %d or %d\n", secret_str.length(), (int) strlen(secret_str.c_str()));
      strcpy(secret, secret_str.substr(0, secret_str.length()-1).c_str());
      printf("New secret length %d\n", (int) strlen(secret));
      printf("New secret = %s\n", secret);

      break;
    }

  }
}

void fill_response(char* response, const char* type, char* secret_out) {
  // given the type, return a response header
  if (strcmp(type, "404") == 0) {
    // 404 Error
    strcpy(response, "HTTP/1.0 404 Not Found\r\n\r\n");
  }
  else if (strcmp(type, "101") == 0) {
    if (sprintf(response, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", secret_out) < 0) {
      printf("Error in sprintf()\n");
    }
    //strcpy(response, );
  }
}

void get_secret(const char* secret_in, char* secret_out) {
  /*
  * Given a websocket key (stored in secret_in), store the base64 encoded SHA-1 hash
  * in secret_out.
  */

  std::string magic_string(secret_in);
  magic_string.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  printf("Magic String => %s\n", magic_string.c_str());

  sha1(magic_string.c_str()).finalize().print_base64(secret_out);
  printf("Returning Secret: %s\n", secret_out);

  /*
  std::string test_string("dGhlIHNhbXBsZSBub25jZQ==");
  test_string.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  char test_out[200];
  sha1(test_string.c_str()).finalize().print_base64(test_out);
  printf("Test String Out => %s\n", test_out);
  // => Should output "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  */
}
