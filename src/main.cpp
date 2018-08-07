#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _WIN32_WINNT _WIN32_WINNT_WINXP

#include <string>
#include <cstdlib>
#include <cstdint>
#include <stdio.h>
#include <windows.h>
#include <winsock2.h> //
#include <ws2tcpip.h> // libws232.a
#include <process.h> // _beginthread ()
#include <fstream>
#include <iostream>

#define PORT      "80"    // port listen to
#define BACKLOG   10      // passed to listen()

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


void handle (void *pParam) {
  printf("Handling a socket.\n");

  SOCKET* client = (SOCKET*) pParam;
  int iResult = send(*client, "We got your message\n", 21, 0);
  if ( iResult == SOCKET_ERROR ) {
    perror("send");
    return;
  }

  int MSG_IN_LEN = 524;
  unsigned char msg_in[MSG_IN_LEN];

  while(1) {
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
      std::ofstream out_file;
      out_file.open("log.txt", std::ios_base::app);
      for ( int i = 0; i < rResult; i++ ) {
        out_file << (int) msg_in[i] << " ";
      }
      out_file.close ();
    }
  }

  printf("Sent data back to socket\n");
  free(pParam);
}
