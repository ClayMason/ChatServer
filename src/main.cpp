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
      /*TODO check if a socket connection already exists*/
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
void expand (char** stream_data, int* alloc_size);
void extract_socket_stream (char* stream_in, int* has_mask, int* finish, int* op_code, unsigned __int64* load_length);
void extract_payload_data (char* input, char* payload_data, unsigned _int64 length);

void handle (void *pParam) {
  printf("Handling a socket.\n");

  SOCKET* client = (SOCKET*) pParam;

  int MSG_IN_LEN = 524;
  unsigned char msg_in[MSG_IN_LEN];
  char raw_input[MSG_IN_LEN];
  bool handshake_sent = false;
  int rResult;

  bool stream_finished;
  int stream_size = 0;
  int stream_alloc = 4;
  char** stream_data = new char*[stream_alloc];

  while(1) {
    if ( !handshake_sent ) {
      ZeroMemory(&msg_in, MSG_IN_LEN);
      rResult = recv(*client, (char*) msg_in, MSG_IN_LEN, 0);
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
      // once the handshake is set, start processing input
      rResult = recv(*client, raw_input, MSG_IN_LEN, 0);
      if ( rResult == SOCKET_ERROR ) {
        printf ("Error recieving ... Disconnecting from client \n");
        // TODO - should disconnect from clinet
      }
      else if ( rResult > 0 ) {
        // Recieved Data !

        // if the array becomes filled, expand it
        if ( stream_size == stream_alloc )
          expand (stream_data, &stram_alloc);

        int has_mask;
        int fin;
        int op_code;
        unsigned __int64 load_length;
        extract_socket_stream (raw_input, &has_mask, &fin, &op_code, &load_length);

        if ( !has_mask ) {
          printf ("The response did not have a mask. Disconnecting!\n");
          // TODO - handle error
        }
        else {
          printf("The client response has a mask!\n");

          // store into stream_data
          char payload_data[load_length];
          extract_payload_data (raw_input, payload_data, load_length);
          stream_data[stream_size-1] = payload_data;
          ++ stream_size;

          if ( fin ) { // if finish reading from socket
            // process data

            // TODO - @ end, clear stream_data array (reset)
          }

        }

      }
    } // end of else (handshake_sent)

  }

  printf("Sent data back to socket\n");
  free(pParam);
}


void expand (char** stream_data, int* alloc_size) {
  // expand the stream_data size by 4
  int new_alloc_size = alloc_size + 4;

  // temporarily transfer the data into an array
  char* tmp_data[new_alloc_size];
  for ( int i = 0; i < alloc_size, i++ )
    tmp_data[i] = stream_data[i];

  // delete the old array and reallocate a new arr with the new size
  delete stream_data;
  stream_data = new char*[new_alloc_size];

  // transfer the data back into the main array
  for ( int i = 0; i < alloc_size; i++ )
    stream_data[i] = tmp_data[i];

  // set the new alloc_size
  *alloc_size = new_alloc_size;

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

void extract_socket_stream (char* stream_in, int* has_mask, int* finish, int* op_code, unsigned __int64* load_length) {
  *finish = stream_in[0] & 1;
  *op_code = (stream_in[0] & 240) >> 4;
  *has_mask = stream_in[1] & 1;
  *load_length = (stream_in[1] & 254) >> 1;
  if ( *load_length == 126 ) {
    *load_length = stream_in[2] + (stream_in[3] << 8);
  }
  else if ( *load_length == 127 ) {
    *load_length = stream_in[2] + (stream_in[3] << 8) + (stream_in[4] << 16)
      + (stream_in[5] << 24) + (stream_in[6] << 32) + (stream_in[7] << 40)
      + (stream_in[8] << 48) + (stream_in[9] << 56);
  }
}

void extract_payload_data (char* input, char* payload_data, unsigned _int64 length) {
  /*
  * extract the payload data from the Input Data
  *   - payload data is starts @ 14th index of input (each index = 8 bits or 1 octet)
  */

  // Step 1: Acquire mask key stored from 10 to 13 (inclusive) index [4 chars long]
  char mask[4];
  for ( int i = 10, i <= 13; ++i ) mask[i-10] = input[i];

  // Assumption made: Each unit of length is 1 octet = 1 character = 1 index in arr
  for ( unsigned _int64 i = 0; i < length; ++i ) {
    payload_data [i] = input[i + 14] ^ mask[i%4];
  }

  // data should be extracted

}
