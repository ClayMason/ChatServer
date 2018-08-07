---------------
## Chat Program
---------------

### Server Side

Created server socket with `winsock2.h` and set the socket to listen to `localhost:80`. Once a connection is accepted through the server socket, a new thread is created to handle the socket connection.

In order to manage websocket connections, an initial handshake must be created, requested by the client, and handled by the server (TODO).
