// socket client ref: https://www.tutorialspoint.com/html5/html5_websocket.htm

console.log("data.js loaded.");
socket_test = function () {
  if ( "WebSocket" in window ) {
    console.log("Websocket supported");

    // open websocket
    var ws = new WebSocket("ws://127.0.0.1:80");

    ws.onopen = function () {
      ws.send("Test123");
      console.log("message sent");
    }

    ws.onerror = function () {
      console.log("An error occurred: " + ws.readyState);
      console.log("Protocol: " + ws.protocol);
    }

    ws.onopen = function () {
      // send data as a test
      //ws.send("Sup server. This is your boy, client!");
      ws.send("It fucking works !");
      console.log("Message sent");
    }

  }
  else console.log("No websocket support in browser");
}

socket_test ();
