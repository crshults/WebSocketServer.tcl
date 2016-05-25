# WebSocketServer.tcl

**Example:**
```
---In tkcon---
package require websocket_server
websocket_server create myServer 9999 callback
proc callback {message} {puts $message}
---In browser's JavaScript console---
var ws = new WebSocket("ws://localhost:9999");
ws.onmessage = function (event) {console.log(event.data);}
ws.send("This is a message from the client.");
---Back in tkcon---
myServer broadcast "This is a message from the server."
```

## How to make it available for use:

1. Take the Tcl module file and drop it into `<TclInstallRoot>\lib\tcl8\8.6\`
2. Rename it to websocket_server-0.0.9.tm
3. `package require websocket_server`
