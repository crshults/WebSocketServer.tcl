package provide websocket_server 0.0.4

package require TclOO
package require sha1
package require list_tools
package require binary_tools

oo::class create websocket_server {
    variable clients handler server_socket

    constructor {port callback} {
        set clients [list]
        set handler $callback
        set server_socket [socket -server [list [self] accept_connection] $port]
    }

    destructor {
        close $server_socket
    }

    method accept_connection {client_socket address port} {
        lappend clients $client_socket
        chan configure $client_socket -blocking no -buffering none -encoding iso8859-1 -translation binary
        chan event $client_socket readable [list [self] perform_handshake $client_socket]
    }

    method perform_handshake {client_socket} {
        set request [split [chan read $client_socket] \n]
        puts "perform_handshake: $request"
        set key [lindex [lindex $request [lsearch $request Sec-WebSocket-Key*]] end]
        chan puts $client_socket "HTTP/1.1 101 Switching Protocols"
        chan puts $client_socket "Upgrade: websocket"
        chan puts $client_socket "Connection: Upgrade"
        chan puts $client_socket "Sec-WebSocket-Accept: [binary encode base64 [sha1::sha1 -bin ${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11]]"
        chan puts $client_socket ""
        chan event $client_socket readable [list [self] read_data $client_socket]
    }

    method read_data {client_socket} {
        set received_message [chan read $client_socket]
        puts "read_data: $received_message"
        if {[chan eof $client_socket]} {
            chan close $client_socket
            set clients [lsearch -inline -all -not -exact $clients $client_socket]
                    }
        while {[string length $received_message] > 0} {
            set received_message [bassign $received_message {fin 1 rsv1 1 rsv2 1 rsv3 1 opcode 4 mask 1 payload_length 7}]
            switch $payload_length {
                126 {set received_message [bassign $received_message {payload_length 16}]}
                127 {set received_message [bassign $received_message {payload_length 64}]}
                }
            binary scan $received_message c1c1c1c1c$payload_length masking_key(0) masking_key(1) masking_key(2) masking_key(3) payload
            set received_message [string range $received_message [expr {$payload_length+4}] end]
            for {set i 0} {$i < $payload_length} {incr i} {
                append message [binary format c1 [expr {[lindex $payload $i] ^ $masking_key([expr $i % 4])}]]
            }
            $handler $message
            set message {}
        }
    }
    
    method broadcast {message} {
        set message \x81[binary format H* [format %02x [string length $message]]]$message
        puts $message
        foreach client $clients {
            puts -nonewline $client $message
        }
    }
}

websocket_server create myServer 9999 callback
proc callback {msg} {puts $msg}
