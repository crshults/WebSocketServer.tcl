package provide websocket_server 0.0.2

package require TclOO
package require sha1
package require base64

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
        chan configure $client_socket -blocking no -buffering none
        puts [chan read $client_socket]
        chan event $client_socket readable [list [self] read_data $client_socket]
    }

    method read_data {client_socket} {
        puts "read data"
        if {[chan eof $client_socket]} {
            chan close $client_socket
            set clients [lsearch -inline -all -not -exact $clients $client_socket]
        } else {
            set received_data [chan read -nonewline $client_socket]
            puts [binary encode hex $received_data]
            set received_data_with_truncated_separators [regsub \r\r\n $received_data \n]
            set received_data_list [split $received_data_with_truncated_separators \n]
            if {[lsearch -glob $received_data_list GET*HTTP/1.1*] >= 0} {
                set key [lindex [lindex $received_data_list [lsearch -glob $received_data_list Sec-WebSocket-Key*]] 1]
                append key 258EAFA5-E914-47DA-95CA-C5AB0DC85B11
                set hashed_key [::sha1::SHA1Init]
                ::sha1::SHA1Update $hashed_key $key
                set final_key [::sha1::SHA1Final $hashed_key]
                set encoded_final_key [::base64::encode $final_key]
                append response "HTTP/1.1 101 Switching Protocols\x0d\x0a"
                append response "Upgrade: websocket\x0d\x0a"
                append response "Connection: Upgrade\x0d\x0a"
                append response "Sec-WebSocket-Accept: $encoded_final_key\x0d\x0a"
                append response "\x0d\x0a"
                puts -nonewline $client_socket $response
            } else {
                binary scan $received_data H4c1c1c1c1c* ignore mask(0) mask(1) mask(2) mask(3) payload
                if {[info exists payload]} {
                    for {set i 0} {$i < [llength $payload]} {incr i} {
                        append message [binary format c1 [expr {[lindex $payload $i] ^ $mask([expr $i % 4])}]]
                    }
                    $handler $message
                }
            }
        }
    }
    
    method broadcast {message} {
        set message \x81[binary format H* [format %02x [string length $message]]]$message
        foreach client $clients {
            puts -nonewline $client $message
        }
    }
}
