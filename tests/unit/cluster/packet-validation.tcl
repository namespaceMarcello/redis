# Open a raw connection to the cluster bus of node 0 and send `packet` on it.
proc send_to_cluster_bus {packet} {
    set host [srv 0 host]
    set port [expr {[srv 0 port] + 10000}]
    if {$::tls} {
        set fd [::tls::socket \
            -cafile "$::tlsdir/ca.crt" \
            -certfile "$::tlsdir/client.crt" \
            -keyfile "$::tlsdir/client.key" \
            $host $port]
    } else {
        set fd [socket $host $port]
    }
    fconfigure $fd -translation binary -buffering full
    puts -nonewline $fd $packet
    flush $fd
    return $fd
}

start_cluster 2 0 {tags {external:skip cluster}} {

test "PUBLISH with channel_len + message_len overflow is rejected" {
    set CLUSTERMSG_TYPE_PUBLISH 4
    set CLUSTERMSG_MIN_LEN 2256

    set target_host [srv 0 host]
    set target_bus_port [expr {[srv 0 port] + 10000}]
    set node_id [R 1 CLUSTER MYID]
    set sender_port [srv -1 port]
    set sender_cport [expr {$sender_port + 10000}]

    # sizeof(clusterMsgDataPublish) - 8 = 16 - 8 = 8
    # With channel_len=0x80000000 and message_len=0x80000000, their sum
    # overflows uint32 to 0, making explen = 2256 + 8 = 2264 without the fix.
    # The fix detects the overflow before computing explen.
    set channel_len 0x80000000
    set message_len 0x80000000
    set totlen [expr {$CLUSTERMSG_MIN_LEN + 8}] ;# 2264

    set packet [build_cluster_bus_header $node_id $sender_port $sender_cport \
        $CLUSTERMSG_TYPE_PUBLISH $totlen]
    append packet [binary format I $channel_len]
    append packet [binary format I $message_len]

    if {$::tls} {
        set fd [::tls::socket \
            -cafile "$::tlsdir/ca.crt" \
            -certfile "$::tlsdir/client.crt" \
            -keyfile "$::tlsdir/client.key" \
            $target_host $target_bus_port]
    } else {
        set fd [socket $target_host $target_bus_port]
    }
    fconfigure $fd -translation binary -buffering full
    puts -nonewline $fd $packet
    flush $fd

    # The fix rejects the packet and logs a warning about the overflow.
    wait_for_log_messages 0 {"*publish*overflow in length fields*"} 0 20 500
    close $fd

    # Verify the server is still responsive after the malformed packet.
    assert_equal [R 0 PING] {PONG}
}

test "MODULE with len overflow is rejected" {
    set CLUSTERMSG_TYPE_MODULE 9
    set CLUSTERMSG_MIN_LEN 2256

    set target_host [srv 0 host]
    set target_bus_port [expr {[srv 0 port] + 10000}]
    set node_id [R 1 CLUSTER MYID]
    set sender_port [srv -1 port]
    set sender_cport [expr {$sender_port + 10000}]

    # sizeof(clusterMsgModule) - 3 = 16 - 3 = 13
    # With module_len=0xFFFFFFFF, adding to base explen (2256+13=2269)
    # overflows uint32, wrapping to 2268 without the fix.
    # The fix detects the overflow before computing explen.
    set module_len 0xFFFFFFFF
    set totlen [expr {($CLUSTERMSG_MIN_LEN + 13 + $module_len) & 0xFFFFFFFF}] ;# 2268

    set packet [build_cluster_bus_header $node_id $sender_port $sender_cport \
        $CLUSTERMSG_TYPE_MODULE $totlen]
    append packet [binary format W 0]           ;# module_id
    append packet [binary format I $module_len] ;# len

    if {$::tls} {
        set fd [::tls::socket \
            -cafile "$::tlsdir/ca.crt" \
            -certfile "$::tlsdir/client.crt" \
            -keyfile "$::tlsdir/client.key" \
            $target_host $target_bus_port]
    } else {
        set fd [socket $target_host $target_bus_port]
    }
    fconfigure $fd -translation binary -buffering full
    puts -nonewline $fd $packet
    flush $fd

    # The fix rejects the packet and logs a warning about the overflow.
    wait_for_log_messages 0 {"*module*overflow in length field*"} 0 20 500
    close $fd

    # Verify the server is still responsive after the malformed packet.
    assert_equal [R 0 PING] {PONG}
}


# Light header (56 bytes) used by PUBLISH and SPUBLISH messages.
set CLUSTERMSG_LIGHT_MIN_LEN 56

test "Light header PUBLISH with channel_len + message_len overflow is rejected" {
    set from [count_log_lines 0]
    set totlen [expr {$CLUSTERMSG_LIGHT_MIN_LEN + 8}]
    set packet [build_cluster_bus_light_header [R 1 CLUSTER MYID] 4 $totlen]
    append packet [binary format II 0x80000000 0x80000000]
    set fd [send_to_cluster_bus $packet]
    wait_for_log_messages 0 {"*publish*overflow in length fields*"} $from 20 500
    close $fd
    assert_equal [R 0 PING] {PONG}
}

test "Light header is rejected for message types that cannot use it" {
    set from [count_log_lines 0]
    # A PING (type 0) with the light bit, padded to a plausible length.
    set totlen [expr {$CLUSTERMSG_LIGHT_MIN_LEN + 8}]
    set packet [build_cluster_bus_light_header [R 1 CLUSTER MYID] 0 $totlen]
    append packet [string repeat \x00 8]
    set fd [send_to_cluster_bus $packet]
    wait_for_log_messages 0 {"*light header*ping*"} $from 20 500
    close $fd
    assert_equal [R 0 PING] {PONG}
}

test "Light header shorter than its minimum length is rejected" {
    set from [count_log_lines 0]
    # Send exactly the declared 24 bytes: any byte past them would be read as
    # the start of another message, with a bad signature.
    set packet [build_cluster_bus_light_header [R 1 CLUSTER MYID] 4 24]
    set fd [send_to_cluster_bus [string range $packet 0 23]]
    wait_for_log_messages 0 {"*Bad message length*"} $from 20 500
    close $fd
    assert_equal [R 0 PING] {PONG}
}

test "Light header PUBLISH too short for its length fields is rejected" {
    set from [count_log_lines 0]
    # First a packet that is rejected but leaves 0xff bytes in the receive
    # buffer right after the 60 bytes of the next one: they must not be read
    # as its message length.
    set totlen [expr {$CLUSTERMSG_LIGHT_MIN_LEN + 8}]
    set filler [build_cluster_bus_light_header [R 1 CLUSTER MYID] 0 $totlen]
    append filler [binary format II 0xffffffff 0xffffffff]
    # The light header is there, the channel and message lengths are not.
    set totlen [expr {$CLUSTERMSG_LIGHT_MIN_LEN + 4}]
    set packet [build_cluster_bus_light_header [R 1 CLUSTER MYID] 4 $totlen]
    append packet [binary format I 0]
    set fd [send_to_cluster_bus $filler$packet]
    wait_for_log_messages 0 {"*invalid light publish packet of length 60 but expected length 64*"} $from 20 500
    close $fd
    assert_equal [R 0 PING] {PONG}
}

test "Full header shorter than its minimum length is rejected" {
    set from [count_log_lines 0]
    # A PING that declares 100 bytes, and only those 100 bytes sent.
    set packet [build_cluster_bus_header [R 1 CLUSTER MYID] [srv -1 port] [expr {[srv -1 port] + 10000}] 0 100]
    set fd [send_to_cluster_bus [string range $packet 0 99]]
    wait_for_log_messages 0 {"*Bad message length*"} $from 20 500
    close $fd
    assert_equal [R 0 PING] {PONG}
}

proc from_link_ctime {id peer} {
    foreach l [R $id CLUSTER LINKS] {
        if {[dict get $l node] eq $peer && [dict get $l direction] eq "from"} {
            return [dict get $l create-time]
        }
    }
    return {}
}

test "Light header PUBLISH from a known node is delivered without taking over its link" {
    set node1 [R 1 CLUSTER MYID]
    set link_ctime [from_link_ctime 0 $node1]
    assert_not_equal {} $link_ctime
    set rd [redis_deferring_client]
    $rd subscribe lightchannel
    $rd read

    # A new connection, never associated with a node, that names node 1.
    set channel lightchannel
    set message fromnode1
    set totlen [expr {$CLUSTERMSG_LIGHT_MIN_LEN + 8 + [string length $channel] + [string length $message]}]
    set packet [build_cluster_bus_light_header $node1 4 $totlen]
    append packet [binary format II [string length $channel] [string length $message]] $channel $message
    set fd [send_to_cluster_bus $packet]
    assert_equal {message lightchannel fromnode1} [$rd read]
    # The link from node 1 is still the one it opened.
    assert_equal $link_ctime [from_link_ctime 0 $node1]
    close $fd
    $rd close
}

test "Light header PUBLISH from an unknown node is ignored" {
    set rd [redis_deferring_client]
    $rd subscribe lightchannel
    $rd read

    # CLUSTER INFO leaves out the counters that are still zero.
    set received [CI 0 cluster_stats_messages_publish_received]
    if {$received eq ""} {set received 0}
    set channel lightchannel
    set message forged
    set totlen [expr {$CLUSTERMSG_LIGHT_MIN_LEN + 8 + [string length $channel] + [string length $message]}]
    set packet [build_cluster_bus_light_header [string repeat a 40] 4 $totlen]
    append packet [binary format II [string length $channel] [string length $message]] $channel $message
    set fd [send_to_cluster_bus $packet]
    wait_for_condition 50 100 {
        [CI 0 cluster_stats_messages_publish_received] > $received
    } else {
        fail "The light PUBLISH was not processed"
    }

    # Had the forged message been delivered, it would come first.
    R 0 PUBLISH lightchannel genuine
    assert_equal {message lightchannel genuine} [$rd read]
    close $fd
    $rd close
}

}
