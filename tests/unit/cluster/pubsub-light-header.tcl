# Pub/Sub messages travel on the cluster bus with a light header (signature,
# length, type and sender name: 56 bytes) instead of the full 2256 bytes one,
# to every node that announced it can read it.

# A message queued for a peer costs its block plus a list node: about a hundred
# bytes with the light header, more than the 2256 bytes of the full header alone.
set ::full_hdr_len 2256
set ::light_min 56
set ::light_max 1000

# Bytes queued per message on each outbound link of node `id` by `count` runs
# of `cmd channel hello`, as a dict: peer node id -> bytes. Everything runs
# inside MULTI, so nothing can be written to the sockets between the two
# CLUSTER LINKS calls.
proc link_queue_per_publish {id cmd channel {count 100}} {
    set r [Rn $id]
    $r MULTI
    $r CLUSTER LINKS
    for {set i 0} {$i < $count} {incr i} {
        $r $cmd $channel hello
    }
    $r CLUSTER LINKS
    set res [$r EXEC]
    set before [outbound_queues [lindex $res 0]]
    set per {}
    dict for {peer mem} [outbound_queues [lindex $res end]] {
        dict set per $peer [expr {($mem - [dict get $before $peer]) / $count}]
    }
    return $per
}

proc outbound_queues {links} {
    set queues {}
    foreach l $links {
        if {[dict get $l direction] eq "to"} {
            dict set queues [dict get $l node] [dict get $l send-buffer-allocated]
        }
    }
    return $queues
}

# 1 if, in the result of link_queue_per_publish, the messages for the peers in
# `light` used the light header and those for the peers in `full` the full one.
proc headers_are {per light full} {
    foreach peer $light {
        set bytes [dict get $per $peer]
        if {$bytes <= $::light_min || $bytes >= $::light_max} {return 0}
    }
    foreach peer $full {
        if {[dict get $per $peer] <= $::full_hdr_len} {return 0}
    }
    return 1
}

# Node ids of all the nodes but `id`, and but those in `except`.
proc peers_of {id {except {}}} {
    set peers {}
    for {set j 0} {$j < [llength $::servers]} {incr j} {
        if {$j == $id || $j in $except} continue
        lappend peers [R $j CLUSTER MYID]
    }
    return $peers
}

# A channel named <prefix><n> whose slot is served by the shard of node `id`.
proc channel_served_by {id prefix} {
    for {set i 0} {$i < 10000} {incr i} {
        set slot [R $id CLUSTER KEYSLOT $prefix$i]
        foreach range [dict get [cluster_get_myself $id] slots] {
            lassign [split $range -] from to
            if {$to eq ""} {set to $from}
            if {$slot >= $from && $slot <= $to} {return $prefix$i}
        }
    }
    fail "No channel found for node $id"
}

# Subscribe a new client of each node in `ids` to `channel`.
proc subscribe_all {ids cmd channel} {
    set clients {}
    foreach id $ids {
        set rd [redis_deferring_client [expr -$id]]
        $rd $cmd $channel
        $rd read
        lappend clients $rd
    }
    return $clients
}

proc has_link_to_peer {id peer} {
    foreach l [R $id CLUSTER LINKS] {
        if {[dict get $l node] eq $peer && [dict get $l direction] eq "to"} {return 1}
    }
    return 0
}

# CLUSTER INFO leaves out the counters that are still zero.
proc publish_stat {id dir} {
    set v [CI $id cluster_stats_messages_publish_$dir]
    expr {$v eq "" ? 0 : $v}
}

proc assert_all_read {clients expected} {
    foreach rd $clients {
        assert_equal $expected [$rd read]
    }
}

start_cluster 3 3 {tags {external:skip cluster}} {
    test "PUBLISH uses the light header on the cluster bus" {
        wait_for_condition 100 100 {
            [headers_are [link_queue_per_publish 0 PUBLISH unheard] [peers_of 0] {}]
        } else {
            fail "Bytes queued per PUBLISH, by peer: [link_queue_per_publish 0 PUBLISH unheard]"
        }
    }

    test "SPUBLISH uses the light header on the cluster bus" {
        set channel [channel_served_by 0 unheard]
        # Node 3 is the replica of node 0 (default_replica_allocation): the
        # only one that gets the message.
        set replica [R 3 CLUSTER MYID]
        wait_for_condition 100 100 {
            [headers_are [link_queue_per_publish 0 SPUBLISH $channel] [list $replica] {}]
        } else {
            fail "Bytes queued per SPUBLISH, by peer: [link_queue_per_publish 0 SPUBLISH $channel]"
        }
        dict for {peer bytes} [link_queue_per_publish 0 SPUBLISH $channel] {
            if {$peer ne $replica} {assert_equal 0 $bytes}
        }
    }

    test "Light header messages are delivered intact" {
        set clients [subscribe_all {1 2 3 4 5} SUBSCRIBE lightchannel]
        set binary "a\x00b\r\n\xff"
        R 0 PUBLISH lightchannel ""
        R 0 PUBLISH lightchannel $binary
        R 0 PUBLISH lightchannel [string repeat x 100000]
        assert_all_read $clients {message lightchannel {}}
        assert_all_read $clients [list message lightchannel $binary]
        assert_all_read $clients [list message lightchannel [string repeat x 100000]]
        foreach rd $clients {$rd close}

        set channel [channel_served_by 0 ch]
        # Node 3 is the replica of node 0 (default_replica_allocation).
        set clients [subscribe_all {3} SSUBSCRIBE $channel]
        R 0 SPUBLISH $channel $binary
        assert_all_read $clients [list smessage $channel $binary]
        foreach rd $clients {$rd close}
    }

    test "Light header messages are counted as publish messages" {
        set sent [publish_stat 0 sent]
        set received [publish_stat 1 received]
        for {set i 0} {$i < 10} {incr i} {R 0 PUBLISH unheard hello}
        assert_equal [expr {$sent + 50}] [publish_stat 0 sent]
        wait_for_condition 100 50 {
            [publish_stat 1 received] == $received + 10
        } else {
            fail "Node 1 counted [publish_stat 1 received] publish messages, expected [expr {$received + 10}]"
        }
    }

    test "A node that does not announce the light header gets full messages" {
        # Node 2 behaves like a node of an older version: it does not announce
        # the light header and does not send it.
        set node2 [R 2 CLUSTER MYID]
        R 2 CONFIG SET cluster-pubsub-light-header no
        wait_for_condition 100 100 {
            [headers_are [link_queue_per_publish 0 PUBLISH unheard] [peers_of 0 {2}] [list $node2]]
        } else {
            fail "Bytes queued per PUBLISH by node 0, by peer: [link_queue_per_publish 0 PUBLISH unheard]"
        }
        set per [link_queue_per_publish 2 PUBLISH unheard]
        assert {[headers_are $per {} [peers_of 2]]}

        # Messages flow both ways, in both formats.
        set clients [subscribe_all {0 1 2} SUBSCRIBE lightchannel]
        R 0 PUBLISH lightchannel from0
        R 2 PUBLISH lightchannel from2
        # Each subscriber gets both: one from its own node, or both from the
        # bus on two different links, so their order is not defined.
        foreach rd $clients {
            set got [lsort [list [$rd read] [$rd read]]]
            assert_equal {{message lightchannel from0} {message lightchannel from2}} $got
            $rd close
        }

        R 2 CONFIG SET cluster-pubsub-light-header yes
        wait_for_condition 100 100 {
            [headers_are [link_queue_per_publish 0 PUBLISH unheard] [peers_of 0] {}] &&
            [headers_are [link_queue_per_publish 2 PUBLISH unheard] [peers_of 2] {}]
        } else {
            fail "Nodes did not switch back to the light header"
        }
    }

    test "A new link uses the full header until the peer answers on it" {
        R 2 CONFIG SET cluster-pubsub-light-header yes
        set node2_id [R 2 CLUSTER MYID]
        set node2_pid [srv -2 pid]
        # With node 2 paused the link to it is recreated (the kernel accepts
        # the connection) but no PONG can arrive on it.
        pause_process $node2_pid
        R 0 DEBUG CLUSTERLINK KILL TO $node2_id
        wait_for_condition 100 50 {
            [has_link_to_peer 0 $node2_id]
        } else {
            resume_process $node2_pid
            fail "Link to node 2 was not recreated"
        }
        set per [link_queue_per_publish 0 PUBLISH unheard]
        resume_process $node2_pid
        assert {[headers_are $per [peers_of 0 {2}] [list $node2_id]]}

        wait_for_condition 100 100 {
            [headers_are [link_queue_per_publish 0 PUBLISH unheard] [peers_of 0] {}]
        } else {
            fail "Node 0 did not go back to the light header for node 2"
        }
    } {} {needs:debug}
}
