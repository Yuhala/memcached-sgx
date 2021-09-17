
/*
 * Created on Thu Sep 16 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * memcached types used in EDL files
 */

#ifndef MCD_TYPES_H
#define MCD_TYPES_H

/**
 * Possible states of a connection.
 */
#ifndef MCD_CONN_STATES
#define MCD_CONN_STATES
enum conn_states
{
    conn_listening, /**< the socket which listens for connections */
    conn_new_cmd,   /**< Prepare connection for next command */
    conn_waiting,   /**< waiting for a readable socket */
    conn_read,      /**< reading in a command line */
    conn_parse_cmd, /**< try to parse a command from the input buffer */
    conn_write,     /**< writing out a simple response */
    conn_nread,     /**< reading in a fixed number of bytes */
    conn_swallow,   /**< swallowing unnecessary bytes w/o storing */
    conn_closing,   /**< closing this connection */
    conn_mwrite,    /**< writing out many items sequentially */
    conn_closed,    /**< connection is closed */
    conn_watch,     /**< held by the logger thread as a watcher */
    conn_io_queue,  /**< wait on async. process to get response object */
    conn_max_state  /**< Max state value (used for assertion) */
};
#endif

#ifndef MCD_NET_TRANS
#define MCD_NET_TRANS

enum network_transport
{
    local_transport, /* Unix sockets*/
    tcp_transport,
    udp_transport
};
#endif

#endif /* MCD_TYPES_H */
