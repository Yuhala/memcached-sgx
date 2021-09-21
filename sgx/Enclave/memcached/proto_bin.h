#ifndef PROTO_BIN_H
#define PROTO_BIN_H

#if defined(__cplusplus)
extern "C"
{
#endif
    /* binary protocol handlers */
    int try_read_command_binary(conn *c);
    void complete_nread_binary(conn *c);
    void write_bin_error(conn *c, protocol_binary_response_status err,
                         const char *errstr, int swallow);

#if defined(__cplusplus)
}
#endif

#endif
