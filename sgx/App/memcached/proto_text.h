#ifndef PROTO_TEXT_H
#define PROTO_TEXT_H

#if defined(__cplusplus)
extern "C"
{
#endif

    /* text protocol handlers */
    void complete_nread_ascii(conn *c);
    int try_read_command_asciiauth(conn *c);
    int try_read_command_ascii(conn *c);

#if defined(__cplusplus)
}
#endif

#endif

