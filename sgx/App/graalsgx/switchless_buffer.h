#ifndef _SWITCHLESS_BUFFER_H
#define _SWITCHLESS_BUFFER_H

#define DEFAULT_BUFFER_ARG_SIZE 16
#define DEFAULT_BUFFER_RET_SIZE 16

#include <unistd.h>


#if defined(__cplusplus)
//extern "C"
//{
#endif
    /* Initializes the buffer at the beginning of the execution of the app
     * returns 1 if there was an error, 0 otherwise
     */
    int init_switchless_buffer(struct buffer* switchless_buffer);
    
#if defined(__cplusplus)
//}
#endif



#endif /* ! _SWITCHLESS_BUFFER_H */
