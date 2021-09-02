#ifndef _SWITCHLESS_BUFFER_H
#define _SWITCHLESS_BUFFER_H

#define DEFAULT_BUFFER_ARG_SIZE 4096
#define DEFAULT_BUFFER_RET_SIZE 4096

/* Initializes the buffer at the beginning of the execution of the app
 * returns 1 if there was an error, 0 otherwise
 */
int init_switchless_buffer(struct buffer* switchless_buffer);

int resize_buffer_args(struct buffer* switchless_buffer, size_t new_size);

int resize_buffer_ret(struct buffer* switchless_buffer, size_t new_size);


#endif /* ! _SWITCHLESS_BUFFER_H */
