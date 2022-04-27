/*
 * Created on Wed Apr 27 2022
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#include "lmbench.h"
#include "Enclave.h"
#include <stdlib.h>

void lmbench_do_read(int num_reads, int thread_id, void *cookie)
{

    _state *request_state = (_state *)cookie;
    char c;

    while (num_reads-- > 0)
    {
        if (read(request_state->fd, &c, 1) != 1)
        {
            printf("lmbench /dev/zero read error\n");
            return;
        }
    }
}
void lmbench_do_write(int num_writes, int thread_id, void *cookie)
{

    _state *request_state = (_state *)cookie;
    char c;

    while (num_writes-- > 0)
    {
        if (write(request_state->fd, &c, 1) != 1)
        {
            printf("lmbench /dev/null write error\n");
            return;
        }
    }
}