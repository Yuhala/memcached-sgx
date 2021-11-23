/*
 * Created on Fri Aug 27 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 *  
 */

#ifndef PALDB_H
#define PALDB_H

#if defined(__cplusplus)
extern "C"
{
#endif

    void *reader_thread(void *input);
    void *writer_thread(void *input);
    void write_keys(int nKeys, int nThreads);
    void read_keys(int nKeys, int nThreads);

#if defined(__cplusplus)
}
#endif

#endif /* PALDB_H */
