/*
 * Created on Mon Nov 22 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */


#ifndef MMAN_H
#define MMAN_H

#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#define PROT_EXEC       4

#define MAP_FILE        0
#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_TYPE        0xf
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS

#define MAP_FAILED      ((void *)-1)

#define _SC_PAGESIZE 11

#define _SC_CLK_TCK 100

#endif /* MMAN_H */
