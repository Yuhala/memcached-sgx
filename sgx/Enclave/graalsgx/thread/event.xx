/*
 * Created on Mon Sep 13 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Enclave.h"
#include <sgx/event.h>

/* GRAAL_SGX_INFO();
    int ret;
    ocall_(&ret);
    return ret; */

int event_del(struct event *ev)
{
    GRAAL_SGX_INFO();
    int ret;
    //ocall_event_del(&ret, ev);
    return ret;
}

void event_set(struct event *ev, evutil_socket_t socketfd, short flags, void (*handler)(evutil_socket_t, short, void *), void *c)
{
    GRAAL_SGX_INFO();
    //ocall_event_set(ev, socketfd, flags, handler, c);
}

int event_base_set(struct event_base *evb, struct event *ev)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_event_base_set(&ret, evb, ev);
    return ret;
}

int event_add(struct event *ev, const struct timeval *timeout)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_event_add(&ret, ev, timeout);
    return ret;
}