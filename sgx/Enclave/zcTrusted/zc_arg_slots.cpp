/*
 * Created on Thu Sep 30 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * Routines in here manage the argument slots. 
 * This may not be fast enough
 */

#include "zc_arg_slots.h"
//#include <stdlib.h>
#include "zc_args.h"

#include <bits/stdc++.h>
using namespace std;
/**
 * Heads of all the argument slot linked lists
 */

zc_arg_slot *fread_free_slots;
zc_arg_slot *fwrite_free_slots;
zc_arg_slot *read_free_slots;
zc_arg_slot *write_free_slots;

void add_free_slot(zc_arg_slot **head, int freeIndex)
{
    zc_arg_slot *temp = new zc_arg_slot();
    temp->data = freeIndex;
    temp->next = *head;
    *head = temp;
}

int get_free_slot(zc_arg_slot **head)
{
    int ret = -1;
    zc_arg_slot *temp = *head;
    if (*head == NULL)
    {
        ret = -1;
    }
    else
    {
        ret = temp->data;
        *head = temp->next;
        temp->next = NULL;
        free(temp);
    }
    return ret;
}

int slotListIsEmpty(zc_arg_slot **head)
{
    return (*head == NULL);
}