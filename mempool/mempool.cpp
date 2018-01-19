//
//  main.cpp
//  anbu
//
//  Created by Anbarasu on 12/23/16.
//  Copyright (c) 2016 Anbarasu. All rights reserved.
//

#include <iostream>
#include <stdint.h>
#include <string.h>
using namespace std;

#include "mempool.hpp"
void VatMemPool::alloc_buf1()
{
    if(block_size)
    {
        // create blocks and update the list
        cout << "creating " << init_count << " blocks of size = " << block_size << " total size = " << block_size * init_count<< endl;
        uint8_t * buffer = (uint8_t *)malloc(size_t(block_size * init_count));
        
        cout << "created successfully.. now updating the list" << endl;
        
        
        
        struct vat_mempool_t *ptr = (struct vat_mempool_t*)malloc(sizeof(struct vat_mempool_t) * init_count);
        
        struct mem_tracker_list_t *mem_tracker_ptr = (struct mem_tracker_list_t*)malloc(sizeof(struct mem_tracker_list_t));
        mem_tracker_ptr->buffer_ptr = buffer;
        mem_tracker_ptr->header_ptr = ptr;
        mem_tracker_ptr->next = mem_tracker_head;
        mem_tracker_head = mem_tracker_ptr;
        
        
        for (uint32_t i = 0 ; i < init_count; i++,ptr++)
        {
            ptr->location = buffer + (i * block_size);
            ptr->next_free = head;
            head = ptr;
        }
    }
}

void VatMemPool::alloc_buf()
{
    if(block_size)
    {
        // create blocks and update the list
        cout << "creating " << init_count << " blocks of size = " << block_size << " total size = " << block_size * init_count<< endl;
        uint8_t * buffer = (uint8_t *)malloc(size_t(block_size * init_count));
    
        cout << "created successfully.. now updating the list" << endl;
    
        for (uint32_t i = 0 ; i < init_count; i++)
        {
            struct vat_mempool_t *ptr = (struct vat_mempool_t*)malloc(sizeof(struct vat_mempool_t));
            ptr->location = buffer + (i * block_size);
            ptr->next_free = head;
            head = ptr;
        }
    }
}

VatMemPool::VatMemPool(uint8_t * _pool_name, size_t _block_size, uint32_t _init_count, uint32_t _exp_count)
{
    strncpy((char *)pool_name,(const char *)_pool_name,24);
    init_count = _init_count;
    exp_count = _exp_count;
    block_size = _block_size;
    if(_block_size < MIN_BLOCK_SIZE) block_size = MIN_BLOCK_SIZE;
    // (x + (b-1)) & (~(b-1)) gives multiple of b for 5 this will give 8 as o/p if b is 4.
    block_size = (block_size + MIN_BLOCK_SIZE -1) & (~(MIN_BLOCK_SIZE-1));
    alloc_buf1();
}

VatMemPool::~VatMemPool()
{
    while(mem_tracker_head)
    {
        free(mem_tracker_head->buffer_ptr);
        free(mem_tracker_head->header_ptr);
        struct mem_tracker_list_t *mem_tracker_ptr = mem_tracker_head;
        mem_tracker_head = mem_tracker_head->next;
        free(mem_tracker_ptr);
    }
    head = NULL;
}


void VatMemPool::vat_mempool_print_stats()
{
    cout << "Pool name = " << pool_name << endl;
    cout << "Expansion count = " << exp_count << endl;
    cout << "init count = " << init_count << endl;
    cout << "Block size = " << block_size << endl;
    struct vat_mempool_t *ptr = head;
    
    int count = 0;
    for (; ptr; ptr = ptr->next_free) {
        count ++;
    }
    cout << "Total number of available nodes = " << count << endl;
    
}

vat_mempool_t * VatMemPool::vat_mempool_alloc()
{
    // return the head in the list
    if(!head)
    {
        if(!exp_count) return NULL;
        
        alloc_buf1();
        exp_count--;
    }
    
    struct vat_mempool_t *ptr = head;
    if(head)
    {
        head = head->next_free;
    }
    return ptr;
}

void VatMemPool::vat_mempool_free(vat_mempool_t * pool)
{
    if(pool)
    {
        pool->next_free = head;
        head = pool;
    }
}

#if 0
int main(int argc, const char * argv[])
{
    uint8_t myStr[] = "text";
    size_t block_size = 0;
    uint32_t init_count = 1;
    uint32_t exp_count = 1;
    VatMemPool obj(myStr, block_size, init_count, exp_count);
    
    obj.vat_mempool_print_stats();
    
    vat_mempool_t * ptr = obj.vat_mempool_alloc();
    cout << ptr << endl;
    obj.vat_mempool_print_stats();
    ptr = obj.vat_mempool_alloc();
    cout << ptr << endl;
    obj.vat_mempool_print_stats();
    
    obj.vat_mempool_free(ptr);
    cout << "After freeing" << endl;
    obj.vat_mempool_print_stats();
    
    return 0;
}
#endif
