#include "threads/synch.h"
#include <bitmap.h>
#include "devices/block.h"
#include "swap.h"

static struct bitmap *swap_bitmap;
struct block *swap_space;
static struct lock swap_lock;

void swap_init()
{ // how big is the swap space
    swap_bitmap = bitmap_create(1024);
    swap_space = block_get_role(BLOCK_SWAP);
    lock_init(&swap_lock);
}

void swap_in(struct page *evicted_page)
{
    // put a page in swap table
    //  change a page to in_swap status
    uint8_t *pointer = evicted_page->frame->kpage;
    bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    // are there 8 slots per page? Also, is it easier to have them always be consecutive???
}