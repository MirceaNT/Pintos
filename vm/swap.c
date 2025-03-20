#include "threads/synch.h"
#include <bitmap.h>
#include "devices/block.h"
#include "swap.h"

static struct bitmap *swap_bitmap;
struct block *swap_space;
static struct lock swap_lock;

void swap_init()
{
    // phys mem / block size = x / blocks per page = 1024
    // 2 ^ 22 / 2 ^ 9 = 2 ^ 13 / 2^3 = 2 ^ 10
    swap_bitmap = bitmap_create(1024);
    swap_space = block_get_role(BLOCK_SWAP);
    lock_init(&swap_lock);
}

void swap_MEM_TO_SWAP(struct page *evicted_page)
{
    // put a page in swap table
    //  change a page to in_swap status
    lock_acquire(&swap_lock);
    uint8_t *pointer = evicted_page->frame->kpage;
    int starting_slot = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

    evicted_page->slot_num = starting_slot;
    for (int i = 0; i < 8; i++)
    {
        block_write(swap_space, starting_slot * 8 + i, pointer);
        pointer = pointer + 512;
    }

    lock_release(&swap_lock);
}

void swap_SWAP_TO_MEM(struct page *insert_page)
{
    lock_acquire(&swap_lock);
    uint8_t *pointer = insert_page->frame->kpage;

    int starting_slot = insert_page->slot_num;

    for (int i = 0; i < 8; i++)
    {
        block_read(swap_space, starting_slot * 8 + i, pointer);
        pointer = pointer + 512;
    }
    bitmap_reset(swap_bitmap, insert_page->slot_num);
    lock_release(&swap_lock);
}

void swap_clear(struct page *clear_page)
{
    lock_acquire(&swap_lock);

    bitmap_reset(swap_bitmap, clear_page->slot_num);

    lock_release(&swap_lock);
}