#include <bitmap.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

static struct bitmap *free_frames;
static struct frame_entry *frame_table;
static unsigned cur_clock, max_clock;

static struct lock frame_lock;

void frame_init(size_t user_pages)
{
    size_t bm_pages = DIV_ROUND_UP(bitmap_buf_size(user_pages), PGSIZE);
    if (bm_pages > user_pages)
    {
        bm_pages = user_pages;
    }
    user_pages = user_pages - bm_pages;
    cur_clock = 0;
    max_clock = user_pages;

    frame_table = (struct frame_entry *)malloc(sizeof(struct frame_entry) * user_pages);
    free_frames = bitmap_create(user_pages);
    for (int i = 0; i < user_pages; i++)
    {
        frame_table[i].frame_num = i;
        frame_table[i].corresponding_page = NULL;
    }

    lock_init(&frame_lock);
}



void frame_alloc(){
    // call palloc_get_page and add to table
    /*
    if palloc_get_pg == null
    
    start eviction process
    no need to free 
    */
}