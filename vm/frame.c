#include <bitmap.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#include "vm/frame.h"
#include "vm/swap.h"
#include <round.h>

static struct bitmap *free_frames;
static struct frame_entry *frame_table;
static unsigned clock_ptr, clock_max;

static struct lock frame_lock;

void init_frame_table(size_t user_pages)
{

    size_t bitmap_pages = DIV_ROUND_UP(bitmap_buf_size(user_pages), PGSIZE);
    if (bitmap_pages > user_pages)
    {
        bitmap_pages = user_pages;
    }
    user_pages -= bitmap_pages;

    clock_ptr = 0;
    clock_max = (unsigned)user_pages;

    frame_table = (struct frame_entry *)malloc(sizeof(struct frame_entry) * user_pages);
    free_frames = bitmap_create(user_pages);
    for (int i = 0; i < user_pages; i++)
    {
        frame_table[i].corresponding_page = NULL;
        frame_table[i].frame_num = i;
    }

    lock_init(&frame_lock);
}

struct frame_entry *
frame_get_multiple(size_t page_cnt)
{
    struct thread *cur_thread = thread_current();
    lock_acquire(&frame_lock);
    size_t fframe_num = bitmap_scan_and_flip(free_frames, 0, page_cnt, false);
    if (fframe_num != BITMAP_ERROR)
    {
        frame_table[fframe_num].kpage = palloc_get_page(PAL_USER | PAL_ZERO);
        lock_release(&frame_lock);
        return &frame_table[fframe_num];
    }
    else
    {

        while (pagedir_is_accessed(cur_thread->pagedir, frame_table[clock_ptr].corresponding_page->address))
        {
            pagedir_set_accessed(cur_thread->pagedir, frame_table[clock_ptr].corresponding_page->address, false);
            clock_ptr = (clock_ptr + 1) % clock_max;
        }
        swap_MEM_TO_SWAP(frame_table[clock_ptr].corresponding_page);
        frame_table[clock_ptr].corresponding_page->status = IN_SWAP;
        frame_table[clock_ptr].corresponding_page->frame = NULL;
        pagedir_clear_page(frame_table[clock_ptr].corresponding_page->pagedir, frame_table[clock_ptr].corresponding_page->address);

        int frame_entry_proper = clock_ptr;
        clock_ptr = (clock_ptr + 1) % clock_max;
        lock_release(&frame_lock);
        return &frame_table[frame_entry_proper];
    }
}

struct frame_entry *
get_frame()
{
    return frame_get_multiple(1);
}

void free_frame(struct frame_entry *f)
{
    lock_acquire(&frame_lock);
    pagedir_clear_page(f->corresponding_page->pagedir, f->corresponding_page->address);
    f->corresponding_page = NULL;
    palloc_free_page(frame_table[f->frame_num].kpage);
    bitmap_set(free_frames, f->frame_num, false);
    lock_release(&frame_lock);
}