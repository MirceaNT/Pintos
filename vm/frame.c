#include <bitmap.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include <round.h>

static struct bitmap *free_frames;
static struct frame_entry *frame_table;
static unsigned clock_ptr, clock_max;

static struct lock frame_lock;

void init_frame_table(size_t user_pages)
{

    unsigned i;

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
    for (i = 0; i < user_pages; i++)
    {
        frame_table[i].frame_num = i;
        frame_table[i].corresponding_page = NULL;
    }

    lock_init(&frame_lock);
}

struct frame_entry *
frame_get_multiple(size_t page_cnt)
{
    lock_acquire(&frame_lock);
    size_t fframe_num = bitmap_scan_and_flip(free_frames, 0, page_cnt, false);
    if (fframe_num != BITMAP_ERROR)
    {
        frame_table[fframe_num].kpage = palloc_get_page(PAL_USER | PAL_ZERO);
        lock_release(&frame_lock);
        return &frame_table[fframe_num];
    }
}

struct frame_entry *
get_frame()
{
    return frame_get_multiple(1);
}

/* Free given frame occupied by terminating process */
void free_frame(struct frame_entry *f)
{
    lock_acquire(&frame_lock);
    pagedir_clear_page(f->corresponding_page->pagedir, f->corresponding_page->address);
    bitmap_reset(free_frames, f->frame_num);
    palloc_free_page(frame_table[f->frame_num].kpage);
    f->corresponding_page = NULL;
    lock_release(&frame_lock);
}