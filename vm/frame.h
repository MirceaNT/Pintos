#pragma once

#include "threads/thread.h"
#include "vm/page.h"

struct frame_entry
{
    uint32_t frame_num;
    void *kpage;
    struct page *corresponding_page;
    struct thread *current_thread;
};

void frame_init(size_t);
struct frame_entry *get_frame(void);
struct frame_entry *frame_get_multiple(size_t);
void free_frame(struct frame_entry *);