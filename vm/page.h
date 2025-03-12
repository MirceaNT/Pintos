#pragma once

#include <hash.h>
#include "filesys/file.h"
#include "vm/frame.h"
#include "threads/synch.h"
#include <stdint.h>
#include <stdbool.h>

enum location
{
    DISK,
    IN_MEM,
    IN_SWAP,
    ZEROS // maybe for stack pages?
};

struct page
{
    struct hash_elem hash_elem;
    void *address;
    struct frame_entry *frame;
    enum location status;
    bool is_stack_page;
    bool write_enable;
    struct file *file_name;
    off_t offset;
    int slot_num;
    size_t zero_bytes;
    size_t read_bytes;
    uint32_t *pagedir;
    struct lock DO_NOT_TOUCH; // used to ensure I don't evict
};

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED);
struct page *lookup_page(void *address);