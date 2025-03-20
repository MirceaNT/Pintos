#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
// the following functions are obtained from the pintos website :)

/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->address, sizeof p->address);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->address < b->address;
}

struct page *lookup_page(void *address)
{
    struct thread *current = thread_current();
    struct page cur_page;
    struct hash_elem *hash_element;

    cur_page.address = (void *)(pg_no(address) << 12);
    hash_element = hash_find(&current->supp_page_table, &cur_page.hash_elem);

    if (hash_element == NULL)
    {
        return NULL;
    }
    else
    {
        return hash_entry(hash_element, struct page, hash_elem);
    }
}

void free_page(struct hash_elem *element)
{
    struct page *cur_page = hash_entry(element, struct page, hash_elem);
    if (cur_page->frame != NULL)
    {
        struct frame *cur_frame = cur_page->frame;
        cur_page->frame = NULL;
        free_frame(cur_frame);
    }
    if (cur_page->slot_num != -1)
    {
        swap_clear(cur_page);
    }
}