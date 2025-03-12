#include "threads/thread.h"
#include "threads/vaddr.h"

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