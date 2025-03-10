#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "filesys/file.h"
#include "lib/kernel/hash.h"
#include "debug.h"

struct supp_page_entry
{
    struct file *file;
    off_t ofs;
    uint8_t *upage;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
    struct hash_elem hash_elem;
};

unsigned supp_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    const struct supp_page_entry *spe = hash_entry(e, struct supp_page_entry, hash_elem);
    return hash_int((int)spe->upage);
}

bool supp_page_table_insert(struct hash *spt, struct supp_page_entry *spe)
{
    struct hash_elem *existing = hash_insert(spt, &spe->hash_elem);
    return (existing == NULL);
}

struct supp_page_entry *supp_page_table_find(struct hash *spt, const void *upage)
{
    /* Create a dummy entry with the key set to 'upage'. */
    struct supp_page_entry dummy;
    dummy.upage = (uint8_t *)upage;
    struct hash_elem *e = hash_find(spt, &dummy.hash_elem);
    if (e != NULL)
        return hash_entry(e, struct supp_page_entry, hash_elem);
    return NULL;
}

struct supp_page_entry *supp_page_table_remove(struct hash *spt, const void *upage)
{
    struct supp_page_entry dummy;
    dummy.upage = (uint8_t *)upage;
    struct hash_elem *e = hash_delete(spt, &dummy.hash_elem);
    if (e != NULL)
        return hash_entry(e, struct supp_page_entry, hash_elem);
    return NULL;
}

static void supp_page_table_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
    struct supp_page_entry *spe = hash_entry(e, struct supp_page_entry, hash_elem);
    free(spe);
}

void supp_page_table_destroy(struct hash *spt)
{
    hash_destroy(spt, supp_page_table_destroy_func);
}