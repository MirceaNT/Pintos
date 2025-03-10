#include "vm/suppTable.h"

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
bool supp_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    const struct supp_page_entry *spe_a = hash_entry(a, struct supp_page_entry, hash_elem);
    const struct supp_page_entry *spe_b = hash_entry(b, struct supp_page_entry, hash_elem);
    return spe_a->upage < spe_b->upage;
}
void supp_page_table_init(struct hash *spt)
{
    hash_init(spt, supp_hash_func, supp_less_func, NULL);
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