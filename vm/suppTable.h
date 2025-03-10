#ifndef SUPP_TABLE_H
#define SUPP_TABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "filesys/file.h"
#include "lib/kernel/hash.h"
#include "debug.h"

/* Supplemental page table entry structure. */
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

/* Hash functions prototypes. */
unsigned supp_hash_func(const struct hash_elem *e, void *aux UNUSED);
bool supp_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

/* Supplemental page table functions prototypes. */
void supp_page_table_init(struct hash *spt);
bool supp_page_table_insert(struct hash *spt, struct supp_page_entry *spe);
struct supp_page_entry *supp_page_table_find(struct hash *spt, const void *upage);
struct supp_page_entry *supp_page_table_remove(struct hash *spt, const void *upage);
void supp_page_table_destroy(struct hash *spt);

#endif /* SUPP_TABLE_H */
