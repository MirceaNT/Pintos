#pragma once

#include "vm/page.h"

void swap_init();
void swap_MEM_TO_SWAP(struct page *);
void swap_SWAP_TO_MEM(struct page *);
void swap_clear(struct page *);