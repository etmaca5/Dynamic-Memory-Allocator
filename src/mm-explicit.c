/*
 * mm-implicit.c - The best malloc package EVAR!
 *
 * TODO (bug): mm_realloc and mm_calloc don't seem to be working...
 * TODO (bug): The allocator doesn't re-use space very well...
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

typedef struct free_block_t {
    size_t header;
    // takes place of header
    struct free_block_t *prev;
    // takes place of payload (since must be 16 aligned)
    struct free_block_t *next;
} free_block_t;

typedef struct footer_t {
    size_t size;
} footer_t;

// total global data is less than 128 bytes
// global variable for the first free block in the free list
static free_block_t *first_free_block = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Set's a block's header and footer with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
    footer_t *footer = (void *) block + size - sizeof(footer_t);
    footer->size = size;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/**
 * returns min of two size_ts, helper function
 */
size_t min(size_t p1, size_t p2) {
    if (p1 <= p2) {return p1;}
    return p2;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
ADDITIONAL HELPER FUNCTIONS
**/

// adds a free block to the free list
void add_free_block(block_t *block) {
    free_block_t *freed_block = (free_block_t *)block;
    if (first_free_block != NULL) {
        free_block_t *second_block = first_free_block;
        first_free_block = freed_block;
        second_block->prev = first_free_block;
        first_free_block->next = second_block;
        first_free_block->prev = NULL;
        return;
    }
    first_free_block = freed_block;
    first_free_block->next = NULL;
    first_free_block->prev = NULL;
}

// removes a free block from the free list
void remove_free_block(block_t *block) {
    // assert(!is_allocated(block));
    free_block_t *freed_block = ((free_block_t *) block);
    free_block_t *next_free_block = freed_block->next;
    free_block_t *prev_free_block = freed_block->prev;
    if(prev_free_block == NULL){first_free_block = next_free_block;}
    else{prev_free_block->next = next_free_block;}
    if(next_free_block != NULL){next_free_block->prev = prev_free_block;}
}


/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    free_block_t *curr_free_block = first_free_block;
    while (curr_free_block != NULL) {
        block_t *block = (block_t *) curr_free_block;
        if (get_size(block) >= size) {
            return block;
        }
        curr_free_block = curr_free_block->next;
    }
    return NULL;
}

// splits block into an allocated block and a free block
void split(block_t *block, size_t size) {
    block_t *new_split_block = (void *) block + size;
    size_t split_block_size = get_size(block) - size;
    if (block == mm_heap_last) {
        mm_heap_last = new_split_block;
    }
    set_header(block, size, true);
    set_header(new_split_block, split_block_size, false);
    add_free_block(new_split_block);
}

// helper to coalesce, which actually combines the given blocks based on which ones are non-allocated
void coalesce_blocks(bool backwards, bool forward, size_t size, block_t *block, block_t* next_block, block_t* prev_block){
    if (backwards && forward) {
        if (next_block == mm_heap_last) {
            mm_heap_last = prev_block;
        }
        set_header(prev_block, size, false);
        remove_free_block(next_block); 
    }
    else if (backwards) {
        if (block == mm_heap_last) {
            mm_heap_last = prev_block;
        }
        set_header(prev_block, size, false);
    }
    else if (forward) {
        if (next_block == mm_heap_last) {
            mm_heap_last = block;
        }
        set_header(block, size, false);
        remove_free_block(next_block);
        add_free_block(block);
    }
    else {
        set_header(block, size, false);
        add_free_block(block);   
    }
}


// coalesce front and back blocks function
void coalesce(block_t *block) {
    size_t size = get_size(block);
    block_t *next_block = NULL;
    block_t *prev_block = NULL;
    bool forward_coalesce = false;
    if (block != mm_heap_last) {
        next_block = (void *) block + get_size(block);
        if (next_block != NULL && !is_allocated(next_block)) {
            forward_coalesce = true;
            size += get_size(next_block);
        }
    }
    bool backwards_coalesce = false;
    if (block != mm_heap_first) {
        footer_t *footer = (void *) block - sizeof(footer_t);
        prev_block = (void *) block - footer->size;
        if (prev_block != NULL && !is_allocated(prev_block)) {
            backwards_coalesce = true;
            size += get_size(prev_block); 
        }
    }
    coalesce_blocks(backwards_coalesce, forward_coalesce, size, block, next_block, prev_block);
}



/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }
    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    first_free_block = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + sizeof(footer_t) + size, ALIGNMENT);
    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        remove_free_block(block);
        if(get_size(block) > sizeof(block_t) + sizeof(footer_t) + size){
            split(block, size);
        }
        else{
            set_header(block, get_size(block), true);
        }
        // set_header(block, get_size(block), true);
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }
    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;
    // Initialize the block with the allocated size
    set_header(block, size, true);
    return block->payload;
}


/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }
    // // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    // // call helper coalesce free which will set the headers to free

    // temporary replacement
    // set_header(block, get_size(block), false);
    // add_free_block(block);
    coalesce(block);

}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }
    else if (old_ptr == NULL) {
        return mm_malloc(size);
    }
    void *ptr = mm_malloc(size);
    if (!ptr) {
        return NULL;
    }
    // always finding new region
    block_t *old_block = block_from_payload(old_ptr);
    block_t *new_block = block_from_payload(ptr);
    memcpy(ptr, old_ptr, min(get_size(old_block), get_size(new_block)) - sizeof(block_t) - sizeof(footer_t));
    mm_free(old_ptr);
    return ptr;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    void *ptr = mm_malloc(size * nmemb);
    memset(ptr, 0, nmemb * size);
    return ptr;
}


/**
HELPER FUNCTIONS TO USE IN CHECK HEAP
*/

/**Ensures that length of free list is equal to number of free blocks*/
void check_free_block_length() {
    size_t count_free_list_length = 0;
    free_block_t *curr_free = first_free_block;
    while (curr_free != NULL) {
        count_free_list_length++;
        curr_free = curr_free->next;
    }
    size_t count_free_blocks = 0;
    block_t *curr_block = mm_heap_first;
    while (curr_block != NULL && curr_block <= mm_heap_last) {
        if (!is_allocated(curr_block)) {
            count_free_blocks++;
        }
        curr_block = (void *) curr_block + get_size(curr_block);
    }
    assert(count_free_list_length == count_free_blocks);
}

/**Ensures that the footers and headers store the same value in each block*/
void check_footers_headers() {
    block_t *curr_block = mm_heap_first;
    size_t block_count = 0;
    while (curr_block != NULL && curr_block <= mm_heap_last) {
        block_count ++;
        footer_t *footer = (void *) curr_block + get_size(curr_block) - sizeof(footer_t);
        if (footer->size != get_size(curr_block)) {
            printf("\nheader size: %zd, footer size: %zd,\nblock count: %zd\n", get_size(curr_block),
                   footer->size, block_count);
            if(curr_block == mm_heap_first){printf("first heap\n");}
            assert(footer->size == get_size(curr_block));
        }
        curr_block = (void *) curr_block + get_size(curr_block);
    }
}


/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    check_footers_headers();
    check_free_block_length();
}
