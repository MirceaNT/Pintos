#include <debug.h>
#include <round.h>
#include <string.h>

#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_SIZE 512
#define INDIRECT_SIZE 128

static char global_buffer[BLOCK_SECTOR_SIZE];

bool inode_extend(struct inode *inode, int new_length)
{
    size_t old_sectors = bytes_to_sectors(inode->data.length);
    size_t new_sectors = bytes_to_sectors(new_length);

    if (new_sectors <= old_sectors)
    {
        inode->data.length = new_length;
        block_write(fs_device, inode->sector, &inode->data);
        return true;
    }

    // For each block index from old_sectors to new_sectors - 1,
    //    allocate the necessary data block in the appropriate zone.
    for (int i = old_sectors; i < new_sectors; i++)
    {
        // Direct block area
        if (i < NUM_DIRECT)
        {
            if (inode->data.direct[i] == 0)
            {
                if (!free_map_allocate(1, &inode->data.direct[i]))
                    return false;
                {
                    char zeros[BLOCK_SECTOR_SIZE];
                    memset(zeros, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, inode->data.direct[i], zeros);
                }
            }
        }
        // Single-indirect area
        else if (i < NUM_DIRECT + INDIRECT_SIZE)
        {
            int single_index = i - NUM_DIRECT;
            // Allocate the single-indirect block if needed.
            if (inode->data.single_indirect_block == 0)
            {
                if (!free_map_allocate(1, &inode->data.single_indirect_block))
                    return false;
                {
                    block_sector_t single_array[INDIRECT_SIZE];
                    memset(single_array, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, inode->data.single_indirect_block, single_array);
                }
            }
            // Read the single-indirect block
            block_sector_t single_array[INDIRECT_SIZE];
            block_read(fs_device, inode->data.single_indirect_block, single_array);
            if (single_array[single_index] == 0)
            {
                if (!free_map_allocate(1, &single_array[single_index]))
                    return false;
                {
                    char zeros[BLOCK_SECTOR_SIZE];
                    memset(zeros, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, single_array[single_index], zeros);
                }
                block_write(fs_device, inode->data.single_indirect_block, single_array);
            }
        }
        // Double-indirect area
        else
        {
            int dbl_index = i - (NUM_DIRECT + INDIRECT_SIZE);
            int outer_index = dbl_index / INDIRECT_SIZE;
            int inner_index = dbl_index % INDIRECT_SIZE;
            // Allocate the double-indirect block if needed
            if (inode->data.double_indirect_block == 0)
            {
                if (!free_map_allocate(1, &inode->data.double_indirect_block))
                    return false;
                {
                    block_sector_t outer_array[INDIRECT_SIZE];
                    memset(outer_array, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, inode->data.double_indirect_block, outer_array);
                }
            }
            // Read the double-indirect block into a local buffer.
            block_sector_t outer_array[INDIRECT_SIZE];
            block_read(fs_device, inode->data.double_indirect_block, outer_array);
            // Allocate an indirect block if needed
            if (outer_array[outer_index] == 0)
            {
                block_sector_t new_indirect;
                if (!free_map_allocate(1, &new_indirect))
                    return false;
                outer_array[outer_index] = new_indirect;
                block_write(fs_device, inode->data.double_indirect_block, outer_array);
                {
                    block_sector_t inner_array[INDIRECT_SIZE];
                    memset(inner_array, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, new_indirect, inner_array);
                }
            }
            // Now, read the indirect block corresponding to outer_index
            block_sector_t indirect_sector = outer_array[outer_index];
            block_sector_t inner_array[INDIRECT_SIZE];
            block_read(fs_device, indirect_sector, inner_array);
            if (inner_array[inner_index] == 0)
            {
                if (!free_map_allocate(1, &inner_array[inner_index]))
                    return false;
                {
                    char zeros[BLOCK_SECTOR_SIZE];
                    memset(zeros, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, inner_array[inner_index], zeros);
                }
                block_write(fs_device, indirect_sector, inner_array);
            }
        }
    }
    inode->data.length = new_length;
    block_write(fs_device, inode->sector, &inode->data);
    return true;
}

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
    return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
 * within INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static block_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
    ASSERT(inode != NULL);
    if (pos >= inode->data.length)
        return -1;

    int block_index = pos / BLOCK_SECTOR_SIZE;

    // Check if the block is stored in direct pointers
    if (block_index < NUM_DIRECT)
        return inode->data.direct[block_index];

    block_index -= NUM_DIRECT;
    // Check if it falls in the single-indirect block
    if (block_index < INDIRECT_SIZE)
    {
        block_sector_t single_array[INDIRECT_SIZE];
        block_read(fs_device, inode->data.single_indirect_block, single_array);
        return single_array[block_index];
    }

    // Otherwise, it is in the double-indirect blocks
    block_index -= INDIRECT_SIZE;
    int outer_index = block_index / INDIRECT_SIZE;
    int inner_index = block_index % INDIRECT_SIZE;
    block_sector_t outer_array[INDIRECT_SIZE];
    block_read(fs_device, inode->data.double_indirect_block, outer_array);
    block_sector_t indirect_sector = outer_array[outer_index];
    if (indirect_sector == 0)
        return -1;
    block_sector_t inner_array[INDIRECT_SIZE];
    block_read(fs_device, indirect_sector, inner_array);
    return inner_array[inner_index];
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
    list_init(&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * device.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */

/*
 This should be finished
 */

bool inode_create(block_sector_t sector, off_t length)
{
    struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
    bool success = false;

    /* If this assertion fails, the inode structure is not exactly
     * one sector in size, and you should fix that. */
    ASSERT(length >= 0);
    // if this fails, reduce the number of direct sectors in inode.h
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    if (disk_inode != NULL)
    {
        size_t sectors = bytes_to_sectors(length);
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;

        //         /*
        //         // this is the default code
        //         if (free_map_allocate(sectors, &disk_inode->start))
        //         {
        //             block_write(fs_device, sector, disk_inode);
        //             if (sectors > 0)
        //             {
        //                 static char zeros[BLOCK_SECTOR_SIZE];
        //                 size_t i;

        //                 for (i = 0; i < sectors; i++)
        //                 {
        //                     block_write(fs_device, disk_inode->start + i, zeros);
        //                 }
        //             }
        //             success = true;
        //         }
        // */

        // Initialize direct pointers to 0.
        for (int i = 0; i < NUM_DIRECT; i++)
            disk_inode->direct[i] = 0;
        disk_inode->single_indirect_block = 0;
        disk_inode->double_indirect_block = 0;

        int allocated = 0;

        // Allocate direct blocks
        for (int i = 0; i < NUM_DIRECT && allocated < sectors; i++)
        {
            if (!free_map_allocate(1, &disk_inode->direct[i]))
            {
                free(disk_inode);
                return false;
            }
            {
                char zeros[BLOCK_SECTOR_SIZE];
                memset(zeros, 0, BLOCK_SECTOR_SIZE);
                block_write(fs_device, disk_inode->direct[i], zeros);
            }
            allocated++;
        }

        // Allocate single-indirect blocks if needed
        if (allocated < sectors)
        {
            int num_single = sectors - allocated;
            if (num_single > INDIRECT_SIZE)
                num_single = INDIRECT_SIZE;
            // Allocate the single-indirect block itself
            if (!free_map_allocate(1, &disk_inode->single_indirect_block))
            {
                free(disk_inode);
                return false;
            }
            // Allocate a temporary buffer for the single indirect block pointers
            block_sector_t *single_array = malloc(BLOCK_SECTOR_SIZE);
            if (single_array == NULL)
            {
                free(disk_inode);
                return false;
            }
            memset(single_array, 0, BLOCK_SECTOR_SIZE);
            for (int i = 0; i < num_single && allocated < sectors; i++)
            {
                if (!free_map_allocate(1, &single_array[i]))
                {
                    free(single_array);
                    free(disk_inode);
                    return false;
                }
                {
                    char zeros[BLOCK_SECTOR_SIZE];
                    memset(zeros, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, single_array[i], zeros);
                }
                allocated++;
            }
            block_write(fs_device, disk_inode->single_indirect_block, single_array);
            free(single_array);
        }

        // Allocate double-indirect blocks if needed
        if (allocated < sectors)
        {
            int num_remaining = sectors - allocated;
            // Allocate the double indirect block itself.
            if (!free_map_allocate(1, &disk_inode->double_indirect_block))
            {
                free(disk_inode);
                return false;
            }
            block_sector_t *outer_array = malloc(BLOCK_SECTOR_SIZE);
            if (outer_array == NULL)
            {
                free(disk_inode);
                return false;
            }
            memset(outer_array, 0, BLOCK_SECTOR_SIZE);
            int num_indirect_blocks = DIV_ROUND_UP(num_remaining, INDIRECT_SIZE);
            for (int i_outer = 0; i_outer < num_indirect_blocks && allocated < sectors; i_outer++)
            {
                block_sector_t indirect_sector;
                if (!free_map_allocate(1, &indirect_sector))
                {
                    free(outer_array);
                    free(disk_inode);
                    return false;
                }
                outer_array[i_outer] = indirect_sector;
                block_sector_t *inner_array = malloc(BLOCK_SECTOR_SIZE);
                if (inner_array == NULL)
                {
                    free(outer_array);
                    free(disk_inode);
                    return false;
                }
                memset(inner_array, 0, BLOCK_SECTOR_SIZE);
                // Determine how many data pointers we need in this indirect block
                int num_data = num_remaining - i_outer * INDIRECT_SIZE;
                if (num_data > INDIRECT_SIZE)
                    num_data = INDIRECT_SIZE;
                for (int j = 0; j < num_data && allocated < sectors; j++)
                {
                    if (!free_map_allocate(1, &inner_array[j]))
                    {
                        free(inner_array);
                        free(outer_array);
                        free(disk_inode);
                        return false;
                    }
                    {
                        char zeros[BLOCK_SECTOR_SIZE];
                        memset(zeros, 0, BLOCK_SECTOR_SIZE);
                        block_write(fs_device, inner_array[j], zeros);
                    }
                    allocated++;
                }
                block_write(fs_device, indirect_sector, inner_array);
                free(inner_array);
            }
            block_write(fs_device, disk_inode->double_indirect_block, outer_array);
            free(outer_array);
        }

        // Write the inode to the given sector.
        block_write(fs_device, sector, disk_inode);
        success = true;
        free(disk_inode);
    }
    return success;
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector)
{
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
         e = list_next(e))
    {
        inode = list_entry(e, struct inode, elem);
        if (inode->sector == sector)
        {
            inode_reopen(inode);
            return inode;
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL)
    {
        return NULL;
    }

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    block_read(fs_device, inode->sector, &inode->data);
    return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
    if (inode != NULL)
    {
        inode->open_cnt++;
    }
    return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode)
{
    return inode->sector;
}

void release_inode_sectors(struct inode *inode)
{
    struct inode_disk *data = &inode->data;

    // Release Direct Blocks
    for (int i = 0; i < NUM_DIRECT; i++)
    {
        if (data->direct[i] != 0)
        {
            free_map_release(data->direct[i], 1);
        }
    }

    //  Release Single-indirect Blocks
    if (data->single_indirect_block != 0)
    {
        block_sector_t single_array[INDIRECT_SIZE];
        block_read(fs_device, data->single_indirect_block, single_array);
        for (int i = 0; i < INDIRECT_SIZE; i++)
        {
            if (single_array[i] != 0)
                free_map_release(single_array[i], 1);
        }
        free_map_release(data->single_indirect_block, 1);
    }

    // Release Double-indirect Blocks
    if (data->double_indirect_block != 0)
    {
        block_sector_t outer_array[INDIRECT_SIZE];
        block_read(fs_device, data->double_indirect_block, outer_array);
        for (int i = 0; i < INDIRECT_SIZE; i++)
        {
            if (outer_array[i] != 0)
            {
                block_sector_t inner_array[INDIRECT_SIZE];
                block_read(fs_device, outer_array[i], inner_array);
                for (int j = 0; j < INDIRECT_SIZE; j++)
                {
                    if (inner_array[j] != 0)
                        free_map_release(inner_array[j], 1);
                }
                free_map_release(outer_array[i], 1);
            }
        }
        free_map_release(data->double_indirect_block, 1);
    }

    // Release the inode's own sector (the inode header)
    free_map_release(inode->sector, 1);
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode)
{
    /* Ignore null pointer. */
    if (inode == NULL)
    {
        return;
    }

    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0)
    {
        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);

        /* Deallocate blocks if removed. */
        if (inode->removed)
        {

            release_inode_sectors(inode);
        }

        free(inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void inode_remove(struct inode *inode)
{
    ASSERT(inode != NULL);
    inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    while (size > 0)
    {

        if (offset >= inode_length(inode))
        {
            break;
        }

        /* Disk sector to read, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset);
        // printf("Reading from %d\n", sector_idx);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
        {
            break;
        }

        if (sector_idx == -1)
        {
            memset(buffer + bytes_read, 0, chunk_size);
        }
        else if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
            /* Read full sector directly into caller's buffer. */
            block_read(fs_device, sector_idx, buffer + bytes_read);
        }
        else
        {
            /* Read sector into bounce buffer, then partially copy
             * into caller's buffer. */
            if (bounce == NULL)
            {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL)
                {
                    break;
                }
            }
            block_read(fs_device, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
                     off_t offset)
{
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;

    if (inode->deny_write_cnt)
    {
        return 0;
    }

    if (offset + size > inode->data.length)
    {
        if (!inode_extend(inode, offset + size))
        {
            return 0;
        }
    }
    // print out byte and sector, and make sure that they meet up in the right place

    while (size > 0)
    {
        /* Sector to write, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;
        // printf("Writing at sector: %d\n", sector_idx);
        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
        {
            break;
        }

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
            /* Write full sector directly to disk. */
            block_write(fs_device, sector_idx, buffer + bytes_written);
        }
        else
        {
            /* We need a bounce buffer. */
            if (bounce == NULL)
            {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL)
                {
                    break;
                }
            }

            /* If the sector contains data before or after the chunk
             * we're writing, then we need to read in the sector
             * first.  Otherwise we start with a sector of all zeros. */
            if (sector_ofs > 0 || chunk_size < sector_left)
            {
                block_read(fs_device, sector_idx, bounce);
            }
            else
            {
                memset(bounce, 0, BLOCK_SECTOR_SIZE);
            }
            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            block_write(fs_device, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
    }
    free(bounce);

    return bytes_written;
}

/* Disables writes to INODE.
 * May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode)
{
    return inode->data.length;
}
