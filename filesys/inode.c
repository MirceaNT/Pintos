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

    /* If the file is initially empty and the double block hasn't been created, make it */
    if (old_sectors == 0 && inode->data.double_indirect_block == 0)
    {
        if (!free_map_allocate(1, &inode->data.double_indirect_block))
        {
            return false;
        }

        lock_acquire(&global_buffer_lock);
        memset(global_buffer, 0, BLOCK_SECTOR_SIZE);
        block_write(fs_device, inode->data.double_indirect_block, global_buffer);
        lock_release(&global_buffer_lock);
    }

    /* add missing data sectors old sectors to new sectors */
    for (int i = old_sectors; i < new_sectors; i++)
    {
        int outer_index = i / INDIRECT_SIZE;
        int inner_index = i % INDIRECT_SIZE;
        block_sector_t new_indirect, data_sector;
        block_sector_t *outer_block;
        block_sector_t *indirect_block;

        lock_acquire(&global_buffer_lock);
        block_read(fs_device, inode->data.double_indirect_block, global_buffer);
        outer_block = (block_sector_t *)global_buffer;

        if (outer_block[outer_index] == 0)
        {
            if (!free_map_allocate(1, &new_indirect))
            {
                lock_release(&global_buffer_lock);
                return false;
            }

            outer_block[outer_index] = new_indirect;
            block_write(fs_device, inode->data.double_indirect_block, global_buffer);
            lock_release(&global_buffer_lock);

            /* Init the new indirect block */
            lock_acquire(&global_buffer_lock);
            memset(global_buffer, 0, BLOCK_SECTOR_SIZE);
            block_write(fs_device, new_indirect, global_buffer);
            lock_release(&global_buffer_lock);
        }
        else
        {
            lock_release(&global_buffer_lock);
        }

        /* allocate data in the indirect block (reread the outer_block for pointers) */
        lock_acquire(&global_buffer_lock);
        block_read(fs_device, inode->data.double_indirect_block, global_buffer);
        outer_block = (block_sector_t *)global_buffer;
        // get the right pointer
        block_sector_t indirect_sector = outer_block[outer_index];
        lock_release(&global_buffer_lock);

        lock_acquire(&global_buffer_lock);
        block_read(fs_device, indirect_sector, global_buffer);
        indirect_block = (block_sector_t *)global_buffer;
        if (indirect_block[inner_index] == 0)
        {
            if (!free_map_allocate(1, &data_sector))
            {
                lock_release(&global_buffer_lock);
                return false;
            }
            indirect_block[inner_index] = data_sector;
            /* Write the updated indirect block back to disk. */
            block_write(fs_device, indirect_sector, global_buffer);
            lock_release(&global_buffer_lock);

            /* Initialize the new data block to zeros. */
            lock_acquire(&global_buffer_lock);
            memset(global_buffer, 0, BLOCK_SECTOR_SIZE);
            block_write(fs_device, data_sector, global_buffer);
            lock_release(&global_buffer_lock);
        }
        else
        {
            lock_release(&global_buffer_lock);
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

/*
This should be finished
*/
static block_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
    ASSERT(inode != NULL);
    if (pos < inode->data.length)
    {
        // my goal is to implement this. I will need some block reads since I can't do this with block_sectors...
        // double_sector[(pos / BLOCK_SECTOR_SIZE) / INDIRECT_SIZE][((pos / BLOCK_SECTOR_SIZE) / INDIRECT_SIZE) % DIRECT_SIZE];

        int block_index = pos / BLOCK_SECTOR_SIZE;
        // Read the double-indirect (outer) block into the global buffer.
        // lock_acquire(&global_buffer_lock);
        block_read(fs_device, inode->data.double_indirect_block, global_buffer);
        // Cast the global buffer to a block_sector_t array.
        block_sector_t *outer_block = (block_sector_t *)global_buffer;
        block_sector_t indirect_sector = outer_block[block_index / INDIRECT_SIZE];
        // lock_release(&global_buffer_lock);

        if (indirect_sector == 0)
            return -1;

        // Read the indirect (inner) block into the global buffer.
        // lock_acquire(&global_buffer_lock);
        block_read(fs_device, indirect_sector, global_buffer);
        block_sector_t *inner_block = (block_sector_t *)global_buffer;
        block_sector_t result = inner_block[block_index % INDIRECT_SIZE];
        // lock_release(&global_buffer_lock);

        return result;

        // return inode->data.start + pos / BLOCK_SECTOR_SIZE;
    }
    else
    {
        return -1;
    }
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
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
     * one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL)
    {
        size_t sectors = bytes_to_sectors(length);
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;

        /*
        // this is the default code
        if (free_map_allocate(sectors, &disk_inode->start))
        {
            block_write(fs_device, sector, disk_inode);
            if (sectors > 0)
            {
                static char zeros[BLOCK_SECTOR_SIZE];
                size_t i;

                for (i = 0; i < sectors; i++)
                {
                    block_write(fs_device, disk_inode->start + i, zeros);
                }
            }
            success = true;
        }
*/

        if (sectors > 0)
        {
            // Allocate one sector for the double-indirect block.
            if (!free_map_allocate(1, &disk_inode->double_indirect_block))
            {
                free(disk_inode);
                return false;
            }

            // Instead of a stack-allocated array, allocate the outer block buffer on the heap.
            block_sector_t *outer_block = malloc(BLOCK_SECTOR_SIZE);
            if (outer_block == NULL)
            {
                free(disk_inode);
                return false;
            }
            memset(outer_block, 0, BLOCK_SECTOR_SIZE);

            int num_indirect_blocks = DIV_ROUND_UP(sectors, INDIRECT_SIZE);
            for (int i = 0; i < num_indirect_blocks; i++)
            {
                block_sector_t indirect_sector;
                if (!free_map_allocate(1, &indirect_sector))
                {
                    free(outer_block);
                    free(disk_inode);
                    return false;
                }
                outer_block[i] = indirect_sector;

                // Allocate an indirect block buffer on the heap rather than on the stack.
                block_sector_t *indirect = malloc(BLOCK_SECTOR_SIZE);
                if (indirect == NULL)
                {
                    free(outer_block);
                    free(disk_inode);
                    return false;
                }
                memset(indirect, 0, BLOCK_SECTOR_SIZE);

                for (int j = 0; j < INDIRECT_SIZE; j++)
                {
                    int data_index = i * INDIRECT_SIZE + j;
                    if (data_index >= sectors)
                        break;

                    block_sector_t data_sector;
                    if (!free_map_allocate(1, &data_sector))
                    {
                        free(indirect);
                        free(outer_block);
                        free(disk_inode);
                        return false;
                    }
                    indirect[j] = data_sector;

                    // Instead of a stack-allocated zeros array, clear the global buffer.
                    // lock_acquire(&global_buffer_lock);
                    memset(global_buffer, 0, BLOCK_SECTOR_SIZE);
                    block_write(fs_device, data_sector, global_buffer);
                    // lock_release(&global_buffer_lock);
                }
                // Write the indirect block to disk using the global buffer.
                // lock_acquire(&global_buffer_lock);
                memcpy(global_buffer, indirect, BLOCK_SECTOR_SIZE);
                block_write(fs_device, indirect_sector, global_buffer);
                // lock_release(&global_buffer_lock);

                free(indirect); // Free the heap buffer for the indirect block.
            }

            // Write the outer (double-indirect) block to disk using the global buffer.
            // lock_acquire(&global_buffer_lock);
            memcpy(global_buffer, outer_block, BLOCK_SECTOR_SIZE);
            block_write(fs_device, disk_inode->double_indirect_block, global_buffer);
            // lock_release(&global_buffer_lock);

            free(outer_block); // Free the outer block heap buff
        }
        else
        {
            disk_inode->double_indirect_block = 0;
        }
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
            free_map_release(inode->sector, 1);
            free_map_release(inode->data.double_indirect_block,
                             bytes_to_sectors(inode->data.length));
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

    while (size > 0)
    {
        /* Sector to write, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

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
