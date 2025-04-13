#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "threads/thread.h"

#include "userprog/syscall.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
    // printf("%d tid, %s\n", thread_current(), "filesys_init");
    lock_init(&global_buffer_lock);
    fs_device = block_get_role(BLOCK_FILESYS);
    if (fs_device == NULL)
    {
        PANIC("No file system device found, can't initialize file system.");
    }

    inode_init();
    free_map_init();

    if (format)
    {
        do_format();
    }

    free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void)
{
    free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool filesys_create(struct dir *parent, const char *file_name, off_t initial_size)
{
    if (parent == NULL || file_name == NULL || strlen(file_name) == 0)
    {
        return false;
    }

    struct inode *inode_check = NULL;
    if (dir_lookup(parent, file_name, &inode_check))
    {
        return false;
    }

    block_sector_t inode_sector = 0;
    if (!free_map_allocate(1, &inode_sector))
    {
        return false;
    }

    if (!inode_create(inode_sector, initial_size, false))
    {
        free_map_release(inode_sector, 1);
        return false;
    }

    bool success = dir_add(parent, file_name, inode_sector);
    if (!success)
    {
        free_map_release(inode_sector, 1);
    }
    // the moment you realize this could've been fewer if statements
    return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
// this has to be the current directory
struct file *filesys_open(const char *name)
{
    // all persistance fails without these 4 lines
    if (strcmp(name, "/") == 0)
    {
        return (struct file *)dir_open_root();
    }

    struct path_result pr = resolve_path(name);
    if (pr.parent == NULL || pr.final_name == NULL)
    {
        if (strcmp(name, ".") == 0)
        {
            if (!thread_current()->cur_dir->inode->removed)
            {
                struct inode *inode = NULL;
                if (!dir_lookup(thread_current()->cur_dir, ".", &inode))
                {
                    free(pr.final_name);
                    dir_close(pr.parent);
                    return NULL;
                }
                free(pr.final_name);
                dir_close(pr.parent);

                if (inode == NULL)
                {
                    return NULL;
                }

                if (inode->data.is_dir)
                {
                    return (struct file *)dir_open(inode);
                }
                else
                {
                    return file_open(inode);
                }
            }
            else
            {
                if (pr.final_name != NULL)
                {
                    free(pr.final_name);
                }
                return NULL;
            }
        }
        else
        {
            // it once did something
        }
    }

    // lookup final token in given directory
    struct inode *inode = NULL;
    if (pr.parent == NULL || pr.final_name == NULL)
    {
        return NULL;
    }
    if (!dir_lookup(pr.parent, pr.final_name, &inode))
    {
        free(pr.final_name);
        dir_close(pr.parent);
        return NULL;
    }
    free(pr.final_name);
    dir_close(pr.parent);

    if (inode == NULL)
    {
        return NULL;
    }

    if (inode->data.is_dir)
    {
        return (struct file *)dir_open(inode);
    }
    else
    {
        return file_open(inode);
    }
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
    // can't remove root
    if (strcmp(name, "/") == 0)
    {
        return false;
    }

    // get director and what to remove
    struct path_result pr = resolve_path(name);
    if (pr.parent == NULL || pr.final_name == NULL)
    {
        if (pr.final_name != NULL)
            free(pr.final_name);
        return false;
    }

    // lookup in parent
    struct inode *inode = NULL;
    if (!dir_lookup(pr.parent, pr.final_name, &inode))
    {
        free(pr.final_name);
        dir_close(pr.parent);
        return false;
    }

    // remove cwd cases
    bool removing_cwd = false;
    if (thread_current()->cur_dir != NULL)
    {
        struct inode *cwd_inode = dir_get_inode(thread_current()->cur_dir);
        if (cwd_inode != NULL &&
            inode_get_inumber(cwd_inode) == inode_get_inumber(inode))
        {
            removing_cwd = true;
        }
    }

    // only what I hardcoded should be in there before removal
    if (inode->data.is_dir)
    {
        struct dir *target_dir = dir_open(inode);
        if (target_dir == NULL)
        {
            free(pr.final_name);
            dir_close(pr.parent);
            return false;
        }

        bool is_empty = true;
        char entry[NAME_MAX + 1];
        while (dir_readdir(target_dir, entry))
        {
            if (strcmp(entry, ".") != 0 && strcmp(entry, "..") != 0)
            {
                is_empty = false;
                break;
            }
        }
        dir_close(target_dir);
        if (!is_empty)
        {
            free(pr.final_name);
            dir_close(pr.parent);
            return false;
        }
    }

    // remove from directory
    bool success = dir_remove(pr.parent, pr.final_name);

    free(pr.final_name);
    dir_close(pr.parent);

    if (success && removing_cwd)
    {
        dir_close(thread_current()->cur_dir);
        thread_current()->cur_dir = dir_reopen(pr.parent);
    }

    return success;
}

/* Formats the file system. */
static void
do_format(void)
{
    printf("Formatting file system...");
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16))
    {
        PANIC("root directory creation failed");
    }
    free_map_close();
    printf("done.\n");
}
